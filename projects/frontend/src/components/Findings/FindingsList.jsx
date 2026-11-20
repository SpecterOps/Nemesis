import PaginationControls from '@/components/FileList/PaginationControls';
import { useUser } from '@/contexts/UserContext';
import BulkActionBar from '@/components/FileList/BulkActionBar';
import { fetchPage, forEachIdChunk, hasuraRequest, isEditableTarget } from '@/hooks/pagedList';
import { useBulkAction } from '@/hooks/useBulkAction';
import { usePagedList } from '@/hooks/usePagedList';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import Alert from './Alert';
import FindingModal from './FindingModal';
import FindingsFilters from './FindingsFilters';
import {
  ALL_CATEGORIES, ALL_SEVERITIES, DEFAULT_TRIAGE_STATE, FINDINGS_PAGE_SIZE, SORT_COLUMNS, TRIAGE_SOURCES,
  TRIAGE_STATES, buildFindingsOrderBy, buildFindingsWhere, matchesAfterHumanTriage,
} from './findingsQuery';
import { useFileNavigation } from './navigation';
import { TableHeaders, TableRow } from './Table';

const ROW_HEIGHT = 42;
const PAGE_SIZE = FINDINGS_PAGE_SIZE;

// Only what the list renders; the (possibly large) finding `data` is loaded when the modal opens
const ROW_FIELDS = `
  finding_id
  finding_name
  object_id
  origin_type
  origin_name
  category
  severity
  created_at
  files_enriched { path agent_id source magic_type }
  finding_triage_histories(order_by: {timestamp: desc}, limit: 1) {
    id automated username value explanation confidence true_positive_context timestamp
  }`;

// Tiny live queries: any new/deleted finding or new triage entry refreshes the current page
const SIGNAL_QUERIES = [
  'subscription FindingsChanged { findings_aggregate { aggregate { max { finding_id } } } }',
  'subscription FindingsTriageChanged { findings_triage_history_aggregate { aggregate { max { id } } } }',
];

const parseList = (value, allowed) => {
  if (!value) return allowed;
  const list = allowed.filter((v) => value.split(',').map((s) => s.trim()).includes(v));
  return list.length > 0 ? list : allowed;
};

// Filters, sort and page all live in the URL
const readUrlState = (searchParams) => {
  const triageState = searchParams.get('triage_state');
  const triageSource = searchParams.get('triage_source');
  const sortColumn = searchParams.get('sort_column');
  const page = parseInt(searchParams.get('page') || '1', 10);
  return {
    filters: {
      categories: parseList(searchParams.get('category'), ALL_CATEGORIES),
      severities: parseList(searchParams.get('severity'), ALL_SEVERITIES),
      search: searchParams.get('search') || '',
      triageState: TRIAGE_STATES.includes(triageState) ? triageState : DEFAULT_TRIAGE_STATE,
      triageSource: TRIAGE_SOURCES.includes(triageSource) ? triageSource : 'all',
      objectId: searchParams.get('object_id') || '',
    },
    sortColumn: SORT_COLUMNS.includes(sortColumn) ? sortColumn : 'created_at',
    sortDirection: searchParams.get('sort_direction') === 'asc' ? 'asc' : 'desc',
    page: Number.isFinite(page) && page > 0 ? page : 1,
  };
};

const FindingsList = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const navigateToFile = useFileNavigation();
  const { username } = useUser();

  const { filters, sortColumn, sortDirection, page: urlPage } = readUrlState(searchParams);
  const selectedParam = searchParams.get('selected');
  const isModalOpen = searchParams.get('modal') === 'true';
  const queryKey = JSON.stringify([filters, sortColumn, sortDirection]);

  // Update URL params from the latest location (not a possibly stale render), replacing by default
  const updateParams = useCallback((mutate, options = { replace: true }) => {
    const params = new URLSearchParams(window.location.search);
    mutate(params);
    if (params.toString() !== new URLSearchParams(window.location.search).toString()) {
      setSearchParams(params, options);
    }
  }, [setSearchParams]);

  // Normalize the URL so it always carries the triage state and sort (as before)
  useEffect(() => {
    updateParams((p) => {
      if (!p.get('triage_state')) p.set('triage_state', filters.triageState);
      if (!p.get('sort_column')) p.set('sort_column', sortColumn);
      if (!p.get('sort_direction')) p.set('sort_direction', sortDirection);
    });
  }, [location.pathname]); // eslint-disable-line react-hooks/exhaustive-deps

  const setPage = useCallback((p) => {
    updateParams((params) => {
      if (p > 1) params.set('page', String(p));
      else params.delete('page');
    });
  }, [updateParams]);

  // Optimistic triage: finding_id -> { value, doneAt } until a fetch started after the write lands
  const pendingTriage = useRef(new Map());
  const filtersRef = useRef(filters);
  // eslint-disable-next-line react-hooks/refs -- latest-value ref read by stable callbacks
  filtersRef.current = filters;

  const withTriage = (finding, value) => ({
    ...finding,
    finding_triage_histories: [{
      id: null, automated: false, username, value, explanation: null, confidence: null,
      true_positive_context: null, timestamp: new Date().toISOString(),
    }],
  });

  const transformRows = useCallback((rows, fetchStartedAt) => {
    const pending = pendingTriage.current;
    if (pending.size === 0) return { rows, dropped: 0 };
    const { triageState, triageSource } = filtersRef.current;
    let dropped = 0;
    const out = [];
    for (const row of rows) {
      const p = pending.get(row.finding_id);
      if (p && p.doneAt && fetchStartedAt > p.doneAt) {
        pending.delete(row.finding_id);
        out.push(row);
      } else if (p) {
        if (matchesAfterHumanTriage(p.value, triageState, triageSource)) out.push(withTriage(row, p.value));
        else dropped++;
      } else {
        out.push(row);
      }
    }
    return { rows: out, dropped };
  }, [username]); // eslint-disable-line react-hooks/exhaustive-deps

  const fetcher = useCallback(({ offset, limit, knownTotal, withCount, signal }) => fetchPage({
    table: 'findings',
    fields: ROW_FIELDS,
    where: buildFindingsWhere(filters),
    orderBy: buildFindingsOrderBy(sortColumn, sortDirection),
    offset, limit, knownTotal, withCount, signal,
  }), [queryKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const list = usePagedList({
    listKey: 'findings',
    pageSize: PAGE_SIZE,
    rowHeight: ROW_HEIGHT,
    page: urlPage,
    setPage,
    queryKey,
    fetcher,
    getId: (f) => f.finding_id,
    transformRows,
    signalQueries: SIGNAL_QUERIES,
  });
  const listRef = useRef(list);
  // eslint-disable-next-line react-hooks/refs -- latest-value ref read by the window key handler
  listRef.current = list;
  const {
    page, rows, rowsPage, total, totalPages, isLoading, isFetching, error, containerRef, nav,
    isTriageMode, setIsTriageMode, selectedIndex, select, checked, setChecked,
    allSelected,
  } = list;

  // Serialize triage writes so repeated presses on one finding land in order
  const writeQueue = useRef(Promise.resolve());

  const triage = useCallback((findingIds, value) => {
    if (findingIds.length === 0) return;
    const ids = [...new Set(findingIds)];
    const { triageState, triageSource } = filtersRef.current;
    const keep = matchesAfterHumanTriage(value, triageState, triageSource);
    ids.forEach((id) => pendingTriage.current.set(id, { value, doneAt: null }));

    // Update/drop the rows right away (selection stays on the same row, or the one that replaces it)
    const idSet = new Set(ids);
    const onPage = nav.current.rows.filter((r) => idSet.has(r.finding_id)).length;
    listRef.current.updateRows((current) => {
      const next = [];
      for (const row of current) {
        if (!idSet.has(row.finding_id)) next.push(row);
        else if (keep) next.push(withTriage(row, value));
      }
      return next;
    }, { totalDelta: keep ? 0 : -onPage });

    writeQueue.current = writeQueue.current.then(async () => {
      try {
        // A database trigger points each finding's triage_id/triage_value at this new entry
        await hasuraRequest(`
          mutation InsertTriage($objects: [findings_triage_history_insert_input!]!) {
            insert_findings_triage_history(objects: $objects) { affected_rows }
          }`, {
          objects: ids.map((id) => ({ finding_id: id, username, value, automated: false })),
        });
        const doneAt = Date.now();
        ids.forEach((id) => {
          const p = pendingTriage.current.get(id);
          if (p && p.value === value) p.doneAt = doneAt;
        });
      } catch (err) {
        console.error('Failed to record finding triage:', err);
        ids.forEach((id) => pendingTriage.current.delete(id));
        listRef.current.refetch();
      }
    });
  }, [username]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleTriage = useCallback((findingId, value) => triage([findingId], value), [triage]);

  // ----- Bulk triage of every result (second Ctrl+A) -----
  const bulkAction = useBulkAction();
  const TRIAGE_LABELS = { true_positive: 'true positive', false_positive: 'false positive', needs_review: 'needs review' };

  const triageAllResults = useCallback((value) => {
    const count = nav.current.total || 0;
    if (count === 0) return;
    // Snapshot the filters: the selection is "everything these filters match right now"
    const where = buildFindingsWhere(filtersRef.current);
    const label = TRIAGE_LABELS[value];
    bulkAction.ask({
      message: `Triage all ${count.toLocaleString()} findings matching the current filters as ${label}?`,
      label: `Triaging as ${label}`,
      total: count,
      work: (progress) => forEachIdChunk({
        table: 'findings',
        idField: 'finding_id',
        where,
        chunkSize: 2000,
        onChunk: async (ids) => {
          await hasuraRequest(`
            mutation InsertTriage($objects: [findings_triage_history_insert_input!]!) {
              insert_findings_triage_history(objects: $objects) { affected_rows }
            }`, { objects: ids.map((id) => ({ finding_id: id, username, value, automated: false })) });
          progress(ids.length);
        },
      }),
      doneMessage: (n) => `Triaged ${n.toLocaleString()} findings as ${label}.`,
      onFinish: () => {
        listRef.current.clearSelection();
        listRef.current.refetch();
      },
    });
  }, [username]); // eslint-disable-line react-hooks/exhaustive-deps

  // ----- Selection <-> URL -----
  // Apply ?selected=<finding id> once the first page has loaded (turns triage mode on, as before)
  const initialSelectionDone = useRef(false);
  useEffect(() => {
    if (initialSelectionDone.current || isLoading) return;
    initialSelectionDone.current = true;
    if (!selectedParam) return;
    const idx = rows.findIndex((f) => String(f.finding_id) === selectedParam);
    if (idx >= 0) {
      setIsTriageMode(true);
      select(idx);
    }
  }, [isLoading]); // eslint-disable-line react-hooks/exhaustive-deps

  // (undefined while another page is loading: the index already refers to that page)
  const selectedRow = selectedIndex >= 0 && rowsPage === page ? rows[selectedIndex] : undefined;

  // Mirror the triage selection (finding id) into the URL. Outside triage mode ?selected only
  // names the finding whose modal is open (set when it was opened).
  useEffect(() => {
    if (!initialSelectionDone.current || isLoading) return;
    let id;
    if (isTriageMode) {
      if (!selectedRow) return;
      id = String(selectedRow.finding_id);
    } else {
      if (isModalOpen) return;
      id = null;
    }
    if (id === selectedParam) return undefined;
    // Debounced: every router update re-renders the app, which would slow down key repeat
    const timer = setTimeout(() => updateParams((p) => (id ? p.set('selected', id) : p.delete('selected'))), 250);
    return () => clearTimeout(timer);
  }, [selectedRow, isTriageMode, isModalOpen, selectedParam, isLoading, updateParams]);

  // ----- Modal (open state lives in the URL so Back/Forward open and close it) -----
  const openModal = useCallback((finding) => {
    updateParams((p) => {
      p.set('selected', String(finding.finding_id));
      p.set('modal', 'true');
    }, { replace: false, state: { findingModal: true } });
  }, [updateParams]);

  const closeModal = useCallback(() => {
    if (location.state?.findingModal) {
      navigate(-1);
    } else {
      updateParams((p) => p.delete('modal'));
    }
  }, [location.state, navigate, updateParams]);

  const modalFindingId = isModalOpen ? (selectedRow && (isTriageMode || String(selectedRow.finding_id) === selectedParam)
    ? selectedRow.finding_id : parseInt(selectedParam, 10)) : null;
  const [modalDetails, setModalDetails] = useState(null);
  useEffect(() => {
    if (!modalFindingId) return undefined;
    let cancelled = false;
    hasuraRequest(`
      query FindingDetails($id: bigint!) {
        findings_by_pk(finding_id: $id) { ${ROW_FIELDS} data }
      }`, { id: modalFindingId })
      .then((data) => { if (!cancelled) setModalDetails(data.findings_by_pk); })
      .catch((err) => console.error('Failed to load finding details:', err));
    return () => { cancelled = true; };
  }, [modalFindingId]);

  const modalFinding = useMemo(() => {
    if (!modalFindingId) return null;
    const row = rows.find((f) => f.finding_id === modalFindingId);
    const details = modalDetails?.finding_id === modalFindingId ? modalDetails : null;
    if (!row && !details) return null;
    // Row carries the optimistic triage state; details carry the data
    return { ...(details || {}), ...(row || {}), data: details ? details.data : undefined };
  }, [modalFindingId, rows, modalDetails]);

  // ----- Sorting / filters -----
  const handleSort = useCallback((column, direction) => {
    updateParams((p) => {
      p.set('sort_column', column);
      p.set('sort_direction', direction);
      p.delete('page');
    });
  }, [updateParams]);

  const handleFiltersChange = useCallback((changes) => {
    updateParams((p) => {
      const next = { ...filtersRef.current, ...changes };
      const setOrDelete = (key, value) => (value ? p.set(key, value) : p.delete(key));
      setOrDelete('category', next.categories.length < ALL_CATEGORIES.length ? next.categories.join(',') : '');
      setOrDelete('severity', next.severities.length < ALL_SEVERITIES.length ? next.severities.join(',') : '');
      setOrDelete('search', next.search);
      p.set('triage_state', next.triageState);
      setOrDelete('triage_source', next.triageSource !== 'all' ? next.triageSource : '');
      setOrDelete('object_id', next.objectId);
      p.delete('page');
    });
  }, [updateParams]);

  // ----- Row callbacks (stable, so memoized rows only re-render when their own props change) -----
  // Click: open the details (and make the row active in triage mode). In triage mode, Ctrl/Cmd-click
  // toggles the row's selection and Shift-click selects the range from the active row; neither opens
  // the details (same selection clicks as the Files list).
  const handleRowClick = useCallback((finding, index, e) => {
    const n = nav.current;
    if (n.triage && e && (e.ctrlKey || e.metaKey || e.shiftKey)) {
      const set = new Set(n.checked);
      if (e.shiftKey && n.index >= 0 && n.rowsPage === n.page) {
        const start = Math.min(n.index, index);
        const end = Math.max(n.index, index);
        for (let i = start; i <= end; i++) if (n.rows[i]) set.add(n.rows[i].finding_id);
      } else if (set.has(finding.finding_id)) {
        set.delete(finding.finding_id);
      } else {
        set.add(finding.finding_id);
      }
      setChecked(set);
      select(index);
      return;
    }
    if (n.triage) select(index);
    openModal(finding);
  }, [openModal, select, setChecked, nav]);

  // ----- Keyboard -----
  const keyState = useRef({ isModalOpen, closeModal, openModal, triage, navigateToFile, bulkAction, triageAllResults });
  // eslint-disable-next-line react-hooks/refs -- latest-value ref read by the window key handler
  keyState.current = { isModalOpen, closeModal, openModal, triage, navigateToFile, bulkAction, triageAllResults };

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (isEditableTarget(e.target)) return;
      if (keyState.current.bulkAction.handleKey(e)) return;
      const { isModalOpen: modalOpen, closeModal: close } = keyState.current;
      const n = nav.current;

      switch (e.key) {
        case 'ArrowLeft':
        case 'Escape':
          // The details dialog takes the key first: Esc/← only close it
          if (modalOpen) {
            e.preventDefault();
            close();
            return;
          }
          break;
        case 't':
          if (e.ctrlKey || e.metaKey || e.altKey) return;
          e.preventDefault();
          if (!n.triage && n.index < 0) select(0);
          setIsTriageMode((v) => !v);
          return;
        case 'PageDown':
        case 'PageUp':
          if (modalOpen || e.ctrlKey || e.metaKey || e.altKey) return;
          e.preventDefault();
          {
            const dir = e.key === 'PageDown' ? 1 : -1;
            listRef.current.run(() => listRef.current.pageKey(dir));
          }
          return;
        default:
          break;
      }

      if (!n.triage) return;

      const ctrlA = (e.ctrlKey || e.metaKey) && e.key === 'a';
      if (ctrlA && modalOpen) return;
      if (!ctrlA && !['Escape', 'ArrowUp', 'ArrowDown', 'ArrowRight', '1', '2', '3', ' '].includes(e.key)) return;
      if (e.key !== 'Escape') e.preventDefault();
      const { key, shiftKey } = e;
      const l = listRef.current;

      // Row actions run in order once a page that is still loading has arrived
      l.run(() => {
        const row = l.currentRow();
        if (ctrlA) {
          // First press: this page; second press: every result
          l.selectAllKey();
          return;
        }
        switch (key) {
          case 'Escape':
            // Clear the selection, or leave triage mode when there is none (same as Files)
            if (n.checked.size > 0 || n.allSelected) {
              l.clearSelection();
            } else {
              setIsTriageMode(false);
              select(-1);
            }
            break;
          case 'ArrowUp':
          case 'ArrowDown': {
            const delta = key === 'ArrowDown' ? 1 : -1;
            if (shiftKey) l.extendSelection(delta);
            else l.moveSelection(delta);
            break;
          }
          case 'ArrowRight':
            if (!row) break;
            if (keyState.current.isModalOpen) keyState.current.navigateToFile(row);
            else keyState.current.openModal(row);
            break;
          case '1':
          case '2':
          case '3': {
            const value = { 1: 'true_positive', 2: 'false_positive', 3: 'needs_review' }[key];
            if (n.allSelected) {
              keyState.current.triageAllResults(value);
            } else if (n.checked.size > 0) {
              keyState.current.triage([...n.checked], value);
              setChecked(new Set());
            } else if (row) {
              keyState.current.triage([row.finding_id], value);
            }
            break;
          }
          case ' ':
            if (row && !keyState.current.isModalOpen) {
              const set = new Set(n.checked);
              if (set.has(row.finding_id)) set.delete(row.finding_id);
              else set.add(row.finding_id);
              setChecked(set);
            }
            break;
          default:
            break;
        }
      });
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (error && rows.length === 0) {
    return <Alert title="Error" variant="error">Failed to load findings: {error}</Alert>;
  }

  return (
    <div className="bg-white dark:bg-dark-secondary rounded-lg shadow flex flex-col h-[calc(100vh-1rem)]">
      {/* Triage mode indicator */}
      <div className="p-1 bg-blue-50 dark:bg-blue-900/20 border-b dark:border-gray-700">
        <p className="text-sm text-blue-600 dark:text-blue-400">
          {isTriageMode
            ? 'Triage Mode Active: ↑↓ to navigate (PgUp/PgDn to jump), → to view details. Select multiple with Shift + ↑↓, hitting space, or Ctrl+A (press again to select all results). Clear selection with ESC. Triage selected results with 1, 2, or 3 keys.'
            : "Press 't' to enter triage mode"}
          {isTriageMode && (allSelected || checked.size > 0) && (
            <span className="ml-2 font-semibold">
              {allSelected
                ? `All ${(total || 0).toLocaleString()} results selected.`
                : `${checked.size.toLocaleString()} selected${checked.size === rows.length && typeof total === 'number' && total > rows.length ? ' (Ctrl+A again to select all results)' : ''}.`}
            </span>
          )}
        </p>
      </div>

      <BulkActionBar bulk={bulkAction.bulk} onConfirm={bulkAction.confirm} onCancel={bulkAction.cancel} />

      {/* Filters section */}
      <FindingsFilters filters={filters} onChange={handleFiltersChange} totalCount={total} />

      {/* Findings Table - fills the remaining viewport height so the list never extends below the window */}
      <div className="overflow-x-auto flex-1 min-h-0 flex flex-col">
        <TableHeaders
          isTriageMode={isTriageMode}
          sortColumn={sortColumn}
          sortDirection={sortDirection}
          onSort={handleSort}
        />

        {isLoading && rows.length === 0 ? (
          <div className="flex justify-center py-4">
            <div className="animate-spin rounded-full h-10 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
          </div>
        ) : rows.length === 0 && !isFetching ? (
          <NoResults />
        ) : (
          <div
            ref={containerRef}
            className={`${list.keyboardNav ? 'kbd-nav ' : ''}flex-1 min-h-0 overflow-y-auto overflow-x-hidden transition-opacity ${isFetching && nav.current.loading ? 'opacity-60' : ''}`}
          >
            {rows.map((finding, index) => (
              <TableRow
                key={finding.finding_id}
                finding={finding}
                index={index}
                height={ROW_HEIGHT}
                isTriageMode={isTriageMode}
                isSelected={isTriageMode && index === selectedIndex && rowsPage === page}
                isChecked={isTriageMode && (allSelected || checked.has(finding.finding_id))}
                onRowClick={handleRowClick}
                onTriage={handleTriage}
              />
            ))}
          </div>
        )}
        {error && rows.length > 0 && (
          <div className="px-4 py-1 text-sm text-red-600 dark:text-red-400">Failed to refresh findings: {error}</div>
        )}
      </div>

      {typeof total === 'number' && total > 0 && (
        <PaginationControls
          currentPage={Math.min(page, totalPages)}
          totalPages={totalPages}
          totalCount={total}
          pageSize={PAGE_SIZE}
          itemLabel="findings"
          onPageChange={(p) => {
            if (p >= 1 && p <= totalPages) list.goToPage(p);
          }}
        />
      )}

      <FindingModal
        isOpen={isModalOpen && !!modalFinding}
        onClose={closeModal}
        finding={modalFinding}
      />
    </div>
  );
};

// Empty result: tell "no findings at all" apart from "none match the filters" with a 1-row query
const NoResults = () => {
  const [anyFindings, setAnyFindings] = useState(null);
  useEffect(() => {
    hasuraRequest('query AnyFinding { findings(limit: 1) { finding_id } }')
      .then((data) => setAnyFindings(data.findings.length > 0))
      .catch(() => setAnyFindings(true));
  }, []);
  if (anyFindings === null) return null;
  return anyFindings ? <NoFilteredFindings /> : <NoFindings />;
};

const NoFindings = () => {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4">
      <div className="text-center">
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
          No findings available
        </h3>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          No findings have been generated yet. Findings will appear here as Nemesis performs its analysis.
        </p>
      </div>
    </div>
  );
};

const NoFilteredFindings = () => {
  const [, setSearchParams] = useSearchParams();

  // Reset to the default filters (untriaged + actionable), keeping the sort
  const handleViewAllFindings = () => {
    const params = new URLSearchParams(window.location.search);
    params.set('triage_state', DEFAULT_TRIAGE_STATE);
    ['category', 'severity', 'search', 'origin', 'triage_source', 'object_id', 'page', 'selected', 'modal'].forEach((k) => params.delete(k));
    setSearchParams(params, { replace: false });
  };

  return (
    <div className="flex flex-col items-center justify-center py-16 px-4">
      <div className="text-center">
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
          No findings match your current filters
        </h3>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          Adjust the filters or click below to view default findings.
        </p>
        <button
          onClick={handleViewAllFindings}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors inline-flex items-center"
        >
          View Default Findings
        </button>
      </div>
    </div>
  );
};

export default FindingsList;

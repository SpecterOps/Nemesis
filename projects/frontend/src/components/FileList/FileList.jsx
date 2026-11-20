import { CheckCell, CheckHeaderCell, LIST_ROW_HEIGHT, SortableHeader, listRowClassName } from '@/components/shared/ListTable';
import Tooltip from '@/components/shared/Tooltip2';
import { useUser } from '@/contexts/UserContext';
import { fetchPage, forEachIdChunk, hasuraRequest, isEditableTarget } from '@/hooks/pagedList';
import { useBulkAction } from '@/hooks/useBulkAction';
import { usePagedList } from '@/hooks/usePagedList';
import { AlertTriangle, ChevronDown, Eye, Search, Tag, X } from 'lucide-react';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { FILES_PAGE_SIZE, FILE_SORT_COLUMNS, buildFilesOrderBy, buildFilesWhere } from './fileQuery';
import BulkActionBar from './BulkActionBar';
import PaginationControls from './PaginationControls';

const ROW_HEIGHT = LIST_ROW_HEIGHT;
const PAGE_SIZE = FILES_PAGE_SIZE;

export const formatFileSize = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
};

// Prevent tooltip clicks from triggering row navigation
const stopPropagation = (e) => e.stopPropagation();

// One file row. Per-row props + stable callbacks so React.memo skips rows whose selection
// state didn't change (keyboard navigation re-renders only two rows).
/**
 * @param {{
 *   file: any, index: number, isTriageMode: boolean, isSelected: boolean, isChecked: boolean,
 *   onRowClick: (e: any, file: any, index: number) => void, username: string,
 * }} props
 */
const FileRow = ({ file, index, isTriageMode, isSelected, isChecked, onRowClick, username }) => {
  const findingsCount = file.findings_count || 0;
  const isActive = isTriageMode && isSelected;
  return (
    // Keyboard access to rows is the page-level handler (t, arrows, ArrowRight opens), not per-row focus
    // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
    <div
      style={{ height: ROW_HEIGHT }}
      data-row-index={index}
      data-object-id={file.object_id}
      data-active={isActive ? 'true' : undefined}
      className={listRowClassName(isTriageMode, isChecked, isActive)}
      onClick={(e) => onRowClick(e, file, index)}
    >
      {isTriageMode && <CheckCell checked={isChecked} />}
      <div className="px-2 flex-shrink-0 w-32 text-sm text-gray-500 dark:text-gray-400 text-left">
        <Tooltip
          content={<div role="presentation" onClick={stopPropagation} className="select-text">{file.agent_id}</div>}
          side="top"
          align="start"
        >
          <span className="block truncate">{file.agent_id}</span>
        </Tooltip>
      </div>
      <div className="px-2 flex-shrink-0 w-40 text-sm text-gray-500 dark:text-gray-400 text-left">
        <Tooltip
          content={<div role="presentation" onClick={stopPropagation} className="select-text">{file.source || 'Unknown'}</div>}
          side="top"
          align="start"
        >
          <span className="block truncate">{file.source || 'Unknown'}</span>
        </Tooltip>
      </div>
      <div className="px-2 flex-shrink-0 w-24 text-sm text-gray-500 dark:text-gray-400 text-left">{formatFileSize(file.size)}</div>
      <div className="px-2 flex-shrink-0 w-44 text-sm text-gray-500 dark:text-gray-400 text-left">{new Date(file.timestamp).toLocaleString()}</div>
      <div className="px-2 flex-shrink-0 w-48 text-sm text-sm text-gray-500 dark:text-gray-400 text-left">
        <Tooltip
          content={<div role="presentation" onClick={stopPropagation} className="select-text">{file.magic_type || 'Unknown'}</div>}
          side="top"
        >
          <span className="inline-block max-w-full px-2 py-0.5 rounded-full text-xs bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300 truncate">
            {file.magic_type || 'Unknown'}
          </span>
        </Tooltip>
      </div>
      <div className="px-2 flex-shrink-0 w-12 text-sm flex items-center justify-center h-full text-center">
        <span className={`inline-flex items-center justify-center min-w-[24px] h-6 px-2 rounded-full text-xs ${findingsCount > 0 ? 'bg-red-100 dark:bg-red-900/20 text-red-600 dark:text-red-400' : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'}`}>
          {findingsCount}
        </span>
      </div>
      <div className="px-6 flex-grow text-sm text-gray-500 dark:text-gray-400 truncate text-left relative">
        {!file.files_view_histories?.some(h => h.username === username) && (
          <div className="absolute left top-1/2 transform -translate-y-1/2 w-1.5 h-1.5 bg-blue-400 opacity-60 rounded-full" title="Unviewed by you"></div>
        )}
        <Tooltip
          content={<div role="presentation" onClick={stopPropagation} className="select-text">{file.path}</div>}
          side="top"
          align="start"
          maxWidth="full"
        >
          <span className="ml-3">{file.path}</span>
        </Tooltip>
      </div>
    </div>
  );
};
const Row = React.memo(FileRow);

// Sortable header component
const FILE_FIELDS = `
  object_id
  agent_id
  source
  file_name
  size
  path
  timestamp
  extension
  magic_type
  mime_type
  is_plaintext
  file_tags
  findings_count
  files_view_histories(where: {username: {_eq: $username}}, order_by: {timestamp: desc}, limit: 1) { username timestamp }`;

// Tiny live queries: new files, new findings or new views refresh the current page
const SIGNAL_QUERIES = [
  'subscription FilesChanged { files_enriched_aggregate { aggregate { max { created_at } } } }',
  'subscription FindingsChanged { findings_aggregate { aggregate { max { finding_id } } } }',
  'subscription FileViewsChanged { files_view_history_aggregate { aggregate { max { id } } } }',
];

const FILE_TYPES = ['all', 'plaintext', 'binary', 'source', 'office', 'config'];
const VIEW_STATES = ['unviewed', 'unviewed_by_me', 'all'];

// Filters, sort and page all live in the URL
const readUrlState = (searchParams) => {
  const type = searchParams.get('type');
  const viewState = searchParams.get('view_state');
  const sortColumn = searchParams.get('sort_column');
  const page = parseInt(searchParams.get('page') || '1', 10);
  return {
    filters: {
      fileType: FILE_TYPES.includes(type) ? type : 'all',
      source: searchParams.get('source') || '',
      path: searchParams.get('path') || '',
      objectId: searchParams.get('object_id') || '',
      tag: searchParams.get('tag') || '',
      viewState: VIEW_STATES.includes(viewState) ? viewState : 'all',
      onlyWithFindings: searchParams.get('findings') === 'true',
    },
    sortColumn: FILE_SORT_COLUMNS.includes(sortColumn) ? sortColumn : 'timestamp',
    sortDirection: searchParams.get('sort_direction') === 'asc' ? 'asc' : 'desc',
    page: Number.isFinite(page) && page > 0 ? page : 1,
  };
};

// Text filter box that updates its (server-side) filter after a short pause in typing
const DebouncedInput = ({ value, onChange, ...props }) => {
  const [text, setText] = useState(value);
  const timer = useRef(null);
  // Adopt external value changes (e.g. Back/Forward) during render rather than in an effect
  const [prevValue, setPrevValue] = useState(value);
  if (value !== prevValue) {
    setPrevValue(value);
    setText(value);
  }
  useEffect(() => () => clearTimeout(timer.current), []);
  return (
    <input
      {...props}
      value={text}
      onChange={(e) => {
        const v = e.target.value;
        setText(v);
        clearTimeout(timer.current);
        timer.current = setTimeout(() => onChange(v), 300);
      }}
    />
  );
};

const FileList = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const { username } = useUser();

  const { filters, sortColumn, sortDirection, page: urlPage } = readUrlState(searchParams);
  const queryKey = JSON.stringify([filters, sortColumn, sortDirection, username]);
  const filtersRef = useRef(filters);
  // eslint-disable-next-line react-hooks/refs -- latest-value ref read by stable callbacks
  filtersRef.current = filters;

  const [availableTags, setAvailableTags] = useState([]);
  const [isTagDropdownOpen, setIsTagDropdownOpen] = useState(false);
  const tagDropdownRef = useRef(null);
  const [tagMenuPos, setTagMenuPos] = useState({ top: 0, left: 0 });

  // Update URL params from the latest location (not a possibly stale render), replacing by default
  const updateParams = useCallback((mutate, options = { replace: true }) => {
    const params = new URLSearchParams(window.location.search);
    mutate(params);
    if (params.toString() !== new URLSearchParams(window.location.search).toString()) {
      setSearchParams(params, options);
    }
  }, [setSearchParams]);

  // Normalize the URL so it always carries the view state and sort (as before)
  useEffect(() => {
    updateParams((p) => {
      if (!p.get('view_state')) p.set('view_state', filters.viewState);
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

  const setFilter = useCallback((key, value) => {
    updateParams((p) => {
      if (value) p.set(key, value);
      else p.delete(key);
      p.delete('page');
    });
  }, [updateParams]);

  // Optimistic "viewed" marks: object_id -> { doneAt } until a fetch started after the write lands
  const pendingViews = useRef(new Map());
  const dropsWhenViewed = (viewState) => viewState === 'unviewed' || viewState === 'unviewed_by_me';
  const withView = (file) => ({
    ...file,
    files_view_histories: [{ username, timestamp: new Date().toISOString() }],
  });

  const transformRows = useCallback((rows, fetchStartedAt) => {
    const pending = pendingViews.current;
    if (pending.size === 0) return { rows, dropped: 0 };
    const drop = dropsWhenViewed(filtersRef.current.viewState);
    let dropped = 0;
    const out = [];
    for (const row of rows) {
      const p = pending.get(row.object_id);
      if (p && p.doneAt && fetchStartedAt > p.doneAt) {
        pending.delete(row.object_id);
        out.push(row);
      } else if (p) {
        if (drop) dropped++;
        else out.push(withView(row));
      } else {
        out.push(row);
      }
    }
    return { rows: out, dropped };
  }, [username]); // eslint-disable-line react-hooks/exhaustive-deps

  const fetcher = useCallback(({ offset, limit, knownTotal, withCount, signal }) => fetchPage({
    table: 'files_enriched',
    fields: FILE_FIELDS,
    where: buildFilesWhere({ ...filters, username }),
    orderBy: buildFilesOrderBy(sortColumn, sortDirection),
    offset, limit, knownTotal, withCount, signal,
    varDefs: ', $username: String!',
    vars: { username: username || '' },
  }), [queryKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const list = usePagedList({
    listKey: 'files',
    pageSize: PAGE_SIZE,
    rowHeight: ROW_HEIGHT,
    page: urlPage,
    setPage,
    queryKey,
    fetcher,
    getId: (f) => f.object_id,
    transformRows,
    signalQueries: SIGNAL_QUERIES,
  });
  const listRef = useRef(list);
  // eslint-disable-next-line react-hooks/refs -- latest-value ref read by the window key handler
  listRef.current = list;
  const {
    page, rows: files, rowsPage, total, totalPages, isLoading, isFetching, error, containerRef, nav,
    isTriageMode, setIsTriageMode, selectedIndex, select, checked: selectedFiles, setChecked,
    allSelected,
  } = list;

  const handleSort = (column, direction) => {
    updateParams((p) => {
      p.set('sort_column', column);
      p.set('sort_direction', direction);
      p.delete('page');
    });
  };

  const openFile = useCallback((file) => {
    // Keep the filters/sort/page in the URL so returning from the file viewer restores them
    const currentSearch = window.location.search;
    navigate(`/files/${file.object_id}${currentSearch}`);
  }, [navigate]);

  // Serialize writes so repeated presses land in order
  const writeQueue = useRef(Promise.resolve());

  const recordFileViews = useCallback((objectIds) => {
    const ids = [...new Set(objectIds)];
    if (ids.length === 0) return;
    ids.forEach((id) => pendingViews.current.set(id, { doneAt: null }));
    const drop = dropsWhenViewed(filtersRef.current.viewState);
    const idSet = new Set(ids);
    const onPage = nav.current.rows.filter((r) => idSet.has(r.object_id)).length;
    listRef.current.updateRows(
      (current) => current.flatMap((row) => (!idSet.has(row.object_id) ? [row] : drop ? [] : [withView(row)])),
      { totalDelta: drop ? -onPage : 0 },
    );

    writeQueue.current = writeQueue.current.then(async () => {
      try {
        await hasuraRequest(`
          mutation InsertFileViews($objects: [files_view_history_insert_input!]!) {
            insert_files_view_history(objects: $objects) { affected_rows }
          }`, { objects: ids.map((id) => ({ object_id: id, username, automated: false })) });
        const doneAt = Date.now();
        ids.forEach((id) => {
          const p = pendingViews.current.get(id);
          if (p) p.doneAt = doneAt;
        });
      } catch (err) {
        console.error('Failed to record file view:', err);
        ids.forEach((id) => pendingViews.current.delete(id));
        listRef.current.refetch();
      }
    });
  }, [username]); // eslint-disable-line react-hooks/exhaustive-deps

  // ----- Mark every result viewed (second Ctrl+A, then 'v') -----
  const bulkAction = useBulkAction();
  const viewAllResults = useCallback(() => {
    const count = nav.current.total || 0;
    if (count === 0) return;
    // Snapshot the filters: the selection is "everything these filters match right now"
    const where = buildFilesWhere({ ...filtersRef.current, username });
    bulkAction.ask({
      message: `Mark all ${count.toLocaleString()} files matching the current filters as viewed?`,
      label: 'Marking files as viewed',
      total: count,
      work: (progress) => forEachIdChunk({
        table: 'files_enriched',
        idField: 'object_id',
        where,
        chunkSize: 5000,
        onChunk: async (ids) => {
          await hasuraRequest(`
            mutation InsertFileViews($objects: [files_view_history_insert_input!]!) {
              insert_files_view_history(objects: $objects) { affected_rows }
            }`, { objects: ids.map((id) => ({ object_id: id, username, automated: false })) });
          progress(ids.length);
        },
      }),
      doneMessage: (n) => `Marked ${n.toLocaleString()} files as viewed.`,
      onFinish: () => {
        listRef.current.clearSelection();
        listRef.current.refetch();
      },
    });
  }, [username]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleRowClick = useCallback((e, file, index) => {
    const n = nav.current;
    if (n.triage) {
      if (e.shiftKey && n.index >= 0 && n.rowsPage === n.page) {
        const start = Math.min(n.index, index);
        const end = Math.max(n.index, index);
        const set = new Set(n.checked);
        for (let i = start; i <= end; i++) if (n.rows[i]) set.add(n.rows[i].object_id);
        setChecked(set);
      } else if (e.ctrlKey || e.metaKey) {
        const set = new Set(n.checked);
        if (set.has(file.object_id)) set.delete(file.object_id);
        else set.add(file.object_id);
        setChecked(set);
      } else {
        setChecked(new Set([file.object_id]));
      }
      select(index);
    } else if (!e.target.closest('button')) {
      openFile(file);
    }
  }, [nav, openFile, select, setChecked]);

  useEffect(() => {
    const fetchAvailableTags = async () => {
      try {
        const data = await hasuraRequest('query GetAllTags { file_tags { tag_name } }');
        setAvailableTags(data.file_tags.map((tag) => tag.tag_name));
      } catch (err) {
        console.error('Failed to fetch available tags:', err);
      }
    };
    fetchAvailableTags();
  }, []);

  useEffect(() => {
    if (!isTagDropdownOpen) return undefined;
    const handleClickOutside = (event) => {
      if (tagDropdownRef.current && !tagDropdownRef.current.contains(event.target)) {
        setIsTagDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isTagDropdownOpen]);

  // Keyboard controls (one listener; reads the latest state through refs)
  const keyState = useRef({ openFile, recordFileViews, bulkAction, viewAllResults });
  // eslint-disable-next-line react-hooks/refs -- latest-value ref read by the window key handler
  keyState.current = { openFile, recordFileViews, bulkAction, viewAllResults };

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (isEditableTarget(e.target)) return;
      if (keyState.current.bulkAction.handleKey(e)) return;
      const n = nav.current;
      const l = listRef.current;

      if ((e.ctrlKey || e.metaKey) && e.key === 'a') {
        if (n.triage) {
          e.preventDefault();
          // First press: the files on this page; second press: every result
          l.run(() => l.selectAllKey());
        }
        return;
      }

      if (e.key === 't' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        if (!n.triage && n.index < 0) select(0);
        setIsTriageMode((v) => !v);
        return;
      }

      if ((e.key === 'PageDown' || e.key === 'PageUp') && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        const dir = e.key === 'PageDown' ? 1 : -1;
        l.run(() => l.pageKey(dir));
        return;
      }

      if (!n.triage) return;
      if (!['ArrowUp', 'ArrowDown', 'Escape', 'ArrowRight', 'v', ' '].includes(e.key)) return;
      e.preventDefault();
      const { key, shiftKey } = e;

      // Row actions run in order once a page that is still loading has arrived
      l.run(() => {
        const row = l.currentRow();
        switch (key) {
          case 'ArrowUp':
          case 'ArrowDown': {
            const delta = key === 'ArrowDown' ? 1 : -1;
            if (shiftKey) l.extendSelection(delta);
            else l.moveSelection(delta);
            break;
          }
          case 'Escape':
            if (n.checked.size > 0 || n.allSelected) {
              l.clearSelection();
            } else {
              setIsTriageMode(false);
              select(-1);
            }
            break;
          case 'ArrowRight':
            if (row) keyState.current.openFile(row);
            break;
          case ' ':
            // Toggle the active row's selection (same as Findings)
            if (row) {
              const set = new Set(n.checked);
              if (set.has(row.object_id)) set.delete(row.object_id);
              else set.add(row.object_id);
              setChecked(set);
            }
            break;
          case 'v':
            if (n.allSelected) {
              keyState.current.viewAllResults();
            } else if (n.checked.size > 0) {
              keyState.current.recordFileViews([...n.checked]);
              setChecked(new Set());
            } else if (row) {
              keyState.current.recordFileViews([row.object_id]);
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

  const hasActiveFilters = filters.fileType !== 'all' || !!filters.source || !!filters.path || !!filters.objectId
    || !!filters.tag || filters.viewState !== 'all' || filters.onlyWithFindings;

  return (
    <div className="bg-white dark:bg-dark-secondary rounded-lg shadow flex flex-col h-[calc(100vh-1rem)]">
      {isTriageMode && (
        <div className="p-1 bg-blue-50 dark:bg-blue-900/20 border-b dark:border-gray-700">
          <p className="text-sm text-blue-600 dark:text-blue-400">
            Triage Mode Active(<a href="https://specterops.github.io/Nemesis/usage_guide/#file-triage-mode" target="_blank" rel="noopener noreferrer" className="underline hover:text-blue-700 dark:hover:text-blue-300">more info</a>) - Use ↑ ↓ ← → to navigate (PgUp/PgDn to jump). Space or Shift+↑↓ to select, Ctrl/Cmd+A to select all on the current page (press again to select all results).
            &apos;v&apos; to mark{allSelected || selectedFiles.size > 0 ? ' selected files' : ''} as viewed,
            or ESC to exit{' '}
            {(allSelected || selectedFiles.size > 0) && (
              <span className="font-semibold">
                {allSelected
                  ? `All ${(total || 0).toLocaleString()} results selected.`
                  : `${selectedFiles.size.toLocaleString()} selected${selectedFiles.size === files.length && typeof total === 'number' && total > files.length ? ' (Ctrl+A again to select all results)' : ''}.`}
              </span>
            )}

          </p>
        </div>
      )}
      <BulkActionBar bulk={bulkAction.bulk} onConfirm={bulkAction.confirm} onCancel={bulkAction.cancel} />

      {/* Filters */}
      <div className="p-2 border-b dark:border-gray-700 overflow-x-auto">
        <div className="flex items-center space-x-4 min-w-max">
          <div className="flex items-center space-x-2">
            <Eye className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <select
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={filters.viewState}
              onChange={(e) => setFilter('view_state', e.target.value)}
            >
              <option value="unviewed">Unviewed Files</option>
              <option value="unviewed_by_me">Files Unviewed by Me</option>
              <option value="all">All Files</option>
            </select>
          </div>

          <Tooltip content={filters.onlyWithFindings ? "Click to show all files" : "Click to show only files with findings"}>
            <button
              className="flex items-center space-x-2 px-3 py-2 border dark:border-gray-700 rounded hover:bg-gray-100 dark:hover:bg-gray-700"
              onClick={() => setFilter('findings', filters.onlyWithFindings ? '' : 'true')}
            >
              <AlertTriangle className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              <span className="text-sm text-gray-700 dark:text-gray-300">
                (Findings) {filters.onlyWithFindings ? "Files With Findings" : "All Files"}
              </span>
            </button>
          </Tooltip>

          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <DebouncedInput
              type="text"
              placeholder="Filter by source"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={filters.source}
              onChange={(v) => setFilter('source', v)}
            />
          </div>

          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <DebouncedInput
              type="text"
              placeholder="Filter by path (e.g. *.txt)"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={filters.path}
              onChange={(v) => setFilter('path', v)}
            />
          </div>

          <div className="relative" ref={tagDropdownRef}>
            <button
              className="flex items-center space-x-2 px-3 py-2 border dark:border-gray-700 rounded hover:bg-gray-100 dark:hover:bg-gray-700"
              onClick={() => {
                // Fixed-position menu (the filter bar scrolls horizontally): place it under the button
                const rect = tagDropdownRef.current?.getBoundingClientRect();
                setTagMenuPos({
                  top: (rect?.bottom || 0) + window.scrollY + 5,
                  left: (rect?.left || 0) + window.scrollX,
                });
                setIsTagDropdownOpen((open) => !open);
              }}
            >
              <Tag className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              <span className="text-sm text-gray-700 dark:text-gray-300">
                {filters.tag ? filters.tag : "Filter by Tag"}
              </span>
              {filters.tag ? (
                // Mouse shortcut inside the toggle button (a button can't nest another);
                // keyboard users clear the tag with the menu's "Show All Files" option
                // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
                <span
                  className="ml-2 cursor-pointer text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                  onClick={(e) => {
                    e.stopPropagation();
                    setFilter('tag', '');
                  }}
                >
                  <X className="w-4 h-4" />
                </span>
              ) : (
                <ChevronDown className="w-4 h-4 text-gray-500 dark:text-gray-400" />
              )}
            </button>

            {isTagDropdownOpen && (
              <div className="fixed min-w-[250px] shadow-xl border border-gray-200 dark:border-gray-700 rounded-md bg-white dark:bg-gray-800 py-1"
                style={{
                  top: `${tagMenuPos.top}px`,
                  left: `${tagMenuPos.left}px`,
                  zIndex: 9999
                }}>
                <div className="max-h-60 overflow-y-auto">
                  <button
                    className={`w-full text-left px-4 py-2 text-sm ${!filters.tag ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'}`}
                    onClick={() => {
                      setFilter('tag', '');
                      setIsTagDropdownOpen(false);
                    }}
                  >
                    Show All Files
                  </button>

                  {availableTags.length > 0 ? (
                    availableTags.map((tag) => (
                      <button
                        key={tag}
                        className={`w-full text-left px-4 py-2 text-sm ${filters.tag === tag ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'}`}
                        onClick={() => {
                          setFilter('tag', tag);
                          setIsTagDropdownOpen(false);
                        }}
                      >
                        {tag}
                      </button>
                    ))
                  ) : (
                    <div className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400 italic">
                      No tags available
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          <span className="text-sm text-gray-600 dark:text-gray-400">
            {typeof total === 'number'
              ? `${total.toLocaleString()} file${total !== 1 ? 's' : ''} found`
              : 'Counting files...'}
          </span>
        </div>
      </div>

      {/* Headers */}
      <div className="flex border-b dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        {isTriageMode && <CheckHeaderCell />}
        <SortableHeader
          column="agent_id"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-32"
        >
          Agent ID
        </SortableHeader>
        <SortableHeader
          column="source"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-40"
        >
          Source
        </SortableHeader>
        <SortableHeader
          column="size"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-24"
        >
          Size
        </SortableHeader>
        <SortableHeader
          column="timestamp"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-44"
        >
          Time Uploaded
        </SortableHeader>
        <SortableHeader
          column="magic_type"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-48"
        >
          Magic Type
        </SortableHeader>
        <SortableHeader
          column="findings"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-12 justify-center"
        >
          Findings
        </SortableHeader>
        <SortableHeader
          column="path"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-grow px-4"
        >
          Path
        </SortableHeader>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2 m-4">
          <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
          <div className="flex flex-col">
            <span className="text-red-600 dark:text-red-400">Error loading files: {error}</span>
            <span className="text-sm text-red-500 dark:text-red-400">Check browser console for details</span>
          </div>
        </div>
      )}

      {/* Loading state */}
      {isLoading && files.length === 0 && (
        <div className="flex justify-center items-center h-32">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
        </div>
      )}

      {/* No results state */}
      {!isLoading && !isFetching && !error && files.length === 0 && (
        <div className="flex flex-col items-center justify-center p-12 text-center">
          <div className="text-gray-500 dark:text-gray-400 mb-6">
            {hasActiveFilters ? (
              <>
                <Search className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium mb-2">No matching files found</h3>
                <p className="max-w-md mx-auto">
                  No files match your current filters.
                </p>
              </>
            ) : (
              <>
                <AlertTriangle className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium mb-2">No files found</h3>
                <p className="max-w-md mx-auto mb-4">
                  No files have been ingested into Nemesis yet.
                </p>
                <div>
                  <Link
                    to="/upload"
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors inline-flex items-center"
                  >
                    <span className="mr-2">Upload Files</span>
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-upload">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                      <polyline points="17 8 12 3 7 8" />
                      <line x1="12" y1="3" x2="12" y2="15" />
                    </svg>
                  </Link>
                </div>
              </>
            )}
          </div>
          {hasActiveFilters && (
            <Link
              to="/files?view_state=all"
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors inline-flex items-center"
            >
              <span>Show All Files</span>
            </Link>
          )}
        </div>
      )}

      {/* Current page of files */}
      {!error && files.length > 0 && (
        <div
          ref={containerRef}
          className={`${list.keyboardNav ? 'kbd-nav ' : ''}flex-1 min-h-0 overflow-auto transition-opacity ${isFetching && nav.current.loading ? 'opacity-60' : ''}`}
        >
          <div className="min-w-full">
            {files.map((file, index) => (
              <Row
                key={file.object_id}
                file={file}
                index={index}
                isTriageMode={isTriageMode}
                isSelected={isTriageMode && index === selectedIndex && rowsPage === page}
                isChecked={isTriageMode && (allSelected || selectedFiles.has(file.object_id))}
                onRowClick={handleRowClick}
                username={username}
              />
            ))}
          </div>
        </div>
      )}

      {typeof total === 'number' && total > 0 && (
        <PaginationControls
          currentPage={Math.min(page, totalPages)}
          totalPages={totalPages}
          totalCount={total}
          pageSize={PAGE_SIZE}
          onPageChange={(p) => {
            if (p >= 1 && p <= totalPages) list.goToPage(p);
          }}
        />
      )}
    </div>
  );
};

export default FileList;
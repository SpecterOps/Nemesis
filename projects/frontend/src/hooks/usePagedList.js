import { useTriageMode } from '@/contexts/TriageModeContext';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { jumpSelection, pageJumpRows, scrollListByPage, scrollRowIntoView } from './pagedList';
import { useChangeSignal } from './useChangeSignal';

/**
 * State and keyboard navigation for a server-paginated list (Files, Findings).
 *
 * - Fetches only the current page (+ the filtered total when filters change or data changed).
 * - Live updates come from small change-signal subscriptions that trigger a debounced refetch.
 * - Selection (triage mode) is a row index within the current page, kept per list in the
 *   TriageMode context and re-anchored by row id whenever the rows change.
 * - All keyboard handlers read/write `nav.current` synchronously, so rapid key repeats act on
 *   what is on screen even before React re-renders.
 *
 * @param {object} opts
 * @param {string} opts.listKey      TriageMode context key ('files' | 'findings')
 * @param {number} opts.pageSize
 * @param {number} opts.rowHeight    fixed row height in px
 * @param {number} opts.page         1-based page from the URL
 * @param {(page:number)=>void} opts.setPage  writes the page to the URL
 *
 * The page actually shown is local state: router location updates are transitions that can lag
 * behind (or be starved by) rapid key repeats, so the URL only mirrors it. External URL changes
 * (Back/Forward, links, filter changes resetting the page) are adopted.
 * @param {string} opts.queryKey     changes whenever filters/sort change
 * @param {(args)=>Promise<{rows, total}>} opts.fetcher  ({offset, limit, knownTotal, withCount, signal})
 * @param {(row)=>any} opts.getId
 * @param {(rows, fetchStartedAt:number)=>{rows, dropped:number}} [opts.transformRows] applies optimistic edits
 * @param {string[]} opts.signalQueries  change-signal subscriptions
 */
export const usePagedList = ({
  listKey, pageSize, rowHeight, page: urlPage, setPage: setUrlPage, queryKey, fetcher, getId, transformRows, signalQueries,
}) => {
  const [page, setPageState] = useState(urlPage);
  const { isTriageMode, setIsTriageMode, selectedIndex, setSelectedIndex } = useTriageMode(listKey);
  const [rows, setRowsState] = useState([]);
  const [rowsPage, setRowsPage] = useState(null); // page the displayed rows belong to
  const [total, setTotalState] = useState(null);
  const [isLoading, setIsLoading] = useState(true); // no rows for the current filters yet
  const [isFetching, setIsFetching] = useState(false); // any request in flight
  const [error, setError] = useState(null);
  const [checked, setCheckedState] = useState(() => new Set()); // multi-selection (triage mode only)
  // Every result of the current filters is selected (second Ctrl+A); spans all pages, ids aren't loaded
  const [allSelected, setAllSelectedState] = useState(false);
  const [refetchTick, setRefetchTick] = useState(0);
  const containerRef = useRef(null);

  // Synchronous view of the navigation state (target page/index may run ahead of the render)
  const nav = useRef({
    page, index: selectedIndex, rows: [], rowsPage: null, total: null, loading: true,
    selectedId: undefined, checked: new Set(), allSelected: false, triage: isTriageMode, pendingScroll: null,
  });
  nav.current.triage = isTriageMode;

  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  const transformRef = useRef(transformRows);
  transformRef.current = transformRows;
  const getIdRef = useRef(getId);
  getIdRef.current = getId;
  const countKeyRef = useRef(null); // queryKey the current total belongs to
  const lastTickRef = useRef(refetchTick);
  const requestRef = useRef(0);

  const setTotal = useCallback((t) => { nav.current.total = t; setTotalState(t); }, []);

  const select = useCallback((index) => {
    const n = nav.current;
    n.index = index;
    n.selectedId = index >= 0 && n.rowsPage === n.page ? (n.rows[index] ? getIdRef.current(n.rows[index]) : undefined) : n.selectedId;
    setSelectedIndex(index);
  }, [setSelectedIndex]);

  const setAllSelected = useCallback((value) => {
    nav.current.allSelected = value;
    setAllSelectedState(value);
  }, []);

  // Any explicit change to the multi-selection drops "all results selected"
  const setChecked = useCallback((next) => {
    nav.current.checked = next;
    setCheckedState(next);
    if (nav.current.allSelected) setAllSelected(false);
  }, [setAllSelected]);

  const clearSelection = useCallback(() => {
    if (nav.current.checked.size) setChecked(new Set());
    else if (nav.current.allSelected) setAllSelected(false);
  }, [setAllSelected, setChecked]);

  // Ctrl+A: the first press selects the rows on this page, the next selects every result
  const selectAllKey = useCallback(() => {
    const n = nav.current;
    if (n.loading || n.rows.length === 0 || n.allSelected) return;
    const pageIds = n.rows.map((r) => getIdRef.current(r));
    if (pageIds.every((id) => n.checked.has(id))) setAllSelected(true);
    else setChecked(new Set(pageIds));
  }, [setAllSelected, setChecked]);

  const setPage = useCallback((p) => {
    nav.current.page = p;
    setPageState(p);
    setUrlPage(p);
  }, [setUrlPage]);

  // Adopt page changes that come from the URL (Back/Forward, links, filters resetting the page),
  // but not our own writes that the router hasn't caught up with yet
  useEffect(() => {
    const actual = parseInt(new URLSearchParams(window.location.search).get('page') || '1', 10) || 1;
    if (urlPage === actual && urlPage !== nav.current.page) {
      nav.current.page = urlPage;
      setPageState(urlPage);
    }
  }, [urlPage]);

  // Raw results of the current page's neighbours (and pages already seen) for the current filters
  // and data version, so keyboard navigation across a page boundary doesn't wait for the network.
  const cacheRef = useRef({ key: null, pages: new Map() });
  const cacheKey = `${queryKey}#${refetchTick}`;
  const invalidateCache = useCallback(() => { cacheRef.current = { key: null, pages: new Map() }; }, []);

  // Replace the displayed rows (optimistic edits); keeps the selection on the same row id,
  // or on the row that took the selected row's place when it was removed.
  const updateRows = useCallback((fn, { totalDelta = 0 } = {}) => {
    const n = nav.current;
    const next = fn(n.rows);
    // Rows removed from this page shift the neighbouring pages
    if (next.length !== n.rows.length) invalidateCache();
    n.rows = next;
    setRowsState(next);
    if (totalDelta && typeof n.total === 'number') setTotal(Math.max(0, n.total + totalDelta));
    if (n.index >= 0 && n.rowsPage === n.page) {
      const byId = n.selectedId === undefined ? -1 : next.findIndex((r) => getIdRef.current(r) === n.selectedId);
      const idx = byId >= 0 ? byId : Math.min(n.index, next.length - 1);
      select(next.length === 0 ? 0 : idx);
    }
  }, [invalidateCache, select, setTotal]);

  const refetch = useCallback(() => setRefetchTick((t) => t + 1), []);

  // Keyboard actions that arrive while a page is loading are replayed in order once it shows,
  // so fast typing across a page boundary neither drops keys nor acts on the wrong rows
  const queueRef = useRef([]);
  const run = useCallback((fn) => {
    if (!nav.current.loading) fn();
    else if (queueRef.current.length < 500) queueRef.current.push(fn);
  }, []);
  const flushQueue = () => {
    const q = queueRef.current;
    while (q.length && !nav.current.loading) q.shift()();
  };
  useChangeSignal(signalQueries, refetch);

  // Show a fetched page: apply optimistic edits, re-anchor the selection
  const showPage = (p, fetched, fetchedTotal, startedAt) => {
    const n = nav.current;
    let newTotal = typeof fetchedTotal === 'number' ? fetchedTotal : n.total;
    let shown = fetched;
    if (transformRef.current) {
      const t = transformRef.current(fetched, startedAt);
      shown = t.rows;
      if (t.dropped && typeof newTotal === 'number') newTotal = Math.max(0, newTotal - t.dropped);
    }
    countKeyRef.current = queryKey;
    setTotal(newTotal);

    // Page beyond the end (rows were removed): go to the last page
    const lastPage = Math.max(1, Math.ceil((newTotal || 0) / pageSize));
    if (p > lastPage) {
      n.pendingIndex = n.pendingIndex ?? 'last';
      setPage(lastPage);
      return false;
    }

    const samePage = n.rowsPage === p;
    n.rows = shown;
    n.rowsPage = p;
    n.loading = false;
    setRowsState(shown);
    setRowsPage(p);

    if (n.triage || n.index >= 0) {
      let idx;
      if (n.pendingIndex !== undefined && n.pendingIndex !== null) {
        idx = n.pendingIndex === 'last' ? shown.length - 1 : n.pendingIndex;
      } else {
        const byId = samePage && n.selectedId !== undefined ? shown.findIndex((r) => getIdRef.current(r) === n.selectedId) : -1;
        idx = byId >= 0 ? byId : Math.max(0, n.index);
      }
      idx = Math.max(0, Math.min(idx, shown.length - 1));
      select(shown.length ? idx : -1);
    }
    n.pendingIndex = undefined;
    setError(null);
    setIsLoading(false);
    return true;
  };

  // Prefetch the neighbouring pages into the cache (page queries only, no count)
  const prefetchNeighbours = (p, total) => {
    const lastPage = Math.max(1, Math.ceil((total || 0) / pageSize));
    const key = cacheRef.current.key;
    [p + 1, p - 1].forEach((q) => {
      if (q < 1 || q > lastPage || cacheRef.current.pages.has(q)) return;
      const startedAt = Date.now();
      cacheRef.current.pages.set(q, null); // in flight
      fetcherRef.current({ offset: (q - 1) * pageSize, limit: pageSize, knownTotal: total, withCount: false })
        .then(({ rows: fetched }) => {
          if (cacheRef.current.key === key) cacheRef.current.pages.set(q, { rows: fetched, startedAt });
        })
        .catch(() => { if (cacheRef.current.key === key) cacheRef.current.pages.delete(q); });
    });
  };

  // Fetch the current page (and the total when filters changed or data changed)
  useEffect(() => {
    const n = nav.current;
    const filtersChanged = countKeyRef.current !== queryKey;
    const signalled = lastTickRef.current !== refetchTick;
    lastTickRef.current = refetchTick;
    if (cacheRef.current.key !== cacheKey) cacheRef.current = { key: cacheKey, pages: new Map() };
    n.page = page;
    if (filtersChanged) {
      setIsLoading(true);
      n.loading = true;
    }
    if (n.rowsPage !== page) n.loading = true;

    // A neighbouring page we already have for these filters and this data version
    const cached = !filtersChanged && !signalled && typeof n.total === 'number' ? cacheRef.current.pages.get(page) : null;
    if (cached) {
      requestRef.current++;
      if (showPage(page, cached.rows, undefined, cached.startedAt)) {
        setIsFetching(false);
        prefetchNeighbours(page, n.total);
        flushQueue();
      }
      return undefined;
    }

    const withCount = filtersChanged || signalled || typeof n.total !== 'number';
    const controller = new AbortController();
    const requestId = ++requestRef.current;
    const startedAt = Date.now();
    setIsFetching(true);

    fetcherRef.current({
      offset: (page - 1) * pageSize,
      limit: pageSize,
      knownTotal: filtersChanged ? undefined : n.total,
      withCount,
      signal: controller.signal,
    }).then(({ rows: fetched, total: fetchedTotal }) => {
      if (requestId !== requestRef.current) return;
      if (cacheRef.current.key === cacheKey) cacheRef.current.pages.set(page, { rows: fetched, startedAt });
      if (showPage(page, fetched, fetchedTotal, startedAt)) {
        setIsFetching(false);
        prefetchNeighbours(page, n.total);
        flushQueue();
      }
    }).catch((err) => {
      if (controller.signal.aborted || requestId !== requestRef.current) return;
      console.error(`Error fetching ${listKey}:`, err);
      setError(err.message);
      queueRef.current = [];
      n.loading = false;
      setIsLoading(false);
      setIsFetching(false);
    });

    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queryKey, page, refetchTick]);

  // Go to another page; `index` = row to select there ('last' for the last row), `scroll` =
  // where to put the (non-triage) scroll position once it renders.
  const goToPage = useCallback((p, { index, scroll = 'top' } = {}) => {
    const n = nav.current;
    if (p === n.page && n.rowsPage === p) {
      if (index !== undefined) select(index === 'last' ? n.rows.length - 1 : index);
      return;
    }
    n.page = p;
    n.loading = true;
    n.pendingIndex = index !== undefined ? index : (n.triage ? 0 : undefined);
    if (n.pendingIndex !== undefined) {
      n.index = n.pendingIndex === 'last' ? pageSize - 1 : n.pendingIndex;
      n.selectedId = undefined;
    }
    n.pendingScroll = scroll;
    // A page-level selection doesn't carry over to another page; "all results" does
    if (n.checked.size && !n.allSelected) setChecked(new Set());
    setPage(p);
  }, [pageSize, select, setChecked, setPage]);

  // Move the triage selection by `delta` rows across page boundaries (clamped at both ends)
  const moveSelection = useCallback((delta) => {
    const n = nav.current;
    if (typeof n.total !== 'number' || n.total === 0) return;
    const { page: p, index } = jumpSelection({ page: n.page, index: n.index, step: delta, total: n.total, pageSize });
    if (p === n.page) {
      if (n.loading) {
        n.pendingIndex = index;
        n.index = index;
        setSelectedIndex(index);
      } else {
        select(Math.min(index, n.rows.length - 1));
      }
    } else {
      goToPage(p, { index });
    }
  }, [goToPage, pageSize, select, setSelectedIndex]);

  // PageUp / PageDown in either mode
  const pageKey = useCallback((direction) => {
    const n = nav.current;
    const container = containerRef.current;
    if (n.triage) {
      moveSelection(direction * pageJumpRows(container, rowHeight));
      return;
    }
    if (n.loading) return;
    const result = scrollListByPage(container, direction);
    const lastPage = Math.max(1, Math.ceil((n.total || 0) / pageSize));
    if (result === 'next' && n.page < lastPage) goToPage(n.page + 1, { scroll: 'top', index: n.index >= 0 ? 0 : undefined });
    if (result === 'prev' && n.page > 1) goToPage(n.page - 1, { scroll: 'bottom', index: n.index >= 0 ? 'last' : undefined });
  }, [goToPage, moveSelection, pageSize, rowHeight]);

  // Shift+Up/Down: extend the multi-selection within the page
  const extendSelection = useCallback((delta) => {
    const n = nav.current;
    if (n.loading || n.index < 0 || !n.rows.length) return;
    const next = Math.max(0, Math.min(n.rows.length - 1, n.index + delta));
    const set = new Set(n.checked);
    set.add(getIdRef.current(n.rows[n.index]));
    set.add(getIdRef.current(n.rows[next]));
    setChecked(set);
    select(next);
  }, [select, setChecked]);

  // The row the keyboard acts on, or null while a page change is still loading
  const currentRow = useCallback(() => {
    const n = nav.current;
    if (n.loading || n.rowsPage !== n.page || n.index < 0) return null;
    return n.rows[n.index] || null;
  }, []);

  // Multi-selection only exists in triage mode
  useEffect(() => {
    if (!isTriageMode) clearSelection();
  }, [isTriageMode, clearSelection]);

  // A selection belongs to the results it was made on: new filters/sort start with none
  const selectionKeyRef = useRef(queryKey);
  useEffect(() => {
    if (selectionKeyRef.current === queryKey) return;
    selectionKeyRef.current = queryKey;
    clearSelection();
  }, [queryKey, clearSelection]);

  // Keyboard vs mouse in triage mode: a key press suppresses the rows' hover highlight (rows
  // scroll under a still pointer while navigating); a real mouse move brings it back. Chrome sends
  // synthetic mousemoves with an unchanged position after scrolling, so compare coordinates.
  const [keyboardNav, setKeyboardNav] = useState(false);
  const keyboardNavRef = useRef(false);
  useEffect(() => {
    const set = (v) => {
      if (keyboardNavRef.current === v) return;
      keyboardNavRef.current = v;
      setKeyboardNav(v);
    };
    if (!isTriageMode) {
      set(false);
      return undefined;
    }
    let last = null;
    const onKeyDown = (e) => {
      if (!e.repeat || !keyboardNavRef.current) set(true);
    };
    const onMouseMove = (e) => {
      const moved = last !== null && (e.clientX !== last.x || e.clientY !== last.y);
      last = { x: e.clientX, y: e.clientY };
      if (moved) set(false);
    };
    window.addEventListener('keydown', onKeyDown, true);
    window.addEventListener('mousemove', onMouseMove, true);
    return () => {
      window.removeEventListener('keydown', onKeyDown, true);
      window.removeEventListener('mousemove', onMouseMove, true);
    };
  }, [isTriageMode]);

  // Keep the selected row fully visible; apply a pending scroll position after a page change
  useLayoutEffect(() => {
    const n = nav.current;
    const container = containerRef.current;
    if (!container || n.loading) return;
    if (n.pendingScroll) {
      container.scrollTop = n.pendingScroll === 'bottom' ? container.scrollHeight : 0;
      n.pendingScroll = null;
    }
    if (isTriageMode && selectedIndex >= 0) scrollRowIntoView(container, selectedIndex, rowHeight);
  }, [selectedIndex, isTriageMode, rows, rowHeight]);

  const totalPages = Math.max(1, Math.ceil((total || 0) / pageSize));

  return {
    page, rows, rowsPage, total, totalPages, isLoading, isFetching, error, containerRef, nav,
    isTriageMode, setIsTriageMode, selectedIndex, select, checked, setChecked,
    allSelected, selectAllKey, clearSelection, keyboardNav,
    updateRows, refetch, run, goToPage, moveSelection, pageKey, extendSelection, currentRow,
  };
};

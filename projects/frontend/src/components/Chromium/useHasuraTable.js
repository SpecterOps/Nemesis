import { useEffect, useRef, useState } from 'react';

// Shared data helpers for the large Chromium / DPAPI tables. These tables can hold
// millions of rows, so everything here is server-side: filtered/sorted/paginated in
// Postgres via Hasura, with stale responses discarded and exports streamed in chunks.

const FILTER_DEBOUNCE_MS = 300;
const EXPORT_CHUNK_SIZE = 10000;

export async function hasuraQuery(query, variables, signal) {
  const response = await fetch('/hasura/v1/graphql', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query, variables }),
    signal,
  });
  if (!response.ok) {
    throw new Error(`Network response error: ${response.status}`);
  }
  const result = await response.json();
  if (result.errors) {
    throw new Error(result.errors[0].message);
  }
  return result.data;
}

// Returns `value` once it has stopped changing for `delay` ms (empty values apply immediately
// so clearing a filter feels instant).
export function useDebouncedValue(value, delay = FILTER_DEBOUNCE_MS) {
  const [debounced, setDebounced] = useState(value);
  const isEmpty = value === '' || value === null || value === undefined;
  // Empty values apply immediately: adjust the state during render instead of in the effect
  if (isEmpty && debounced !== value) setDebounced(value);
  useEffect(() => {
    if (isEmpty) return undefined;
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay, isEmpty]);
  return debounced;
}

// Build a deterministic order_by: the user's sort column plus the primary key as a tiebreaker
// (same direction, so a (column, id) btree index can serve it), which keeps offset paging stable
// when the sort column has many duplicate values.
export function buildStableOrderBy(sortColumn, sortDirection, tiebreaker = 'id') {
  const orderBy = [{ [sortColumn]: sortDirection }];
  if (tiebreaker && sortColumn !== tiebreaker) {
    orderBy.push({ [tiebreaker]: sortDirection });
  }
  return orderBy;
}

/**
 * Fetch one page of `table` plus its total count in a single round-trip.
 * If the filtered total is <= `threshold` the whole (bounded) set is loaded instead so the
 * caller can show it in a virtualized list; otherwise only `pageSize` rows are loaded.
 * The count is only re-queried when the filter changes (not on page/sort changes).
 */
export function useHasuraTable({ table, fields, where, orderBy, currentPage, pageSize, threshold = 0 }) {
  const [state, setState] = useState({ records: [], totalCount: 0, isPaginated: false, isLoading: true, error: null });
  const countCache = useRef({ key: null, count: 0 });

  const whereKey = JSON.stringify(where);
  const orderKey = JSON.stringify(orderBy);

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- show loading as this effect starts its request
    setState((s) => ({ ...s, isLoading: true, error: null }));

    const run = async () => {
      const needCount = countCache.current.key !== whereKey;
      const knownCount = needCount ? null : countCache.current.count;
      // If we already know the set is small, load it whole in one request.
      const loadAll = knownCount !== null && knownCount <= threshold;
      const limit = loadAll ? threshold : pageSize;
      const offset = loadAll ? 0 : (currentPage - 1) * pageSize;

      const query = `
        query PagedTable($where: ${table}_bool_exp, $order_by: [${table}_order_by!], $limit: Int!, $offset: Int!) {
          rows: ${table}(where: $where, order_by: $order_by, limit: $limit, offset: $offset) {
            ${fields}
          }
          ${needCount ? `agg: ${table}_aggregate(where: $where) { aggregate { count } }` : ''}
        }
      `;
      const data = await hasuraQuery(query, { where, order_by: orderBy, limit, offset }, controller.signal);
      let rows = data.rows;
      const count = needCount ? data.agg.aggregate.count : knownCount;
      if (needCount) {
        countCache.current = { key: whereKey, count };
      }

      const paginated = count > threshold;
      if (!paginated && !loadAll && count > rows.length) {
        // Small result set: fetch it whole for the virtualized view.
        const all = await hasuraQuery(
          `query AllRows($where: ${table}_bool_exp, $order_by: [${table}_order_by!], $limit: Int!) {
            rows: ${table}(where: $where, order_by: $order_by, limit: $limit) { ${fields} }
          }`,
          { where, order_by: orderBy, limit: threshold },
          controller.signal
        );
        rows = all.rows;
      }
      if (!cancelled) {
        setState({ records: rows, totalCount: count, isPaginated: paginated, isLoading: false, error: null });
      }
    };

    run().catch((err) => {
      if (cancelled || err.name === 'AbortError') return;
      console.error(`Error fetching ${table}:`, err);
      // Force a recount next time in case the failure was in the count.
      countCache.current = { key: null, count: 0 };
      setState((s) => ({ ...s, isLoading: false, error: err.message }));
    });

    return () => {
      cancelled = true;
      controller.abort();
    };
    // where/orderBy are new objects every render; their JSON keys stand in for them
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [table, fields, whereKey, orderKey, currentPage, pageSize, threshold]);

  return state;
}

const csvEscape = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
export { csvEscape };

/**
 * Export every row matching `where` to a CSV download, fetching EXPORT_CHUNK_SIZE rows at a
 * time so the browser never holds one giant GraphQL response or one giant string.
 * `toCsvRow(record)` returns an array of already-formatted cell strings.
 * Returns the number of exported rows.
 */
export async function exportHasuraTableToCsv({ table, fields, where, orderBy, headers, toCsvRow, filename, onProgress }) {
  const parts = [headers.join(',') + '\n'];
  let offset = 0;
  let total = 0;
  for (;;) {
    const data = await hasuraQuery(
      `query ExportChunk($where: ${table}_bool_exp, $order_by: [${table}_order_by!], $limit: Int!, $offset: Int!) {
        rows: ${table}(where: $where, order_by: $order_by, limit: $limit, offset: $offset) { ${fields} }
      }`,
      { where, order_by: orderBy, limit: EXPORT_CHUNK_SIZE, offset }
    );
    const rows = data.rows;
    if (rows.length > 0) {
      parts.push(rows.map((r) => toCsvRow(r).join(',')).join('\n') + '\n');
    }
    total += rows.length;
    offset += rows.length;
    if (onProgress) onProgress(total);
    if (rows.length < EXPORT_CHUNK_SIZE) break;
  }

  if (total === 0) {
    return 0;
  }

  const blob = new Blob(parts, { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  return total;
}

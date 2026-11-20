// Shared helpers for the server-paginated Files / Findings lists: Hasura paging and keyboard
// paging (PageUp / PageDown) math.

export const hasuraRequest = async (query, variables, signal) => {
  const response = await fetch('/hasura/v1/graphql', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
    },
    body: JSON.stringify({ query, variables }),
    signal,
  });
  if (!response.ok) throw new Error(`Network response error: ${response.status}`);
  const result = await response.json();
  if (result.errors) throw new Error(result.errors[0].message);
  return result.data;
};

const REVERSED = {
  asc: 'desc',
  desc: 'asc',
  asc_nulls_first: 'desc_nulls_last',
  desc_nulls_last: 'asc_nulls_first',
  asc_nulls_last: 'desc_nulls_first',
  desc_nulls_first: 'asc_nulls_last',
};

// Exact reverse of a Hasura order_by (including nulls placement)
export const reverseOrderBy = (orderBy) => {
  if (Array.isArray(orderBy)) return orderBy.map(reverseOrderBy);
  if (typeof orderBy === 'string') return REVERSED[orderBy] || orderBy;
  return Object.fromEntries(Object.entries(orderBy).map(([k, v]) => [k, reverseOrderBy(v)]));
};

/**
 * Fetch one page of `table` (and optionally its filtered total). Pages in the back half of a
 * known total are read with the order reversed from the end, so the last page of a million rows
 * costs the same as the first instead of skipping ~1M rows.
 *
 * @param {object} args
 * @param {string} args.table
 * @param {string} args.fields
 * @param {object} args.where
 * @param {any} args.orderBy
 * @param {number} args.offset
 * @param {number} args.limit
 * @param {number} [args.knownTotal]
 * @param {boolean} [args.withCount]
 * @param {string} [args.varDefs]
 * @param {object} [args.vars]
 * @param {AbortSignal} [args.signal]
 * @returns {Promise<{rows: any[], total: number | undefined}>}
 */
export const fetchPage = async ({
  table, fields, where, orderBy, offset, limit, knownTotal, withCount, varDefs = '', vars = {}, signal,
}) => {
  let reverse = false;
  let qOffset = offset;
  let qLimit = limit;
  if (typeof knownTotal === 'number' && offset > knownTotal / 2 && offset < knownTotal) {
    reverse = true;
    const end = Math.min(offset + limit, knownTotal);
    qOffset = knownTotal - end;
    qLimit = end - offset;
  }
  const query = `
    query PagedList($where: ${table}_bool_exp!, $order_by: [${table}_order_by!], $limit: Int!, $offset: Int!${varDefs}) {
      ${withCount ? `total: ${table}_aggregate(where: $where) { aggregate { count } }` : ''}
      rows: ${table}(where: $where, order_by: $order_by, limit: $limit, offset: $offset) { ${fields} }
    }`;
  const data = await hasuraRequest(
    query,
    { where, order_by: reverse ? reverseOrderBy(orderBy) : orderBy, limit: qLimit, offset: qOffset, ...vars },
    signal,
  );
  const rows = reverse ? [...data.rows].reverse() : data.rows;
  return { rows, total: withCount ? data.total.aggregate.count : undefined };
};

// Keyboard shortcuts shouldn't fire while typing
export const isEditableTarget = (target) =>
  !!target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT' || !!target.isContentEditable);

// Triage-mode row highlight: checked rows get the filled background, the active (keyboard
// cursor) row an inset ring (no layout change) plus a light background only when not checked
export const triageRowClasses = (isTriageMode, isChecked, isActive) => {
  if (!isTriageMode) return '';
  const bg = isChecked ? '!bg-blue-100 dark:!bg-blue-900/30' : isActive ? '!bg-blue-50 dark:!bg-blue-900/20' : '';
  const ring = isActive ? 'ring-2 ring-inset ring-blue-600 dark:ring-blue-400' : '';
  return `${bg} ${ring}`;
};

// Rows a PageUp/PageDown moves the selection: floor(0.75 x fully visible rows), at least 1
export const pageJumpRows = (container, rowHeight) => {
  const visible = container ? Math.floor(container.clientHeight / rowHeight) : 10;
  return Math.max(1, Math.floor(0.75 * visible));
};

// Scroll a fixed-row-height list container just enough to show row `index` completely
export const scrollRowIntoView = (container, index, rowHeight) => {
  if (!container || index < 0) return;
  const rowTop = index * rowHeight;
  if (rowTop < container.scrollTop) {
    container.scrollTop = rowTop;
  } else if (rowTop + rowHeight > container.scrollTop + container.clientHeight) {
    container.scrollTop = rowTop + rowHeight - container.clientHeight;
  }
};

/**
 * Non-triage PageUp/PageDown: scroll the list by 3/4 of its visible height. Returns 'next' /
 * 'prev' when the list is already at its bottom / top, so the caller can move to the adjacent page.
 */
export const scrollListByPage = (container, direction) => {
  if (!container) return direction > 0 ? 'next' : 'prev';
  const maxScroll = container.scrollHeight - container.clientHeight;
  if (direction > 0 && container.scrollTop >= maxScroll - 2) return 'next';
  if (direction < 0 && container.scrollTop <= 2) return 'prev';
  const delta = Math.max(1, Math.floor(container.clientHeight * 0.75));
  container.scrollTop = Math.min(maxScroll, Math.max(0, container.scrollTop + direction * delta));
  return 'scrolled';
};

/**
 * Triage-mode PageUp/PageDown: move an absolute selection by `step` rows, clamped to
 * [0, total - 1], and split it into page (1-based) and row-in-page.
 */
export const jumpSelection = ({ page, index, step, total, pageSize }) => {
  const current = (page - 1) * pageSize + Math.max(0, index);
  const target = Math.min(Math.max(0, current + step), Math.max(0, total - 1));
  return { page: Math.floor(target / pageSize) + 1, index: target % pageSize };
};

// Visit every id matching `where` in `idField` order, `chunkSize` ids at a time (keyset paging,
// so rows that stop matching once a chunk is processed don't shift later chunks). Calls
// `onChunk(ids)` and awaits it before fetching the next chunk; resolves to the number of ids.
/**
 * @param {object} args
 * @param {string} args.table
 * @param {string} args.idField
 * @param {object} args.where
 * @param {number} [args.chunkSize]
 * @param {(ids: any[]) => Promise<unknown>} args.onChunk
 * @param {AbortSignal} [args.signal]
 * @returns {Promise<number>}
 */
export const forEachIdChunk = async ({ table, idField, where, chunkSize = 2000, onChunk, signal }) => {
  let last = null;
  let done = 0;
  for (;;) {
    const chunkWhere = last === null ? where : { _and: [where, { [idField]: { _gt: last } }] };
    const data = await hasuraRequest(
      `query ChunkIds($where: ${table}_bool_exp!, $limit: Int!) {
        ${table}(where: $where, order_by: { ${idField}: asc }, limit: $limit) { ${idField} }
      }`,
      { where: chunkWhere, limit: chunkSize },
      signal,
    );
    const ids = data[table].map((r) => r[idField]);
    if (ids.length === 0) return done;
    await onChunk(ids);
    done += ids.length;
    last = ids[ids.length - 1];
    if (ids.length < chunkSize) return done;
  }
};

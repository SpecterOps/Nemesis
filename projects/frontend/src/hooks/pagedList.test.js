// Unit tests for the list paging helpers and the Files/Findings query builders.
// Run with: node --test src/hooks/pagedList.test.js   (no browser, no network)
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildFilesOrderBy, buildFilesWhere, wildcardToIlike } from '../components/FileList/fileQuery.js';
import {
  ALL_CATEGORIES, ALL_SEVERITIES, buildFindingsOrderBy, buildFindingsWhere, escapeLike, matchesAfterHumanTriage,
} from '../components/Findings/findingsQuery.js';
import {
  fetchPage, forEachIdChunk, isEditableTarget, jumpSelection, pageJumpRows, reverseOrderBy, scrollListByPage, scrollRowIntoView,
  triageRowClasses,
} from './pagedList.js';

// The tests stub the browser globals that hasuraRequest uses
const g = /** @type {any} */ (globalThis);

const defaults = {
  categories: ALL_CATEGORIES, severities: ALL_SEVERITIES, search: '', triageState: 'all', triageSource: 'all', objectId: '',
};

test('reverseOrderBy flips direction and nulls placement, recursively', () => {
  assert.deepEqual(
    reverseOrderBy([{ files_enriched: { path: 'asc' } }, { triage_value: 'asc_nulls_first' }, { finding_id: 'desc' }]),
    [{ files_enriched: { path: 'desc' } }, { triage_value: 'desc_nulls_last' }, { finding_id: 'asc' }],
  );
  assert.deepEqual(reverseOrderBy({ x: 'desc_nulls_first' }), { x: 'asc_nulls_last' });
});

test('jumpSelection moves across pages and clamps at both ends', () => {
  assert.deepEqual(jumpSelection({ page: 1, index: 98, step: 8, total: 1000, pageSize: 100 }), { page: 2, index: 6 });
  assert.deepEqual(jumpSelection({ page: 2, index: 6, step: -8, total: 1000, pageSize: 100 }), { page: 1, index: 98 });
  assert.deepEqual(jumpSelection({ page: 1, index: 3, step: -8, total: 1000, pageSize: 100 }), { page: 1, index: 0 });
  assert.deepEqual(jumpSelection({ page: 10, index: 95, step: 8, total: 1000, pageSize: 100 }), { page: 10, index: 99 });
  assert.deepEqual(jumpSelection({ page: 1, index: 0, step: 5, total: 3, pageSize: 100 }), { page: 1, index: 2 });
  // no selection yet counts as row 0
  assert.deepEqual(jumpSelection({ page: 1, index: -1, step: 1, total: 10, pageSize: 100 }), { page: 1, index: 1 });
});

test('pageJumpRows is floor(0.75 x fully visible rows), at least 1', () => {
  assert.equal(pageJumpRows({ clientHeight: 572 }, 48), 8); // 11 rows visible
  assert.equal(pageJumpRows({ clientHeight: 40 }, 48), 1);
  assert.equal(pageJumpRows(null, 48), 7);
});

test('scrollListByPage scrolls 3/4 of the height, reports page edges', () => {
  const c = { scrollTop: 0, clientHeight: 400, scrollHeight: 1000 };
  assert.equal(scrollListByPage(c, 1), 'scrolled');
  assert.equal(c.scrollTop, 300);
  assert.equal(scrollListByPage(c, 1), 'scrolled');
  assert.equal(c.scrollTop, 600); // clamped to max
  assert.equal(scrollListByPage(c, 1), 'next');
  c.scrollTop = 0;
  assert.equal(scrollListByPage(c, -1), 'prev');
  assert.equal(scrollListByPage(null, 1), 'next');
});

test('scrollRowIntoView only scrolls when the row is not fully visible', () => {
  const c = { scrollTop: 0, clientHeight: 100 };
  scrollRowIntoView(c, 1, 40);
  assert.equal(c.scrollTop, 0);
  scrollRowIntoView(c, 3, 40);
  assert.equal(c.scrollTop, 60);
  scrollRowIntoView(c, 0, 40);
  assert.equal(c.scrollTop, 0);
  scrollRowIntoView(null, 3, 40); // no container: no throw
});

test('isEditableTarget ignores inputs, textareas, selects and contenteditable', () => {
  assert.equal(isEditableTarget({ tagName: 'INPUT' }), true);
  assert.equal(isEditableTarget({ tagName: 'TEXTAREA' }), true);
  assert.equal(isEditableTarget({ tagName: 'SELECT' }), true);
  assert.equal(isEditableTarget({ tagName: 'DIV', isContentEditable: true }), true);
  assert.equal(isEditableTarget({ tagName: 'BODY' }), false);
  assert.equal(isEditableTarget(null), false);
  // Monaco's focused EditContext <div> sits inside .monaco-editor
  assert.equal(isEditableTarget({ tagName: 'DIV', closest: (sel) => (sel === '.monaco-editor' ? {} : null) }), true);
  assert.equal(isEditableTarget({ tagName: 'DIV', closest: () => null }), false);
});

test('fetchPage reads back-half pages in reverse order from the end', async () => {
  const calls = [];
  g.window = { ENV: { HASURA_ADMIN_SECRET: 'x' } };
  g.fetch = async (url, opts) => {
    const body = JSON.parse(opts.body);
    calls.push(body.variables);
    const rows = Array.from({ length: body.variables.limit }, (_, i) => ({ id: body.variables.offset + i }));
    return { ok: true, json: async () => ({ data: { rows, total: { aggregate: { count: 1050 } } } }) };
  };
  // last page of 1050 rows (offset 1000, 50 rows) -> reversed query at offset 0
  const last = await fetchPage({ table: 't', fields: 'id', where: {}, orderBy: [{ a: 'asc' }], offset: 1000, limit: 100, knownTotal: 1050 });
  assert.deepEqual(calls[0].order_by, [{ a: 'desc' }]);
  assert.equal(calls[0].offset, 0);
  assert.equal(calls[0].limit, 50);
  assert.deepEqual(last.rows.map((r) => r.id), Array.from({ length: 50 }, (_, i) => 49 - i));
  // first page and unknown total -> forward
  await fetchPage({ table: 't', fields: 'id', where: {}, orderBy: [{ a: 'asc' }], offset: 0, limit: 100, knownTotal: 1050, withCount: true });
  assert.deepEqual(calls[1].order_by, [{ a: 'asc' }]);
  await fetchPage({ table: 't', fields: 'id', where: {}, orderBy: [{ a: 'asc' }], offset: 900, limit: 100 });
  assert.equal(calls[2].offset, 900);
  // errors surface
  g.fetch = async () => ({ ok: true, json: async () => ({ errors: [{ message: 'boom' }] }) });
  await assert.rejects(() => fetchPage({ table: 't', fields: 'id', where: {}, orderBy: [], offset: 0, limit: 1 }), /boom/);
  g.fetch = async () => ({ ok: false, status: 500 });
  await assert.rejects(() => fetchPage({ table: 't', fields: 'id', where: {}, orderBy: [], offset: 0, limit: 1 }), /500/);
});

test('findings where: defaults are unfiltered, each filter maps to a server condition', () => {
  assert.deepEqual(buildFindingsWhere(defaults), {});
  assert.deepEqual(buildFindingsWhere({ ...defaults, categories: ['pii'] }), { category: { _in: ['pii'] } });
  assert.deepEqual(buildFindingsWhere({ ...defaults, severities: ['critical'] }), { severity: { _gte: 9 } });
  assert.deepEqual(buildFindingsWhere({ ...defaults, severities: ['low', 'informational'] }), { _or: [{ severity: { _gte: 2, _lte: 3 } }, { severity: { _lte: 1 } }] });
  const search = buildFindingsWhere({ ...defaults, search: 'C:\\a_b%' });
  assert.equal(search._or[0].finding_name._ilike, '%C:\\\\a\\_b\\%%');
  assert.deepEqual(search._or[3], { file_path: { _ilike: '%C:\\\\a\\_b\\%%' } });
  assert.deepEqual(buildFindingsWhere({ ...defaults, triageState: 'untriaged' }), { triage_id: { _is_null: true } });
  assert.deepEqual(buildFindingsWhere({ ...defaults, triageState: 'true_positive' }), { triage_value: { _eq: 'true_positive' } });
  assert.deepEqual(buildFindingsWhere({ ...defaults, triageState: 'untriaged_and_actionable' }), {
    _or: [
      { triage_id: { _is_null: true } },
      { _and: [{ triage_automated: { _eq: true } }, { triage_value: { _in: ['true_positive', 'needs_review'] } }] },
    ],
  });
  assert.deepEqual(buildFindingsWhere({ ...defaults, triageState: 'triaged', triageSource: 'human' }), {
    _and: [
      { triage_id: { _is_null: false } },
      { _and: [{ triage_id: { _is_null: false } }, { triage_automated: { _eq: false } }] },
    ],
  });
  assert.deepEqual(buildFindingsWhere({ ...defaults, triageSource: 'automated' }), { triage_automated: { _eq: true } });
  assert.deepEqual(buildFindingsWhere({ ...defaults, triageState: 'bogus', triageSource: 'bogus' }), {});
});

test('findings where: a malformed object_id matches nothing instead of erroring', () => {
  const id = '0f8fad5b-d9cb-469f-a165-70867728950e';
  assert.deepEqual(buildFindingsWhere({ ...defaults, objectId: ` ${id} ` }), { object_id: { _eq: id } });
  assert.deepEqual(buildFindingsWhere({ ...defaults, objectId: 'not-a-uuid' }), { finding_id: { _is_null: true } });
});

test('findings order_by: every sortable column, stable tie-breaker', () => {
  assert.deepEqual(buildFindingsOrderBy('severity', 'asc'), [{ severity: 'asc' }, { finding_id: 'asc' }]);
  assert.deepEqual(buildFindingsOrderBy('file_path', 'desc'), [{ file_path: 'desc' }, { finding_id: 'desc' }]);
  assert.deepEqual(buildFindingsOrderBy('triage_value', 'asc')[0], { triage_value: 'asc_nulls_first' });
  assert.deepEqual(buildFindingsOrderBy('bogus', 'sideways'), [{ created_at: 'desc' }, { finding_id: 'desc' }]);
});

test('matchesAfterHumanTriage drops rows that leave the triage filter', () => {
  assert.equal(matchesAfterHumanTriage('true_positive', 'untriaged_and_actionable', 'all'), false);
  assert.equal(matchesAfterHumanTriage('true_positive', 'all', 'all'), true);
  assert.equal(matchesAfterHumanTriage('true_positive', 'false_positive', 'all'), false);
  assert.equal(matchesAfterHumanTriage('false_positive', 'false_positive', 'all'), true);
  assert.equal(matchesAfterHumanTriage('false_positive', 'triaged', 'automated'), false);
  assert.equal(matchesAfterHumanTriage('false_positive', 'triaged', 'human'), true);
});

test('escapeLike / wildcardToIlike keep Windows paths literal', () => {
  assert.equal(escapeLike('a\\b_c%'), 'a\\\\b\\_c\\%');
  assert.equal(wildcardToIlike('C:\\Users\\*.txt'), 'C:\\\\Users\\\\%.txt');
});

test('files where: filters map to server conditions', () => {
  const base = { fileType: 'all', source: '', path: '', objectId: '', tag: '', viewState: 'all', onlyWithFindings: false, username: 'u' };
  assert.ok(buildFilesWhere(base)._or, 'base condition only');
  const w = buildFilesWhere({ ...base, path: 'dir1', tag: 't', viewState: 'unviewed_by_me', onlyWithFindings: true, fileType: 'plaintext', source: 'HOST*' });
  const conds = w._and.slice(1);
  assert.deepEqual(conds, [
    { findings_count: { _gt: 0 } },
    { is_plaintext: { _eq: true } },
    { source: { _ilike: 'HOST%' } },
    { path: { _ilike: '%dir1%' } },
    { file_tags: { _contains: ['t'] } },
    { _not: { files_view_histories: { username: { _eq: 'u' } } } },
  ]);
  assert.deepEqual(buildFilesWhere({ ...base, viewState: 'unviewed' })._and[1], { _not: { files_view_histories: {} } });
  assert.deepEqual(buildFilesWhere({ ...base, objectId: 'nope' })._and[1], { object_id: { _is_null: true } });
});

test('files order_by: every sortable column, stable tie-breaker', () => {
  assert.deepEqual(buildFilesOrderBy('findings', 'desc'), [{ findings_count: 'desc' }, { object_id: 'desc' }]);
  assert.deepEqual(buildFilesOrderBy('path', 'asc'), [{ path: 'asc' }, { object_id: 'asc' }]);
  assert.deepEqual(buildFilesOrderBy(undefined, undefined), [{ timestamp: 'desc' }, { object_id: 'desc' }]);
});

test('forEachIdChunk walks every matching id by keyset, even when rows stop matching', async () => {
  g.window = { ENV: { HASURA_ADMIN_SECRET: 'x' } };
  // 7 matching ids; processing a chunk removes those rows from the result (like triaging untriaged rows)
  let matching = [3, 5, 8, 9, 12, 15, 20];
  const wheres = [];
  g.fetch = async (url, opts) => {
    const { variables } = JSON.parse(opts.body);
    wheres.push(variables.where);
    const after = variables.where._and ? variables.where._and[1].finding_id._gt : -Infinity;
    const ids = matching.filter((id) => id > after).slice(0, variables.limit);
    return { ok: true, json: async () => ({ data: { findings: ids.map((finding_id) => ({ finding_id })) } }) };
  };
  const seen = [];
  const n = await forEachIdChunk({
    table: 'findings', idField: 'finding_id', where: { category: { _eq: 'pii' } }, chunkSize: 3,
    onChunk: async (ids) => { seen.push(ids); matching = matching.filter((id) => !ids.includes(id)); },
  });
  assert.equal(n, 7);
  assert.deepEqual(seen, [[3, 5, 8], [9, 12, 15], [20]]);
  assert.deepEqual(wheres[0], { category: { _eq: 'pii' } });
  assert.deepEqual(wheres[1], { _and: [{ category: { _eq: 'pii' } }, { finding_id: { _gt: 8 } }] });
});

test('forEachIdChunk: no matches, exact multiple of the chunk size, and errors', async () => {
  g.window = { ENV: { HASURA_ADMIN_SECRET: 'x' } };
  const all = [1, 2, 3, 4];
  let calls = 0;
  g.fetch = async (url, opts) => {
    calls++;
    const { variables } = JSON.parse(opts.body);
    const after = variables.where._and ? variables.where._and[1].id._gt : -Infinity;
    const ids = all.filter((id) => id > after).slice(0, variables.limit);
    return { ok: true, json: async () => ({ data: { t: ids.map((id) => ({ id })) } }) };
  };
  const chunks = [];
  assert.equal(await forEachIdChunk({ table: 't', idField: 'id', where: {}, chunkSize: 2, onChunk: async (ids) => chunks.push(ids) }), 4);
  assert.deepEqual(chunks, [[1, 2], [3, 4]]);
  assert.equal(calls, 3, 'a full last chunk needs one more (empty) fetch to know it is done');

  g.fetch = async () => ({ ok: true, json: async () => ({ data: { t: [] } }) });
  let called = false;
  assert.equal(await forEachIdChunk({ table: 't', idField: 'id', where: {}, onChunk: async () => { called = true; } }), 0);
  assert.equal(called, false);

  g.fetch = async () => ({ ok: false, status: 503 });
  await assert.rejects(() => forEachIdChunk({ table: 't', idField: 'id', where: {}, onChunk: async () => {} }), /503/);
  // a failing chunk action stops the walk
  g.fetch = async () => ({ ok: true, json: async () => ({ data: { t: [{ id: 1 }] } }) });
  await assert.rejects(() => forEachIdChunk({ table: 't', idField: 'id', where: {}, onChunk: async () => { throw new Error('insert failed'); } }), /insert failed/);
});

test('triageRowClasses: checked rows are filled, the active row gets a ring, never two backgrounds', () => {
  const classes = (...args) => triageRowClasses(...args).split(/\s+/).filter(Boolean);
  assert.deepEqual(classes(false, true, true), []);
  assert.deepEqual(classes(true, false, false), []);
  assert.deepEqual(classes(true, true, false), ['!bg-blue-100', 'dark:!bg-blue-900/30']);
  assert.deepEqual(classes(true, false, true), ['!bg-blue-50', 'dark:!bg-blue-900/20', 'ring-2', 'ring-inset', 'ring-blue-600', 'dark:ring-blue-400']);
  // active + checked: the checked background (not the light one) plus the ring
  const both = classes(true, true, true);
  assert.ok(both.includes('!bg-blue-100') && both.includes('ring-2') && both.includes('ring-inset'));
  assert.ok(!both.includes('!bg-blue-50'));
});

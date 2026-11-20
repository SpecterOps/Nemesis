// Server-side (Hasura) filter/sort builders for the Findings list. Plain JS with no React or alias
// imports so it can be unit-checked from node.

export const FINDINGS_PAGE_SIZE = 100;

export const ALL_CATEGORIES = [
  'credential', 'extracted_hash', 'extracted_data', 'vulnerability', 'yara_match', 'pii', 'misc', 'informational',
];
export const ALL_SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
export const DEFAULT_TRIAGE_STATE = 'untriaged_and_actionable';
export const TRIAGE_STATES = [
  'untriaged_and_actionable', 'all', 'untriaged', 'triaged', 'true_positive', 'false_positive', 'needs_review',
];
export const TRIAGE_SOURCES = ['all', 'automated', 'human'];
export const SORT_COLUMNS = ['severity', 'created_at', 'finding_name', 'category', 'origin_name', 'file_path', 'triage_value'];

const SEVERITY_RANGES = {
  critical: { _gte: 9 },
  high: { _gte: 7, _lte: 8 },
  medium: { _gte: 4, _lte: 6 },
  low: { _gte: 2, _lte: 3 },
  informational: { _lte: 1 },
};

// Escape LIKE metacharacters so the search text matches literally (e.g. "C:\Users", "file_1")
export const escapeLike = (s) => s.replace(/[\\%_]/g, (c) => `\\${c}`);

const HUMAN = { _or: [{ automated: { _eq: false } }, { automated: { _is_null: true } }] };
const AUTOMATED = { automated: { _eq: true } };
const ACTIONABLE_VALUES = { value: { _in: ['true_positive', 'needs_review'] } };

// "The latest triage entry matches `pred`". findings.triage_id points at the latest entry when it is
// set (the UI sets it with every triage); findings without it fall back to "some entry matches"
// (automated triage runs once, before any human triage, so the latest entry is the human one if
// there is any). `noHumanFallback` additionally requires the fallback rows to have no human entry.
const latestTriage = (pred, { noHumanFallback = false } = {}) => {
  const fallback = [{ triage_id: { _is_null: true } }, { finding_triage_histories: pred }];
  if (noHumanFallback) fallback.push({ _not: { finding_triage_histories: HUMAN } });
  return { _or: [{ findings_triage_history: pred }, { _and: fallback }] };
};

const UNTRIAGED = { _not: { finding_triage_histories: {} } };

export const triageStateCondition = (state) => {
  switch (state) {
    case 'untriaged':
      return UNTRIAGED;
    case 'triaged':
      return { finding_triage_histories: {} };
    case 'untriaged_and_actionable':
      // Untriaged, or the latest triage is an automated true_positive / needs_review
      return { _or: [UNTRIAGED, latestTriage({ _and: [AUTOMATED, ACTIONABLE_VALUES] }, { noHumanFallback: true })] };
    case 'true_positive':
    case 'false_positive':
    case 'needs_review':
      return latestTriage({ value: { _eq: state } });
    default:
      return null;
  }
};

export const triageSourceCondition = (source) => {
  if (source === 'automated') return latestTriage(AUTOMATED, { noHumanFallback: true });
  if (source === 'human') return latestTriage(HUMAN);
  return null;
};

export const buildFindingsWhere = ({ categories, severities, search, triageState, triageSource, objectId }) => {
  const and = [];
  if (categories && categories.length > 0 && categories.length < ALL_CATEGORIES.length) {
    and.push({ category: { _in: categories } });
  }
  if (severities && severities.length > 0 && severities.length < ALL_SEVERITIES.length) {
    const ranges = severities.filter((s) => SEVERITY_RANGES[s]).map((s) => ({ severity: SEVERITY_RANGES[s] }));
    and.push(ranges.length === 1 ? ranges[0] : { _or: ranges });
  }
  if (search) {
    const pattern = `%${escapeLike(search)}%`;
    and.push({
      _or: [
        { finding_name: { _ilike: pattern } },
        { category: { _ilike: pattern } },
        { origin_name: { _ilike: pattern } },
        { files_enriched: { path: { _ilike: pattern } } },
      ],
    });
  }
  if (objectId) {
    // object_id is a uuid: an invalid value can't match anything (and would make Hasura error)
    const valid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(objectId.trim());
    and.push(valid ? { object_id: { _eq: objectId.trim() } } : { finding_id: { _is_null: true } });
  }
  const triage = triageStateCondition(triageState);
  if (triage) and.push(triage);
  const source = triageSourceCondition(triageSource);
  if (source) and.push(source);
  return and.length === 0 ? {} : and.length === 1 ? and[0] : { _and: and };
};

// Order-by list for a sort column; always ends with finding_id so paging is stable
export const buildFindingsOrderBy = (column, direction) => {
  const dir = direction === 'asc' ? 'asc' : 'desc';
  const tie = { finding_id: dir };
  switch (column) {
    case 'severity':
    case 'finding_name':
    case 'category':
    case 'origin_name':
      return [{ [column]: dir }, tie];
    case 'file_path':
      return [{ files_enriched: { path: dir } }, tie];
    case 'triage_value':
      // Untriaged ('' in the old client-side sort) first when ascending, last when descending
      return [{ findings_triage_history: { value: dir === 'asc' ? 'asc_nulls_first' : 'desc_nulls_last' } }, tie];
    case 'created_at':
    default:
      return [{ created_at: dir }, tie];
  }
};

// Would a finding still match the triage filters after the current user triages it with `value`?
// (A human triage becomes the latest entry, so this is exact.) Used to drop rows optimistically.
export const matchesAfterHumanTriage = (value, triageState, triageSource) => {
  if (triageSource === 'automated') return false;
  switch (triageState) {
    case 'untriaged':
    case 'untriaged_and_actionable':
      return false;
    case 'true_positive':
    case 'false_positive':
    case 'needs_review':
      return value === triageState;
    default:
      return true;
  }
};

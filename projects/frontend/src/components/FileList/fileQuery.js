// Server-side (Hasura) filter/sort builders for the Files list. Plain JS with no React or alias
// imports so it can be checked from node.
import { CONFIG_FILE_EXTENSIONS, OFFICE_EXTENSIONS, SOURCE_CODE_EXTENSIONS } from './fileExtensions.js';

export const FILES_PAGE_SIZE = 100;
export const FILE_SORT_COLUMNS = ['agent_id', 'source', 'size', 'timestamp', 'magic_type', 'findings', 'path'];

// User wildcard pattern ("*" = any run of characters) to an ILIKE pattern. Backslashes (Windows
// paths) are escaped so they match literally instead of acting as the LIKE escape character.
export const wildcardToIlike = (pattern) => pattern.replace(/\\/g, '\\\\').replace(/\*/g, '%');

export const buildFilesWhere = ({ fileType, source, path, objectId, tag, viewState, onlyWithFindings, username }) => {
  const and = [
    // Top-level files, plus extracted children that have a nesting level
    {
      _or: [
        { originating_object_id: { _is_null: true } },
        { _and: [{ originating_object_id: { _is_null: false } }, { nesting_level: { _gt: 0 } }] },
      ],
    },
  ];

  if (onlyWithFindings) and.push({ findings_count: { _gt: 0 } });

  if (objectId) {
    const valid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(objectId.trim());
    // An invalid uuid can't match anything (and would make Hasura reject the query)
    and.push(valid ? { object_id: { _eq: objectId.trim() } } : { object_id: { _is_null: true } });
  }

  if (fileType === 'plaintext') and.push({ is_plaintext: { _eq: true } });
  else if (fileType === 'binary') and.push({ is_plaintext: { _eq: false } });
  else if (fileType === 'source') and.push({ extension: { _in: SOURCE_CODE_EXTENSIONS } });
  else if (fileType === 'office') and.push({ extension: { _in: OFFICE_EXTENSIONS } });
  else if (fileType === 'config') and.push({ extension: { _in: CONFIG_FILE_EXTENSIONS } });

  if (source) and.push({ source: { _ilike: wildcardToIlike(source) } });

  if (path) {
    const pattern = path.includes('*') ? path : `*${path}*`;
    and.push({ path: { _ilike: wildcardToIlike(pattern) } });
  }

  if (tag) and.push({ file_tags: { _contains: [tag] } });

  if (viewState === 'unviewed') {
    and.push({ _not: { files_view_histories: {} } });
  } else if (viewState === 'unviewed_by_me') {
    and.push({ _not: { files_view_histories: { username: { _eq: username || '' } } } });
  }

  return and.length === 1 ? and[0] : { _and: and };
};

// Order-by list for a sort column; always ends with object_id so paging is stable
export const buildFilesOrderBy = (column, direction) => {
  const dir = direction === 'asc' ? 'asc' : 'desc';
  const tie = { object_id: dir };
  switch (column) {
    case 'agent_id':
    case 'source':
    case 'size':
    case 'magic_type':
    case 'path':
      return [{ [column]: dir }, tie];
    case 'findings':
      return [{ findings_count: dir }, tie];
    case 'timestamp':
    default:
      return [{ timestamp: dir }, tie];
  }
};

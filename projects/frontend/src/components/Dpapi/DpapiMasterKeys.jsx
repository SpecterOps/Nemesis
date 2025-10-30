import Tooltip from '@/components/shared/Tooltip2';
import { AlertTriangle, ChevronDown, ChevronUp, Search } from 'lucide-react';
import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import AutoSizer from 'react-virtualized-auto-sizer';
import { FixedSizeList as List } from 'react-window';

const ROW_HEIGHT = 48;

const Row = React.memo(({ index, style, data }) => {
  const { records } = data;
  const record = records[index];
  const [copiedCell, setCopiedCell] = useState(null);

  const handleCellDoubleClick = (value, cellKey) => {
    if (value && value.toString().trim()) {
      navigator.clipboard.writeText(value.toString());
      setCopiedCell(cellKey);
      setTimeout(() => setCopiedCell(null), 1000);
    }
  };

  // Convert BYTEA to hex string for display
  const bytesToHex = (bytes) => {
    if (!bytes) return null;
    // If it's already a string (hex format from PostgreSQL), strip the \x prefix
    if (typeof bytes === 'string') {
      return bytes.startsWith('\\x') ? bytes.substring(2) : bytes;
    }
    // If it's a Buffer or Uint8Array, convert to hex
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  };

  const plaintextKeySha1 = bytesToHex(record.plaintext_key_sha1);

  return (
    <div
      style={style}
      className="flex items-center border-b dark:border-gray-700 transition-colors dark:bg-dark-secondary hover:bg-gray-100 dark:hover:bg-gray-700"
    >
      <div
        className={`px-4 flex-shrink-0 w-96 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'guid' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.guid, 'guid')}
        title="Double-click to copy"
      >
        <Tooltip content={record.guid || ''} side="top" align="start">
          <span className="block truncate font-mono">{record.guid || ''}</span>
        </Tooltip>
      </div>
      <div
        className={`px-4 flex-shrink-0 w-96 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'plaintext_key_sha1' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(plaintextKeySha1, 'plaintext_key_sha1')}
        title="Double-click to copy"
      >
        <Tooltip content={plaintextKeySha1 || 'Not decrypted'} side="top" align="start">
          <span className={`block truncate font-mono ${plaintextKeySha1 ? '' : 'italic text-gray-400 dark:text-gray-500'}`}>
            {plaintextKeySha1 || 'Not decrypted'}
          </span>
        </Tooltip>
      </div>
      <div
        className={`px-4 flex-shrink-0 w-96 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'backup_key_guid' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.backup_key_guid, 'backup_key_guid')}
        title="Double-click to copy"
      >
        <Tooltip content={record.backup_key_guid || 'None'} side="top" align="start">
          <span className={`block truncate font-mono ${record.backup_key_guid ? '' : 'italic text-gray-400 dark:text-gray-500'}`}>
            {record.backup_key_guid || 'None'}
          </span>
        </Tooltip>
      </div>
    </div>
  );
});

const SortableHeader = ({ children, column, currentSort, currentDirection, onSort, className = "" }) => {
  const isActive = currentSort === column;
  const nextDirection = isActive && currentDirection === 'asc' ? 'desc' : 'asc';

  return (
    <div
      className={`flex items-center cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 px-4 py-2 ${className}`}
      onClick={() => onSort(column, nextDirection)}
    >
      <span className="text-sm font-medium text-gray-500 dark:text-gray-400">{children}</span>
      <div className="ml-1 flex flex-col">
        {isActive ? (
          currentDirection === 'asc' ? (
            <ChevronUp className="w-3 h-3 text-gray-600 dark:text-gray-300" />
          ) : (
            <ChevronDown className="w-3 h-3 text-gray-600 dark:text-gray-300" />
          )
        ) : (
          <div className="w-3 h-3" />
        )}
      </div>
    </div>
  );
};

const DpapiMasterKeys = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [records, setRecords] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [totalCount, setTotalCount] = useState(0);

  // Filter states
  const [guidFilter, setGuidFilter] = useState(() => searchParams.get('guid') || '');
  const [sortColumn, setSortColumn] = useState(() => searchParams.get('sort_column') || 'guid');
  const [sortDirection, setSortDirection] = useState(() => searchParams.get('sort_direction') || 'asc');

  const handleSort = (column, direction) => {
    setSortColumn(column);
    setSortDirection(direction);
  };

  const buildWhereClause = () => {
    const conditions = [];

    if (guidFilter) {
      // If user provided wildcards, use them as-is; otherwise add wildcards around the term
      const hasWildcard = guidFilter.includes('*');
      const pattern = hasWildcard
        ? guidFilter.replace(/\*/g, '%')
        : `%${guidFilter}%`;
      conditions.push({ guid: { _ilike: pattern } });
    }

    return conditions.length > 0 ? conditions[0] : {};
  };

  const buildOrderByClause = () => {
    const orderBy = {};
    orderBy[sortColumn] = sortDirection;
    return orderBy;
  };

  useEffect(() => {
    const params = new URLSearchParams(searchParams);

    if (guidFilter) {
      params.set('guid', guidFilter);
    } else {
      params.delete('guid');
    }

    params.set('sort_column', sortColumn);
    params.set('sort_direction', sortDirection);

    setSearchParams(params, { replace: true });
  }, [guidFilter, sortColumn, sortDirection, setSearchParams]);

  useEffect(() => {
    const fetchData = async () => {
      setIsLoading(true);
      setError(null);

      try {
        const query = {
          query: `
            query GetMasterKeys($where: dpapi_masterkeys_bool_exp, $order_by: [dpapi_masterkeys_order_by!]) {
              dpapi_masterkeys(
                where: $where,
                order_by: $order_by
              ) {
                guid
                plaintext_key_sha1
                backup_key_guid
              }
              dpapi_masterkeys_aggregate(where: $where) {
                aggregate {
                  count
                }
              }
            }
          `,
          variables: {
            where: buildWhereClause(),
            order_by: buildOrderByClause()
          }
        };

        const response = await fetch('/hasura/v1/graphql', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
          },
          body: JSON.stringify(query)
        });

        if (!response.ok) {
          throw new Error(`Network response error: ${response.status}`);
        }

        const result = await response.json();
        if (result.errors) {
          throw new Error(result.errors[0].message);
        }

        setRecords(result.data.dpapi_masterkeys);
        setTotalCount(result.data.dpapi_masterkeys_aggregate.aggregate.count);
      } catch (err) {
        console.error('Error fetching DPAPI masterkeys:', err);
        setError(err.message);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [guidFilter, sortColumn, sortDirection]);

  return (
    <div>
      {/* Filters */}
      <div className="p-2 border-b dark:border-gray-700 overflow-x-auto">
        <div className="flex items-center space-x-4 min-w-max">
          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <input
              type="text"
              placeholder="Filter by GUID"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={guidFilter}
              onChange={(e) => setGuidFilter(e.target.value)}
            />
          </div>

          <span className="text-sm text-gray-600 dark:text-gray-400">
            {totalCount.toLocaleString()} masterkey{totalCount !== 1 ? 's' : ''} found
          </span>
        </div>
      </div>

      {/* Headers */}
      <div className="flex border-b dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        <SortableHeader
          column="guid"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-96"
        >
          GUID
        </SortableHeader>
        <SortableHeader
          column="plaintext_key_sha1"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-96"
        >
          Plaintext Key SHA1
        </SortableHeader>
        <SortableHeader
          column="backup_key_guid"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-96"
        >
          Backup Key GUID
        </SortableHeader>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2 m-4">
          <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
          <div className="flex flex-col">
            <span className="text-red-600 dark:text-red-400">Error loading DPAPI masterkeys: {error}</span>
            <span className="text-sm text-red-500 dark:text-red-400">Check browser console for details</span>
          </div>
        </div>
      )}

      {/* Loading state */}
      {isLoading && (
        <div className="flex justify-center items-center h-32">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
        </div>
      )}

      {/* No results state */}
      {!isLoading && !error && records.length === 0 && (
        <div className="flex flex-col items-center justify-center p-12 text-center">
          <div className="text-gray-500 dark:text-gray-400 mb-6">
            <Search className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <h3 className="text-lg font-medium mb-2">No masterkeys found</h3>
            <p className="max-w-md mx-auto">
              No DPAPI masterkeys match your current filters.
            </p>
          </div>
        </div>
      )}

      {/* Virtualized list */}
      {!isLoading && !error && records.length > 0 && (
        <div className="h-[calc(100vh-180px)]">
          <AutoSizer>
            {({ height, width }) => (
              <List
                height={height}
                width={width}
                itemCount={records.length}
                itemSize={ROW_HEIGHT}
                itemData={{
                  records
                }}
              >
                {Row}
              </List>
            )}
          </AutoSizer>
        </div>
      )}
    </div>
  );
};

export default DpapiMasterKeys;
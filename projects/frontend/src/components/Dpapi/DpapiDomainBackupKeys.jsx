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

  return (
    <div
      style={style}
      className="flex items-center border-b dark:border-gray-700 transition-colors dark:bg-dark-secondary hover:bg-gray-100 dark:hover:bg-gray-700"
    >
      <div
        className={`px-4 flex-shrink-0 w-24 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'id' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.id, 'id')}
        title="Double-click to copy"
      >
        <span className="block truncate font-mono">{record.id || ''}</span>
      </div>
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
        className={`px-4 flex-grow text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'domain_controller' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.domain_controller, 'domain_controller')}
        title="Double-click to copy"
      >
        <Tooltip content={record.domain_controller || 'None'} side="top" align="start" maxWidth="full">
          <span className={`block truncate ${record.domain_controller ? '' : 'italic text-gray-400 dark:text-gray-500'}`}>
            {record.domain_controller || 'None'}
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

const DpapiDomainBackupKeys = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [records, setRecords] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [totalCount, setTotalCount] = useState(0);

  // Filter states
  const [guidFilter, setGuidFilter] = useState(() => searchParams.get('guid') || '');
  const [dcFilter, setDcFilter] = useState(() => searchParams.get('dc') || '');
  const [sortColumn, setSortColumn] = useState(() => {
    const col = searchParams.get('sort_column');
    return (col === 'id' || col === 'guid' || col === 'domain_controller') ? col : 'id';
  });
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

    if (dcFilter) {
      // If user provided wildcards, use them as-is; otherwise add wildcards around the term
      const hasWildcard = dcFilter.includes('*');
      const pattern = hasWildcard
        ? dcFilter.replace(/\*/g, '%')
        : `%${dcFilter}%`;
      conditions.push({ domain_controller: { _ilike: pattern } });
    }

    return conditions.length > 1 ? { _and: conditions } : conditions[0] || {};
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

    if (dcFilter) {
      params.set('dc', dcFilter);
    } else {
      params.delete('dc');
    }

    params.set('sort_column', sortColumn);
    params.set('sort_direction', sortDirection);

    setSearchParams(params, { replace: true });
  }, [guidFilter, dcFilter, sortColumn, sortDirection, setSearchParams]);

  useEffect(() => {
    const fetchData = async () => {
      setIsLoading(true);
      setError(null);

      try {
        const query = {
          query: `
            query GetDomainBackupKeys($where: dpapi_domain_backup_keys_bool_exp, $order_by: [dpapi_domain_backup_keys_order_by!]) {
              dpapi_domain_backup_keys(
                where: $where,
                order_by: $order_by
              ) {
                id
                guid
                domain_controller
              }
              dpapi_domain_backup_keys_aggregate(where: $where) {
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

        setRecords(result.data.dpapi_domain_backup_keys);
        setTotalCount(result.data.dpapi_domain_backup_keys_aggregate.aggregate.count);
      } catch (err) {
        console.error('Error fetching DPAPI domain backup keys:', err);
        setError(err.message);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [guidFilter, dcFilter, sortColumn, sortDirection]);

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

          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <input
              type="text"
              placeholder="Filter by domain controller"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2 w-64"
              value={dcFilter}
              onChange={(e) => setDcFilter(e.target.value)}
            />
          </div>

          <span className="text-sm text-gray-600 dark:text-gray-400">
            {totalCount.toLocaleString()} domain backup key{totalCount !== 1 ? 's' : ''} found
          </span>
        </div>
      </div>

      {/* Headers */}
      <div className="flex border-b dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        <SortableHeader
          column="id"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-24"
        >
          ID
        </SortableHeader>
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
          column="domain_controller"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-grow"
        >
          Domain Controller
        </SortableHeader>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2 m-4">
          <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
          <div className="flex flex-col">
            <span className="text-red-600 dark:text-red-400">Error loading DPAPI domain backup keys: {error}</span>
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
            <h3 className="text-lg font-medium mb-2">No domain backup keys found</h3>
            <p className="max-w-md mx-auto">
              No DPAPI domain backup keys match your current filters.
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

export default DpapiDomainBackupKeys;
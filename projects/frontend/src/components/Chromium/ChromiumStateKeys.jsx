import Tooltip from '@/components/shared/Tooltip2';
import { AlertTriangle, ChevronDown, ChevronUp, ChevronLeft, ChevronRight, Search, X, Download } from 'lucide-react';
import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import AutoSizer from 'react-virtualized-auto-sizer';
import { FixedSizeList as List } from 'react-window';

const ROW_HEIGHT = 48;
const PAGINATION_THRESHOLD = 10000;
const PAGE_SIZE = 100;

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
      <div className="px-2 flex-shrink-0 w-80 text-sm text-gray-500 dark:text-gray-400 text-left">
        <Tooltip content={record.originating_object_id} side="top" align="start">
          <Link
            to={`/files/${record.originating_object_id}`}
            className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 truncate block"
          >
            {record.originating_object_id}
          </Link>
        </Tooltip>
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-32 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'source' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.source, 'source')}
        title="Double-click to copy"
      >
        <Tooltip content={record.source || 'Unknown'} side="top" align="start">
          <span className="block truncate">{record.source || 'Unknown'}</span>
        </Tooltip>
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-32 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'username' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.username, 'username')}
        title="Double-click to copy"
      >
        <Tooltip content={record.username || 'Unknown'} side="top" align="start">
          <span className="block truncate">{record.username || 'Unknown'}</span>
        </Tooltip>
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-32 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'browser' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.browser, 'browser')}
        title="Double-click to copy"
      >
        <Tooltip content={record.browser || 'Unknown'} side="top" align="start">
          <span className="block truncate">{record.browser || 'Unknown'}</span>
        </Tooltip>
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-40 text-sm text-gray-500 dark:text-gray-400 flex items-center justify-center cursor-pointer select-text transition-colors ${copiedCell === 'key_is_decrypted' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.key_is_decrypted ? 'Yes' : 'No', 'key_is_decrypted')}
        title="Double-click to copy"
      >
        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
          record.key_is_decrypted 
            ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' 
            : 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300'
        }`}>
          {record.key_is_decrypted ? 'Yes' : 'No'}
        </span>
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-56 text-sm text-gray-500 dark:text-gray-400 flex items-center justify-center cursor-pointer select-text transition-colors ${copiedCell === 'app_bound_key_is_decrypted' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.app_bound_key_is_decrypted ? 'Yes' : 'No', 'app_bound_key_is_decrypted')}
        title="Double-click to copy"
      >
        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
          record.app_bound_key_is_decrypted 
            ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' 
            : 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300'
        }`}>
          {record.app_bound_key_is_decrypted ? 'Yes' : 'No'}
        </span>
      </div>
    </div>
  );
});

const SortableHeader = ({ children, column, currentSort, currentDirection, onSort, className = "" }) => {
  const isActive = currentSort === column;
  const nextDirection = isActive && currentDirection === 'asc' ? 'desc' : 'asc';

  return (
    <div
      className={`flex items-center cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 px-2 py-2 ${className}`}
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

const PaginationControls = ({ currentPage, totalPages, totalCount, onPageChange }) => {
  const maxVisiblePages = 7;
  const startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
  const endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
  
  const pageNumbers = [];
  for (let i = startPage; i <= endPage; i++) {
    pageNumbers.push(i);
  }

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t dark:border-gray-700">
      <div className="flex-1 flex justify-between sm:hidden">
        <button
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage === 1}
          className="relative inline-flex items-center px-4 py-2 border dark:border-gray-700 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-dark-secondary hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Previous
        </button>
        <button
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
          className="ml-3 relative inline-flex items-center px-4 py-2 border dark:border-gray-700 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-dark-secondary hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Next
        </button>
      </div>
      <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
        <div>
          <p className="text-sm text-gray-700 dark:text-gray-300">
            Showing <span className="font-medium">{(currentPage - 1) * PAGE_SIZE + 1}</span> to{' '}
            <span className="font-medium">
              {Math.min(currentPage * PAGE_SIZE, totalCount)}
            </span>{' '}
            of <span className="font-medium">{totalCount.toLocaleString()}</span> results
          </p>
        </div>
        <div>
          <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
            <button
              onClick={() => onPageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="relative inline-flex items-center px-2 py-2 rounded-l-md border dark:border-gray-700 bg-white dark:bg-dark-secondary text-sm font-medium text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="h-5 w-5" />
            </button>
            
            {startPage > 1 && (
              <>
                <button
                  onClick={() => onPageChange(1)}
                  className="bg-white dark:bg-dark-secondary border dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 relative inline-flex items-center px-4 py-2 text-sm font-medium"
                >
                  1
                </button>
                {startPage > 2 && (
                  <span className="relative inline-flex items-center px-4 py-2 border dark:border-gray-700 bg-white dark:bg-dark-secondary text-sm font-medium text-gray-700 dark:text-gray-300">
                    ...
                  </span>
                )}
              </>
            )}
            
            {pageNumbers.map((page) => (
              <button
                key={page}
                onClick={() => onPageChange(page)}
                className={`${
                  currentPage === page
                    ? 'z-10 bg-blue-50 dark:bg-blue-900/30 border-blue-500 dark:border-blue-400 text-blue-600 dark:text-blue-400'
                    : 'bg-white dark:bg-dark-secondary border dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700'
                } relative inline-flex items-center px-4 py-2 text-sm font-medium`}
              >
                {page}
              </button>
            ))}
            
            {endPage < totalPages && (
              <>
                {endPage < totalPages - 1 && (
                  <span className="relative inline-flex items-center px-4 py-2 border dark:border-gray-700 bg-white dark:bg-dark-secondary text-sm font-medium text-gray-700 dark:text-gray-300">
                    ...
                  </span>
                )}
                <button
                  onClick={() => onPageChange(totalPages)}
                  className="bg-white dark:bg-dark-secondary border dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 relative inline-flex items-center px-4 py-2 text-sm font-medium"
                >
                  {totalPages}
                </button>
              </>
            )}
            
            <button
              onClick={() => onPageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="relative inline-flex items-center px-2 py-2 rounded-r-md border dark:border-gray-700 bg-white dark:bg-dark-secondary text-sm font-medium text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronRight className="h-5 w-5" />
            </button>
          </nav>
        </div>
      </div>
    </div>
  );
};

const ChromiumStateKeys = ({ renderActions }) => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [records, setRecords] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [isPaginated, setIsPaginated] = useState(false);

  // Filter states
  const [sourceFilter, setSourceFilter] = useState(() => searchParams.get('source') || '');
  const [usernameFilter, setUsernameFilter] = useState(() => searchParams.get('username') || '');
  const [browserFilter, setBrowserFilter] = useState(() => searchParams.get('browser') || '');
  const [keyIsDecryptedFilter, setKeyIsDecryptedFilter] = useState(() => searchParams.get('key_is_decrypted') || '');
  const [appBoundKeyIsDecryptedFilter, setAppBoundKeyIsDecryptedFilter] = useState(() => searchParams.get('app_bound_key_is_decrypted') || '');
  const [sortColumn, setSortColumn] = useState(() => searchParams.get('sort_column') || 'originating_object_id');
  const [sortDirection, setSortDirection] = useState(() => searchParams.get('sort_direction') || 'asc');

  // CSV export state
  const [isExporting, setIsExporting] = useState(false);

  const totalPages = Math.ceil(totalCount / PAGE_SIZE);

  const handleSort = (column, direction) => {
    setSortColumn(column);
    setSortDirection(direction);
    setCurrentPage(1);
  };

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setCurrentPage(newPage);
    }
  };

  const buildWhereClause = () => {
    const conditions = [];

    if (sourceFilter) {
      conditions.push({ source: { _ilike: sourceFilter.replace(/\*/g, '%') } });
    }

    if (usernameFilter) {
      conditions.push({ username: { _ilike: usernameFilter.replace(/\*/g, '%') } });
    }

    if (browserFilter) {
      conditions.push({ browser: { _ilike: browserFilter.replace(/\*/g, '%') } });
    }

    if (keyIsDecryptedFilter === 'true') {
      conditions.push({ key_is_decrypted: { _eq: true } });
    } else if (keyIsDecryptedFilter === 'false') {
      conditions.push({ key_is_decrypted: { _eq: false } });
    }

    if (appBoundKeyIsDecryptedFilter === 'true') {
      conditions.push({ app_bound_key_is_decrypted: { _eq: true } });
    } else if (appBoundKeyIsDecryptedFilter === 'false') {
      conditions.push({ app_bound_key_is_decrypted: { _eq: false } });
    }

    return conditions.length > 1 ? { _and: conditions } : conditions[0] || {};
  };

  const buildOrderByClause = () => {
    const orderBy = {};
    
    switch (sortColumn) {
      case 'originating_object_id':
        orderBy.originating_object_id = sortDirection;
        break;
      case 'source':
        orderBy.source = sortDirection;
        break;
      case 'username':
        orderBy.username = sortDirection;
        break;
      case 'browser':
        orderBy.browser = sortDirection;
        break;
      case 'key_is_decrypted':
        orderBy.key_is_decrypted = sortDirection;
        break;
      case 'app_bound_key_is_decrypted':
        orderBy.app_bound_key_is_decrypted = sortDirection;
        break;
      default:
        orderBy.originating_object_id = sortDirection;
    }
    
    return orderBy;
  };

  const handleExportCSV = async () => {
    setIsExporting(true);
    try {
      // Query to get ALL data matching current filters (bypassing pagination)
      const exportQuery = {
        query: `
          query GetStateKeysExport($where: chromium_state_keys_bool_exp, $order_by: [chromium_state_keys_order_by!]) {
            chromium_state_keys(
              where: $where,
              order_by: $order_by
            ) {
              originating_object_id
              source
              username
              browser
              key_is_decrypted
              app_bound_key_is_decrypted
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
        body: JSON.stringify(exportQuery)
      });

      if (!response.ok) {
        throw new Error(`Network response error: ${response.status}`);
      }

      const result = await response.json();
      if (result.errors) {
        throw new Error(result.errors[0].message);
      }

      const data = result.data.chromium_state_keys;

      // Convert to CSV
      if (data.length === 0) {
        alert('No data to export');
        return;
      }

      const headers = [
        'Object ID',
        'Source', 
        'Username',
        'Browser',
        'Key Is Decrypted',
        'App Bound Key Is Decrypted'
      ];

      const csvContent = [
        headers.join(','),
        ...data.map(record => [
          `"${(record.originating_object_id || '').replace(/"/g, '""')}"`,
          `"${(record.source || '').replace(/"/g, '""')}"`,
          `"${(record.username || '').replace(/"/g, '""')}"`,
          `"${(record.browser || '').replace(/"/g, '""')}"`,
          record.key_is_decrypted ? 'true' : 'false',
          record.app_bound_key_is_decrypted ? 'true' : 'false'
        ].join(','))
      ].join('\n');

      // Download the file
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `chromium_state_keys_${new Date().toISOString().split('T')[0]}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

    } catch (err) {
      console.error('Error exporting CSV:', err);
      alert(`Error exporting CSV: ${err.message}`);
    } finally {
      setIsExporting(false);
    }
  };

  useEffect(() => {
    const params = new URLSearchParams();

    if (sourceFilter) {
      params.set('source', sourceFilter);
    }

    if (usernameFilter) {
      params.set('username', usernameFilter);
    }

    if (browserFilter) {
      params.set('browser', browserFilter);
    }

    if (keyIsDecryptedFilter) {
      params.set('key_is_decrypted', keyIsDecryptedFilter);
    }

    if (appBoundKeyIsDecryptedFilter) {
      params.set('app_bound_key_is_decrypted', appBoundKeyIsDecryptedFilter);
    }

    params.set('sort_column', sortColumn);
    params.set('sort_direction', sortDirection);

    setSearchParams(params, { replace: true });
  }, [sourceFilter, usernameFilter, browserFilter, keyIsDecryptedFilter, appBoundKeyIsDecryptedFilter, sortColumn, sortDirection, setSearchParams]);


  useEffect(() => {
    const fetchData = async () => {
      setIsLoading(true);
      setError(null);
      
      try {
        // First, get the count
        const countQuery = {
          query: `
            query GetStateKeysCount($where: chromium_state_keys_bool_exp) {
              chromium_state_keys_aggregate(where: $where) {
                aggregate {
                  count
                }
              }
            }
          `,
          variables: {
            where: buildWhereClause()
          }
        };

        const countResponse = await fetch('/hasura/v1/graphql', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
          },
          body: JSON.stringify(countQuery)
        });

        if (!countResponse.ok) {
          throw new Error(`Network response error: ${countResponse.status}`);
        }

        const countResult = await countResponse.json();
        if (countResult.errors) {
          throw new Error(countResult.errors[0].message);
        }

        const count = countResult.data.chromium_state_keys_aggregate.aggregate.count;
        setTotalCount(count);
        setIsPaginated(count > PAGINATION_THRESHOLD);

        // Now fetch the actual data
        let dataQuery;
        if (count > PAGINATION_THRESHOLD) {
          // Paginated query
          dataQuery = {
            query: `
              query GetStateKeysPaginated($where: chromium_state_keys_bool_exp, $limit: Int!, $offset: Int!, $order_by: [chromium_state_keys_order_by!]) {
                chromium_state_keys(
                  where: $where,
                  limit: $limit,
                  offset: $offset,
                  order_by: $order_by
                ) {
                  originating_object_id
                  source
                  username
                  browser
                  key_is_decrypted
                  app_bound_key_is_decrypted
                }
              }
            `,
            variables: {
              where: buildWhereClause(),
              limit: PAGE_SIZE,
              offset: (currentPage - 1) * PAGE_SIZE,
              order_by: buildOrderByClause()
            }
          };
        } else {
          // Non-paginated query - get all data
          dataQuery = {
            query: `
              query GetStateKeysAll($where: chromium_state_keys_bool_exp, $order_by: [chromium_state_keys_order_by!]) {
                chromium_state_keys(
                  where: $where,
                  order_by: $order_by
                ) {
                  originating_object_id
                  source
                  username
                  browser
                  key_is_decrypted
                  app_bound_key_is_decrypted
                }
              }
            `,
            variables: {
              where: buildWhereClause(),
              order_by: buildOrderByClause()
            }
          };
        }

        const dataResponse = await fetch('/hasura/v1/graphql', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
          },
          body: JSON.stringify(dataQuery)
        });

        if (!dataResponse.ok) {
          throw new Error(`Network response error: ${dataResponse.status}`);
        }

        const dataResult = await dataResponse.json();
        if (dataResult.errors) {
          throw new Error(dataResult.errors[0].message);
        }

        setRecords(dataResult.data.chromium_state_keys);
      } catch (err) {
        console.error('Error fetching chromium state keys:', err);
        setError(err.message);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [currentPage, sourceFilter, usernameFilter, browserFilter, keyIsDecryptedFilter, appBoundKeyIsDecryptedFilter, sortColumn, sortDirection]);

  // Provide the CSV download button to the parent component
  useEffect(() => {
    if (renderActions) {
      renderActions(
        <button
          onClick={handleExportCSV}
          disabled={isExporting || isLoading || totalCount === 0}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white text-sm font-medium rounded-lg transition-colors disabled:cursor-not-allowed"
          title={totalCount === 0 ? "No data to export" : `Export ${totalCount.toLocaleString()} records to CSV`}
        >
          {isExporting ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              <span>Exporting...</span>
            </>
          ) : (
            <>
              <Download className="w-4 h-4" />
              <span>Download CSV</span>
            </>
          )}
        </button>
      );
    }
  }, [renderActions, isExporting, isLoading, totalCount]);

  return (
    <div>
      {/* Filters */}
      <div className="p-2 border-b dark:border-gray-700 overflow-x-auto">
        <div className="flex items-center space-x-4 min-w-max">
          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <input
              type="text"
              placeholder="Filter by source"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={sourceFilter}
              onChange={(e) => {
                setSourceFilter(e.target.value);
                setCurrentPage(1);
              }}
            />
          </div>

          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <input
              type="text"
              placeholder="Filter by username"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={usernameFilter}
              onChange={(e) => {
                setUsernameFilter(e.target.value);
                setCurrentPage(1);
              }}
            />
          </div>

          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <input
              type="text"
              placeholder="Filter by browser"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={browserFilter}
              onChange={(e) => {
                setBrowserFilter(e.target.value);
                setCurrentPage(1);
              }}
            />
          </div>

          <div className="flex items-center space-x-2">
            <select
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={keyIsDecryptedFilter}
              onChange={(e) => {
                setKeyIsDecryptedFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <option value="">Key Decrypted (All)</option>
              <option value="true">Yes</option>
              <option value="false">No</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <select
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={appBoundKeyIsDecryptedFilter}
              onChange={(e) => {
                setAppBoundKeyIsDecryptedFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <option value="">App Bound Key Decrypted (All)</option>
              <option value="true">Yes</option>
              <option value="false">No</option>
            </select>
          </div>

          <span className="text-sm text-gray-600 dark:text-gray-400">
            {totalCount.toLocaleString()} record{totalCount !== 1 ? 's' : ''} found
            {isPaginated && ` (showing ${records.length})`}
          </span>
        </div>
      </div>

      {/* Error State */}
      {error && (
        <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2">
          <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
          <div className="flex flex-col">
            <span className="text-red-600 dark:text-red-400">Error loading chromium state keys: {error}</span>
            <span className="text-sm text-red-500 dark:text-red-400">Check browser console for details</span>
          </div>
        </div>
      )}

      {/* Loading State */}
      {isLoading && (
        <div className="flex justify-center items-center h-32">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
        </div>
      )}

      {/* Headers */}
      <div className="flex border-b dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        <SortableHeader
          column="originating_object_id"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-80"
        >
          Object ID
        </SortableHeader>
        <SortableHeader
          column="source"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-32"
        >
          Source
        </SortableHeader>
        <SortableHeader
          column="username"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-32"
        >
          Username
        </SortableHeader>
        <SortableHeader
          column="browser"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-32"
        >
          Browser
        </SortableHeader>
        <SortableHeader
          column="key_is_decrypted"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-40"
        >
          Key Decrypted
        </SortableHeader>
        <SortableHeader
          column="app_bound_key_is_decrypted"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-56"
        >
          App Bound Key Decrypted
        </SortableHeader>
      </div>

      {!isLoading && !error && records.length === 0 && totalCount === 0 && (
        <div className="flex flex-col items-center justify-center p-12 text-center">
          <div className="text-gray-500 dark:text-gray-400 mb-6">
            <Search className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <h3 className="text-lg font-medium mb-2">No chromium state keys found</h3>
            <p className="max-w-md mx-auto">
              No chromium state key records match your current filters.
            </p>
          </div>
        </div>
      )}

      {/* List or Table based on pagination */}
      {!isLoading && !error && records.length > 0 && (
        <>
          {isPaginated ? (
            // Paginated table view
            <div className="overflow-x-auto">
              <div className="min-w-full">
                {records.map((record, index) => (
                  <Row
                    key={`${record.originating_object_id}-${index}`}
                    index={index}
                    style={{ height: ROW_HEIGHT }}
                    data={{
                      records
                    }}
                  />
                ))}
              </div>
            </div>
          ) : (
            // Virtualized list view
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
          
          {/* Pagination controls */}
          {isPaginated && (
            <PaginationControls
              currentPage={currentPage}
              totalPages={totalPages}
              totalCount={totalCount}
              onPageChange={handlePageChange}
            />
          )}
        </>
      )}
    </div>
  );
};

export default ChromiumStateKeys;
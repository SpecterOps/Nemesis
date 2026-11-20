import Tooltip from '@/components/shared/Tooltip2';
import { AlertTriangle, ChevronDown, ChevronUp, ChevronLeft, ChevronRight, Search, Download } from 'lucide-react';
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import AutoSizer from 'react-virtualized-auto-sizer';
import { FixedSizeList as List } from 'react-window';
import { buildStableOrderBy, csvEscape, exportHasuraTableToCsv, useDebouncedValue, useHasuraTable } from './useHasuraTable';

const ROW_HEIGHT = 48;
const PAGINATION_THRESHOLD = 10000;
const PAGE_SIZE = 100;
const TABLE_FIELDS = 'originating_object_id source username browser title url visit_count last_visit_time';

/** @param {{ index: number, style: import('react').CSSProperties, data: any }} props */
const RecordRow = ({ index, style, data }) => {
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
      <div className="px-2 flex-shrink-0 w-24 text-sm text-gray-500 dark:text-gray-400 text-left">
        {record.originating_object_id ? (
          <Tooltip content={record.originating_object_id} side="top" align="start">
            <Link
              to={`/files/${record.originating_object_id}`}
              className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 truncate block"
            >
              {record.originating_object_id.substring(0, 8)}...
            </Link>
          </Tooltip>
        ) : (
          <span className="text-gray-400">—</span>
        )}
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-20 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'source' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.source, 'source')}
        title="Double-click to copy"
      >
        <Tooltip content={record.source || 'Unknown'} side="top" align="start">
          <span className="block truncate">{record.source || 'Unknown'}</span>
        </Tooltip>
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-24 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'username' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.username, 'username')}
        title="Double-click to copy"
      >
        <Tooltip content={record.username || 'Unknown'} side="top" align="start">
          <span className="block truncate">{record.username || 'Unknown'}</span>
        </Tooltip>
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-20 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'browser' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.browser, 'browser')}
        title="Double-click to copy"
      >
        <Tooltip content={record.browser || 'Unknown'} side="top" align="start">
          <span className="block truncate">{record.browser || 'Unknown'}</span>
        </Tooltip>
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-60 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'title' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.title, 'title')}
        title="Double-click to copy"
      >
        <Tooltip content={record.title || ''} side="top" align="start">
          <span className="block truncate">{record.title || ''}</span>
        </Tooltip>
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-16 text-sm text-gray-500 dark:text-gray-400 text-center cursor-pointer select-text transition-colors ${copiedCell === 'visit_count' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.visit_count, 'visit_count')}
        title="Double-click to copy"
      >
        {record.visit_count || 0}
      </div>
      <div 
        className={`px-2 flex-shrink-0 w-44 text-sm text-gray-500 dark:text-gray-400 text-left cursor-pointer select-text transition-colors ${copiedCell === 'last_visit_time' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.last_visit_time ? new Date(record.last_visit_time).toLocaleString() : '', 'last_visit_time')}
        title="Double-click to copy"
      >
        {record.last_visit_time ? new Date(record.last_visit_time).toLocaleString() : ''}
      </div>
      <div 
        className={`px-6 flex-grow text-sm text-gray-500 dark:text-gray-400 truncate text-left cursor-pointer select-text transition-colors ${copiedCell === 'url' ? 'bg-green-200 dark:bg-green-800' : ''}`}
        onDoubleClick={() => handleCellDoubleClick(record.url, 'url')}
        title="Double-click to copy"
      >
        <Tooltip content={record.url || ''} side="top" align="start" maxWidth="full">
          <span>{record.url || ''}</span>
        </Tooltip>
      </div>
    </div>
  );
};
const Row = React.memo(RecordRow);

const SortableHeader = ({ children, column, currentSort, currentDirection, onSort, className = "" }) => {
  const isActive = currentSort === column;
  const nextDirection = isActive && currentDirection === 'asc' ? 'desc' : 'asc';

  return (
    <button
      type="button"
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
    </button>
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

const ChromiumHistory = ({ renderActions }) => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);

  // Filter states
  const [sourceFilter, setSourceFilter] = useState(() => searchParams.get('source') || '');
  const [usernameFilter, setUsernameFilter] = useState(() => searchParams.get('username') || '');
  const [browserFilter, setBrowserFilter] = useState(() => searchParams.get('browser') || '');
  const [urlFilter, setUrlFilter] = useState(() => searchParams.get('url') || '');
  const [sortColumn, setSortColumn] = useState(() => searchParams.get('sort_column') || 'last_visit_time');
  const [sortDirection, setSortDirection] = useState(() => searchParams.get('sort_direction') || 'desc');

  // CSV export state
  const [isExporting, setIsExporting] = useState(false);
  const [exportProgress, setExportProgress] = useState(0);


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

  // Debounce text filters so typing doesn't fire a query per keystroke
  const debouncedSourceFilter = useDebouncedValue(sourceFilter);
  const debouncedUsernameFilter = useDebouncedValue(usernameFilter);
  const debouncedBrowserFilter = useDebouncedValue(browserFilter);
  const debouncedUrlFilter = useDebouncedValue(urlFilter);

  const buildWhereClause = () => {
    const conditions = [];

    if (debouncedSourceFilter) {
      conditions.push({ source: { _ilike: debouncedSourceFilter.replace(/\*/g, '%') } });
    }

    if (debouncedUsernameFilter) {
      conditions.push({ username: { _ilike: debouncedUsernameFilter.replace(/\*/g, '%') } });
    }

    if (debouncedBrowserFilter) {
      conditions.push({ browser: { _ilike: debouncedBrowserFilter.replace(/\*/g, '%') } });
    }

    if (debouncedUrlFilter) {
      conditions.push({ url: { _ilike: debouncedUrlFilter.replace(/\*/g, '%') } });
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
      case 'title':
        orderBy.title = sortDirection;
        break;
      case 'url':
        orderBy.url = sortDirection;
        break;
      case 'visit_count':
        orderBy.visit_count = sortDirection;
        break;
      case 'last_visit_time':
        orderBy.last_visit_time = sortDirection;
        break;
      default:
        orderBy.last_visit_time = sortDirection;
    }

    return buildStableOrderBy(Object.keys(orderBy)[0], sortDirection);
  };

  const { records, totalCount, isPaginated, isLoading, error } = useHasuraTable({
    table: 'chromium_history',
    fields: TABLE_FIELDS,
    where: buildWhereClause(),
    orderBy: buildOrderByClause(),
    currentPage,
    pageSize: PAGE_SIZE,
    threshold: PAGINATION_THRESHOLD,
  });
  const totalPages = Math.ceil(totalCount / PAGE_SIZE);

  const handleExportCSV = async () => {
    setIsExporting(true);
    setExportProgress(0);
    try {
      // Stream ALL rows matching the current filters in chunks (tables can hold millions of rows)
      const exported = await exportHasuraTableToCsv({
        table: 'chromium_history',
        fields: TABLE_FIELDS,
        where: buildWhereClause(),
        orderBy: buildOrderByClause(),
        headers: ['Object ID', 'Source', 'Username', 'Browser', 'Title', 'URL', 'Visit Count', 'Last Visit Time'],
        toCsvRow: (record) => [
          csvEscape(record.originating_object_id),
          csvEscape(record.source),
          csvEscape(record.username),
          csvEscape(record.browser),
          csvEscape(record.title),
          csvEscape(record.url),
          record.visit_count || 0,
          record.last_visit_time ? `"${new Date(record.last_visit_time).toISOString()}"` : '""'
        ],
        filename: `chromium_history_${new Date().toISOString().split('T')[0]}.csv`,
        onProgress: setExportProgress,
      });
      if (exported === 0) {
        alert('No data to export');
      }
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

    if (urlFilter) {
      params.set('url', urlFilter);
    }

    params.set('sort_column', sortColumn);
    params.set('sort_direction', sortDirection);

    setSearchParams(params, { replace: true });
  }, [sourceFilter, usernameFilter, browserFilter, urlFilter, sortColumn, sortDirection, setSearchParams]);


  // The parent renders the button once per effect run below; always export with the latest filters
  const exportRef = useRef(handleExportCSV);
  useEffect(() => {
    exportRef.current = handleExportCSV;
  });

  // Provide the CSV download button to the parent component
  useEffect(() => {
    if (renderActions) {
      renderActions(
        <button
          onClick={() => exportRef.current()}
          disabled={isExporting || isLoading || totalCount === 0}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white text-sm font-medium rounded-lg transition-colors disabled:cursor-not-allowed"
          title={totalCount === 0 ? "No data to export" : `Export ${totalCount.toLocaleString()} records to CSV`}
        >
          {isExporting ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              <span>Exporting{exportProgress > 0 ? ` ${exportProgress.toLocaleString()} / ${totalCount.toLocaleString()}` : '...'}</span>
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
  }, [renderActions, isExporting, exportProgress, isLoading, totalCount]);

  // Memoized so typing in a filter box doesn't re-render every visible row
  const itemData = useMemo(() => ({ records }), [records]);
  const pagedRows = useMemo(() => records.map((record, index) => (
    <Row
      key={`${record.originating_object_id}-${index}`}
      index={index}
      style={{ height: ROW_HEIGHT }}
      data={{
        records,
        navigate
      }}
    />
  )), [records, navigate]);

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
            <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <input
              type="text"
              placeholder="Filter by URL"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={urlFilter}
              onChange={(e) => {
                setUrlFilter(e.target.value);
                setCurrentPage(1);
              }}
            />
          </div>

          <span className="text-sm text-gray-600 dark:text-gray-400">
            {totalCount.toLocaleString()} record{totalCount !== 1 ? 's' : ''} found
            {isPaginated && ` (showing ${records.length})`}
          </span>
        </div>
      </div>

      {/* Headers */}
      <div className="flex border-b dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        <SortableHeader
          column="originating_object_id"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-24"
        >
          Object ID
        </SortableHeader>
        <SortableHeader
          column="source"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-20"
        >
          Source
        </SortableHeader>
        <SortableHeader
          column="username"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-24"
        >
          Username
        </SortableHeader>
        <SortableHeader
          column="browser"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-20"
        >
          Browser
        </SortableHeader>
        <SortableHeader
          column="title"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-60"
        >
          Title
        </SortableHeader>
        <SortableHeader
          column="visit_count"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-16"
        >
          Visits
        </SortableHeader>
        <SortableHeader
          column="last_visit_time"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-44"
        >
          Last Visit
        </SortableHeader>
        <SortableHeader
          column="url"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-grow px-4"
        >
          URL
        </SortableHeader>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2 m-4">
          <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
          <div className="flex flex-col">
            <span className="text-red-600 dark:text-red-400">Error loading chromium history: {error}</span>
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
      {!isLoading && !error && records.length === 0 && totalCount === 0 && (
        <div className="flex flex-col items-center justify-center p-12 text-center">
          <div className="text-gray-500 dark:text-gray-400 mb-6">
            <Search className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <h3 className="text-lg font-medium mb-2">No Chromium history found</h3>
            <p className="max-w-md mx-auto">
              No Chromium history records match your current filters.
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
                {pagedRows}
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
                    itemData={itemData}
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

export default ChromiumHistory;
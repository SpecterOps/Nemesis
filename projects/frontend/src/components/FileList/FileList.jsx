import Tooltip from '@/components/shared/Tooltip2';
import { useTriageMode } from '@/contexts/TriageModeContext';
import { useUser } from '@/contexts/UserContext';
import { createClient } from 'graphql-ws';
import { AlertTriangle, ChevronDown, ChevronUp, ChevronLeft, ChevronRight, Clock, Eye, Search, Tag, X } from 'lucide-react';
import React, { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import AutoSizer from 'react-virtualized-auto-sizer';
import { FixedSizeList as List } from 'react-window';
import { CONFIG_FILE_EXTENSIONS, OFFICE_EXTENSIONS, SOURCE_CODE_EXTENSIONS } from './fileExtensions';


const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${wsProtocol}//${window.location.host}/hasura/v1/graphql`;

const wsClient = createClient({
  url: wsUrl,
  connectionParams: {
    headers: {
      'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
    },
  },
});

const ROW_HEIGHT = 48;
const PAGINATION_THRESHOLD = 10000;
const PAGE_SIZE = 100;

export const formatFileSize = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
};


const Row = React.memo(({ index, style, data }) => {
  const {
    files,
    isTriageMode,
    selectedIndex,
    selectedFiles,
    handleRowClick,
    navigate,
    username
  } = data;
  const file = files[index];

  // Prevent tooltip clicks from triggering row navigation
  const handleTooltipClick = (e) => {
    e.stopPropagation();
  };

  return (
    <div
      style={style}
      className={`
        flex items-center border-b dark:border-gray-700 cursor-pointer transition-colors
        dark:bg-dark-secondary hover:bg-gray-100 dark:hover:bg-gray-700
        ${selectedFiles.has(file.object_id) ? '!bg-blue-100 dark:!bg-blue-900/30' : ''}
        ${isTriageMode && index === selectedIndex ? '!bg-blue-50 dark:!bg-blue-900/20' : ''}
      `}
      onClick={(e) => handleRowClick(e, file, index)}
    >
      {isTriageMode && (
        <div className="w-8 px-2 text-center text-gray-400">
          {index === selectedIndex ? '✓' : ''}
        </div>
      )}
      <div className="px-2 flex-shrink-0 w-32 text-sm text-gray-500 dark:text-gray-400 text-left">
        <Tooltip
          content={
            <div onClick={handleTooltipClick} className="select-text">
              {file.agent_id}
            </div>
          }
          side="top"
          align="start"
        >
          <span className="block truncate">{file.agent_id}</span>
        </Tooltip>
      </div>
      <div className="px-2 flex-shrink-0 w-40 text-sm text-gray-500 dark:text-gray-400 text-left">
        <Tooltip
          content={
            <div onClick={handleTooltipClick} className="select-text">
              {file.source || 'Unknown'}
            </div>
          }
          side="top"
          align="start"
        >
          <span className="block truncate">{file.source || 'Unknown'}</span>
        </Tooltip>
      </div>
      <div className="px-2 flex-shrink-0 w-24 text-sm text-gray-500 dark:text-gray-400 text-left">{formatFileSize(file.size)}</div>
      <div className="px-2 flex-shrink-0 w-44 text-sm text-gray-500 dark:text-gray-400 text-left">{new Date(file.timestamp).toLocaleString()}</div>
      <div className="px-2 flex-shrink-0 w-48 text-sm text-sm text-gray-500 dark:text-gray-400 text-left">
        <Tooltip
          content={
            <div onClick={handleTooltipClick} className="select-text">
              {file.magic_type || 'Unknown'}
            </div>
          }
          side="top"
        >
          <span className="inline-block max-w-full px-2 py-1 rounded-full text-xs bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300 truncate">
            {file.magic_type || 'Unknown'}
          </span>
        </Tooltip>
      </div>
      <div className="px-2 flex-shrink-0 w-12 text-sm flex items-center justify-center h-full text-center">
        <span className={`inline-flex items-center justify-center min-w-[24px] h-6 px-2 rounded-full text-xs ${file.findingsByObjectId_aggregate.aggregate.count > 0 ? 'bg-red-100 dark:bg-red-900/20 text-red-600 dark:text-red-400' : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'}`}>
          {file.findingsByObjectId_aggregate.aggregate.count || 0}
        </span>
      </div>
      <div className="px-6 flex-grow text-sm text-gray-500 dark:text-gray-400 truncate text-left relative">
        {!file.files_view_histories?.some(h => h.username === username) && (
          <div className="absolute left top-1/2 transform -translate-y-1/2 w-1.5 h-1.5 bg-blue-400 opacity-60 rounded-full" title="Unviewed by you"></div>
        )}
        <Tooltip
          content={
            <div onClick={handleTooltipClick} className="select-text">
              {file.path}
            </div>
          }
          side="top"
          align="start"
          maxWidth="full"
        >
          <span className="ml-3">{file.path}</span>
        </Tooltip>
      </div>
    </div>
  );
});

// Sortable header component
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

// Pagination controls component
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


const FileList = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [files, setFiles] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const { isTriageMode, setIsTriageMode, selectedIndex, setSelectedIndex } = useTriageMode();
  const [selectedFiles, setSelectedFiles] = useState(new Set());
  const selectedRowRef = useRef(null);
  const lastDirection = useRef('down');
  const { username } = useUser();

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [isPaginated, setIsPaginated] = useState(false);

  // Filter states initialized from URL parameters
  const [fileTypeFilter, setFileTypeFilter] = useState(() => searchParams.get('type') || 'all');
  const [sourceFilter, setSourceFilter] = useState(() => searchParams.get('source') || '');
  const [pathFilter, setPathFilter] = useState(() => searchParams.get('path') || '');
  const [objectIdFilter, setObjectIdFilter] = useState(() => searchParams.get('object_id') || '');
  const [sortColumn, setSortColumn] = useState(() => searchParams.get('sort_column') || 'timestamp');
  const [sortDirection, setSortDirection] = useState(() => searchParams.get('sort_direction') || 'desc');
  const [viewFilter, setViewFilter] = useState(() => searchParams.get('view_state') || 'all');
  const [showOnlyWithFindings, setShowOnlyWithFindings] = useState(false);

  const [availableTags, setAvailableTags] = useState([]);
  const [selectedTag, setSelectedTag] = useState('');
  const [isTagDropdownOpen, setIsTagDropdownOpen] = useState(false);
  const tagDropdownRef = useRef(null);

  // Calculate total pages
  const totalPages = Math.ceil(totalCount / PAGE_SIZE);

  // Handle column sorting
  const handleSort = (column, direction) => {
    setSortColumn(column);
    setSortDirection(direction);
    setCurrentPage(1); // Reset to first page on sort change
  };

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setCurrentPage(newPage);
      setSelectedIndex(-1); // Reset selection when changing pages
      setSelectedFiles(new Set());
    }
  };

  const handleRowClick = (e, file, index) => {
    if (isTriageMode) {
      const actualIndex = isPaginated ? (currentPage - 1) * PAGE_SIZE + index : index;

      if (e.shiftKey && selectedIndex !== -1) {
        // For paginated mode, only allow shift selection within current page
        if (isPaginated) {
          const pageStartIndex = (currentPage - 1) * PAGE_SIZE;
          const pageEndIndex = Math.min(pageStartIndex + PAGE_SIZE, totalCount);

          if (selectedIndex >= pageStartIndex && selectedIndex < pageEndIndex) {
            const start = Math.min(selectedIndex - pageStartIndex, index);
            const end = Math.max(selectedIndex - pageStartIndex, index);
            const newSelection = new Set(selectedFiles);
            for (let i = start; i <= end; i++) {
              newSelection.add(files[i].object_id);
            }
            setSelectedFiles(newSelection);
          }
        } else {
          const start = Math.min(selectedIndex, actualIndex);
          const end = Math.max(selectedIndex, actualIndex);
          const newSelection = new Set(selectedFiles);
          for (let i = start; i <= end; i++) {
            newSelection.add(files[i].object_id);
          }
          setSelectedFiles(newSelection);
        }
      } else if (e.ctrlKey || e.metaKey) {
        const newSelection = new Set(selectedFiles);
        if (newSelection.has(file.object_id)) {
          newSelection.delete(file.object_id);
        } else {
          newSelection.add(file.object_id);
        }
        setSelectedFiles(newSelection);
      } else {
        setSelectedFiles(new Set([file.object_id]));
      }
      setSelectedIndex(actualIndex);
    } else if (!e.target.closest('button')) {
      // Get current search params to preserve them
      const currentSearch = searchParams.toString();
      navigate(`/files/${file.object_id}${currentSearch ? `?${currentSearch}` : ''}`);
    }
  };

  const toggleDropdown = () => {
    setIsTagDropdownOpen(!isTagDropdownOpen);
  };

  const listRef = useRef();
  useEffect(() => {
    if (listRef.current && isTriageMode && selectedIndex >= 0 && !isPaginated) {
      listRef.current.scrollToItem(selectedIndex, 'center');
    }
  }, [selectedIndex, isTriageMode, isPaginated]);

  // Build where clause for queries
  const buildWhereClause = () => {
    const conditions = [];

    // Base condition for files
    conditions.push({
      _or: [
        { originating_object_id: { _is_null: true } },
        {
          _and: [
            { originating_object_id: { _is_null: false } },
            { nesting_level: { _is_null: false } },
            { nesting_level: { _gt: 0 } }
          ]
        }
      ]
    });

    // Add filter conditions
    if (showOnlyWithFindings) {
      conditions.push({
        findingsByObjectId_aggregate: {
          count: {
            predicate: { _gt: 0 }
          }
        }
      });
    }

    if (objectIdFilter) {
      conditions.push({ object_id: { _eq: objectIdFilter } });
    }

    if (fileTypeFilter === 'plaintext') {
      conditions.push({ is_plaintext: { _eq: true } });
    } else if (fileTypeFilter === 'binary') {
      conditions.push({ is_plaintext: { _eq: false } });
    } else if (fileTypeFilter === 'source') {
      conditions.push({ extension: { _in: SOURCE_CODE_EXTENSIONS } });
    } else if (fileTypeFilter === 'office') {
      conditions.push({ extension: { _in: OFFICE_EXTENSIONS } });
    } else if (fileTypeFilter === 'config') {
      conditions.push({ extension: { _in: CONFIG_FILE_EXTENSIONS } });
    }

    if (sourceFilter) {
      conditions.push({ source: { _ilike: sourceFilter.replace(/\*/g, '%') } });
    }

    if (pathFilter) {
      conditions.push({ path: { _ilike: pathFilter.replace(/\*/g, '%') } });
    }

    if (selectedTag) {
      conditions.push({ file_tags: { _contains: [selectedTag] } });
    }

    if (viewFilter !== 'all') {
      if (viewFilter === 'unviewed') {
        conditions.push({
          _not: {
            files_view_histories: {}
          }
        });
      } else if (viewFilter === 'unviewed_by_me') {
        conditions.push({
          _not: {
            files_view_histories: {
              username: { _eq: username }
            }
          }
        });
      }
    }

    return conditions.length > 1 ? { _and: conditions } : conditions[0];
  };

  // Build order by clause
  const buildOrderByClause = () => {
    const orderBy = {};

    switch (sortColumn) {
      case 'agent_id':
        orderBy.agent_id = sortDirection;
        break;
      case 'source':
        orderBy.source = sortDirection;
        break;
      case 'size':
        orderBy.size = sortDirection;
        break;
      case 'timestamp':
        orderBy.timestamp = sortDirection;
        break;
      case 'magic_type':
        orderBy.magic_type = sortDirection;
        break;
      case 'findings':
        orderBy.findingsByObjectId_aggregate = { count: sortDirection };
        break;
      case 'path':
        orderBy.path = sortDirection;
        break;
      default:
        orderBy.timestamp = sortDirection;
    }

    return orderBy;
  };

  useEffect(() => {
    const fetchAvailableTags = async () => {
      const query = {
        query: `
          query GetAllTags {
            file_tags {
              tag_name
            }
          }
        `
      };

      try {
        const response = await fetch('/hasura/v1/graphql', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
          },
          body: JSON.stringify(query)
        });

        if (!response.ok) throw new Error('Network error');

        const result = await response.json();
        if (result.errors) throw new Error(result.errors[0].message);

        const tags = result.data.file_tags.map(tag => tag.tag_name);
        setAvailableTags(tags);
      } catch (err) {
        console.error('Failed to fetch available tags:', err);
      }
    };

    fetchAvailableTags();
  }, []);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (tagDropdownRef.current && !tagDropdownRef.current.contains(event.target)) {
        console.log("Click outside detected");
        setIsTagDropdownOpen(false);
      }
    };

    // Only add the listener if the dropdown is open
    if (isTagDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => {
        document.removeEventListener('mousedown', handleClickOutside);
      };
    }
    return () => { }; // Empty cleanup function when condition isn't met
  }, [isTagDropdownOpen]);

  // Update URL parameters when filters change
  useEffect(() => {
    const params = new URLSearchParams();

    if (fileTypeFilter !== 'all') {
      params.set('type', fileTypeFilter);
    }

    if (sourceFilter) {
      params.set('source', sourceFilter);
    }

    if (pathFilter) {
      params.set('path', pathFilter);
    }

    params.set('view_state', viewFilter);

    if (objectIdFilter) {
      params.set('object_id', objectIdFilter);
    }

    if (selectedTag) {
      params.set('tag', selectedTag);
    }

    // Add sort column and direction to URL params
    params.set('sort_column', sortColumn);
    params.set('sort_direction', sortDirection);

    // Add findings filter to URL params
    if (showOnlyWithFindings) {
      params.set('findings', 'true');
    }

    // Use replace: true to avoid adding to browser history for every filter change
    setSearchParams(params, { replace: true });
  }, [fileTypeFilter, sourceFilter, pathFilter, viewFilter, objectIdFilter, selectedTag, sortColumn, sortDirection, showOnlyWithFindings]);

  // Removed the useEffect that was syncing from URL params to avoid circular updates

  const handleBulkRecordFileView = (value) => {
    selectedFiles.forEach(fileId => {
      recordFileView(fileId);
    });
    setSelectedFiles(new Set());
  };

  const recordFileView = async (objectId) => {
    console.log("Calling recordFileView for:", objectId);
    const mutation = {
      query: `
        mutation InsertFileView($object_id: uuid!, $username: String!) {
          insert_files_view_history_one(object: {
            object_id: $object_id,
            username: $username,
            automated: false
          }) {
            id
            timestamp
          }
        }
      `,
      variables: {
        object_id: objectId,
        username: username
      }
    };

    try {
      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(mutation)
      });

      if (!response.ok) throw new Error('Network response was not ok');

      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

    } catch (err) {
      console.error('Failed to record file view:', err);
    }
  };

  // Convert wildcard pattern to regex
  const wildcardToRegExp = (wildcard) => {
    const escapedWildcard = wildcard.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp('^' + escapedWildcard.replace(/\\\*/g, '.*') + '$');
  };

  // Scroll handling
  useEffect(() => {
    if (selectedRowRef.current && isTriageMode && selectedIndex >= 0) {
      const timer = setTimeout(() => {
        selectedRowRef.current.scrollIntoView({
          behavior: 'smooth',
          block: lastDirection.current === 'up' ? 'center' : 'end'
        });
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [selectedIndex, isTriageMode]);

  // keyboard controls
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Ignore keyboard shortcuts when focus is on an input or textarea element
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) {
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key === 'a') {
        e.preventDefault();
        if (isTriageMode) {
          // In paginated mode, only select files on current page
          const newSelection = new Set(files.map(f => f.object_id));
          setSelectedFiles(newSelection);
        }
        return;
      }

      if (e.key === 't' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        setIsTriageMode(prev => {
          const newMode = !prev;
          if (newMode && selectedIndex === -1) {
            setSelectedIndex(isPaginated ? (currentPage - 1) * PAGE_SIZE : 0);
          }
          return newMode;
        });
        return;
      }

      if (!isTriageMode) return;

      const filesLength = files.length;
      const currentPageSelectedIndex = isPaginated ? selectedIndex - (currentPage - 1) * PAGE_SIZE : selectedIndex;

      switch (e.key) {
        case 'ArrowUp':
          e.preventDefault();
          lastDirection.current = 'up';
          if (isPaginated) {
            if (currentPageSelectedIndex > 0) {
              setSelectedIndex(selectedIndex - 1);
            } else if (currentPage > 1) {
              handlePageChange(currentPage - 1);
              setSelectedIndex((currentPage - 2) * PAGE_SIZE + PAGE_SIZE - 1);
            }
          } else {
            if (e.shiftKey) {
              const prevIndex = Math.max(0, selectedIndex - 1);
              const newSelection = new Set(selectedFiles);
              newSelection.add(files[selectedIndex].object_id);
              newSelection.add(files[prevIndex].object_id);
              setSelectedFiles(newSelection);
              setSelectedIndex(prevIndex);
            } else {
              setSelectedIndex(prev => Math.max(0, prev - 1));
            }
          }
          break;
        case 'ArrowDown':
          e.preventDefault();
          lastDirection.current = 'down';
          if (isPaginated) {
            if (currentPageSelectedIndex < filesLength - 1) {
              setSelectedIndex(selectedIndex + 1);
            } else if (currentPage < totalPages) {
              handlePageChange(currentPage + 1);
              setSelectedIndex((currentPage) * PAGE_SIZE);
            }
          } else {
            if (e.shiftKey) {
              const nextIndex = Math.min(filesLength - 1, selectedIndex + 1);
              const newSelection = new Set(selectedFiles);
              newSelection.add(files[selectedIndex].object_id);
              newSelection.add(files[nextIndex].object_id);
              setSelectedFiles(newSelection);
              setSelectedIndex(nextIndex);
            } else {
              setSelectedIndex(prev => Math.min(filesLength - 1, prev + 1));
            }
          }
          break;
        case 'Escape':
          e.preventDefault();
          if (selectedFiles.size > 0) {
            setSelectedFiles(new Set());
          } else {
            setIsTriageMode(false);
            setSelectedIndex(-1);
          }
          break;
        case 'ArrowRight':
          e.preventDefault();
          if (selectedIndex >= 0 && currentPageSelectedIndex >= 0 && currentPageSelectedIndex < filesLength) {
            navigate(`/files/${files[currentPageSelectedIndex].object_id}`);
          }
          break;
        case 'v':
          e.preventDefault();
          if (selectedIndex >= 0 && currentPageSelectedIndex >= 0 && currentPageSelectedIndex < filesLength) {
            recordFileView(files[currentPageSelectedIndex].object_id);
          }
          break;
      }

      // Bulk triage shortcuts
      if (selectedFiles.size > 0) {
        switch (e.key) {
          case 'v':
            e.preventDefault();
            handleBulkRecordFileView();
            break;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isTriageMode, selectedIndex, files, navigate, setIsTriageMode, setSelectedIndex, selectedFiles, isPaginated, currentPage, totalPages]);

  // Handle maintained triage mode state
  useEffect(() => {
    if (location.state?.maintainTriageMode) {
      setIsTriageMode(true);
      if (location.state?.maintainSelectedIndex >= 0) {
        setSelectedIndex(location.state.maintainSelectedIndex);
      }
    }
  }, [location.state, setIsTriageMode, setSelectedIndex]);

  // Fetch data based on count
  useEffect(() => {
    const fetchData = async () => {
      setIsLoading(true);
      setError(null);

      try {
        // First, get the count
        const countQuery = {
          query: `
            query GetFileCount($where: files_enriched_bool_exp) {
              files_enriched_aggregate(where: $where) {
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

        const count = countResult.data.files_enriched_aggregate.aggregate.count;
        setTotalCount(count);
        setIsPaginated(count > PAGINATION_THRESHOLD);

        // Now fetch the actual data
        let dataQuery;
        if (count > PAGINATION_THRESHOLD) {
          // Paginated query
          dataQuery = {
            query: `
              query GetFilesPaginated($where: files_enriched_bool_exp, $limit: Int!, $offset: Int!, $order_by: [files_enriched_order_by!]) {
                files_enriched(
                  where: $where,
                  limit: $limit,
                  offset: $offset,
                  order_by: $order_by
                ) {
                  object_id
                  agent_id
                  source
                  file_name
                  size
                  path
                  timestamp
                  extension
                  magic_type
                  mime_type
                  is_plaintext
                  hashes
                  file_tags
                  findingsByObjectId_aggregate {
                    aggregate {
                      count
                    }
                  }
                  files_view_histories(
                    distinct_on: username
                    order_by: [{ username: asc }, { timestamp: desc }]
                  ) {
                    username
                    timestamp
                  }
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
              query GetFilesAll($where: files_enriched_bool_exp, $order_by: [files_enriched_order_by!]) {
                files_enriched(
                  where: $where,
                  order_by: $order_by
                ) {
                  object_id
                  agent_id
                  source
                  file_name
                  size
                  path
                  timestamp
                  extension
                  magic_type
                  mime_type
                  is_plaintext
                  hashes
                  file_tags
                  findingsByObjectId_aggregate {
                    aggregate {
                      count
                    }
                  }
                  files_view_histories(
                    distinct_on: username
                    order_by: [{ username: asc }, { timestamp: desc }]
                  ) {
                    username
                    timestamp
                  }
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

        setFiles(dataResult.data.files_enriched);
      } catch (err) {
        console.error('Error fetching files:', err);
        setError(err.message);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [currentPage, fileTypeFilter, sourceFilter, pathFilter, viewFilter, objectIdFilter, selectedTag, sortColumn, sortDirection, showOnlyWithFindings, username]);

  // Set up subscription (only for non-paginated mode)
  useEffect(() => {
    if (isPaginated) return; // Don't use subscriptions in paginated mode

    const subscription = {
      query: `
        subscription WatchFiles($where: files_enriched_bool_exp, $order_by: [files_enriched_order_by!]) {
          files_enriched(
            where: $where,
            order_by: $order_by
          ) {
            object_id
            agent_id
            source
            file_name
            size
            path
            timestamp
            extension
            magic_type
            mime_type
            is_plaintext
            hashes
            file_tags
            findingsByObjectId_aggregate {
              aggregate {
                count
              }
            }
            files_view_histories(
              distinct_on: username
              order_by: [{ username: asc }, { timestamp: desc }]
            ) {
              username
              timestamp
            }
          }
        }
      `,
      variables: {
        where: buildWhereClause(),
        order_by: buildOrderByClause()
      }
    };

    let unsubscribe;

    (async () => {
      unsubscribe = wsClient.subscribe(
        subscription,
        {
          next: ({ data }) => {
            if (data?.files_enriched) {
              setFiles(data.files_enriched);
              setTotalCount(data.files_enriched.length);
            }
          },
          error: (err) => {
            console.error('Subscription error:', err);
            setError('Error in real-time updates. Please refresh the page.');
          },
          complete: () => {
            // console.log('Subscription completed');
          },
        },
      );
    })();

    return () => {
      if (unsubscribe) {
        unsubscribe();
      }
    };
  }, [isPaginated, fileTypeFilter, sourceFilter, pathFilter, viewFilter, objectIdFilter, selectedTag, sortColumn, sortDirection, showOnlyWithFindings, username]);

  return (
    <div className="bg-white dark:bg-dark-secondary rounded-lg shadow">
      {isTriageMode && (
        <div className="p-1 bg-blue-50 dark:bg-blue-900/20 border-b dark:border-gray-700">
          <p className="text-sm text-blue-600 dark:text-blue-400">
            Triage Mode Active - Use ↑↓ to navigate{isPaginated ? ' (across pages)' : ''}. Use Shift+↑↓ to select multiple rows. Ctrl/Cmd+A to select all{isPaginated ? ' on current page' : ''}.
            'v' to mark{selectedFiles.size > 0 ? ' selected files' : ''} as viewed,
            or ESC to exit
          </p>
        </div>
      )}

      {/* Filters */}
      <div className="p-2 border-b dark:border-gray-700 overflow-x-auto">
        <div className="flex items-center space-x-4 min-w-max">
          <div className="flex items-center space-x-2">
            <Eye className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <select
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={viewFilter}
              onChange={(e) => {
                setViewFilter(e.target.value);
                setCurrentPage(1);
              }}
            >
              <option value="unviewed">Unviewed Files</option>
              <option value="unviewed_by_me">Files Unviewed by Me</option>
              <option value="all">All Files</option>
            </select>
          </div>

          <Tooltip content={showOnlyWithFindings ? "Click to show all files" : "Click to show only files with findings"}>
            <button
              className="flex items-center space-x-2 px-3 py-2 border dark:border-gray-700 rounded hover:bg-gray-100 dark:hover:bg-gray-700"
              onClick={() => {
                setShowOnlyWithFindings(!showOnlyWithFindings);
                setCurrentPage(1);
              }}
            >
              <AlertTriangle className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              <span className="text-sm text-gray-700 dark:text-gray-300">
                (Findings) {showOnlyWithFindings ? "Files With Findings" : "All Files"}
              </span>
            </button>
          </Tooltip>

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
              placeholder="Filter by path (e.g. *.txt)"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={pathFilter}
              onChange={(e) => {
                setPathFilter(e.target.value);
                setCurrentPage(1);
              }}
            />
          </div>

          <div className="relative" ref={tagDropdownRef}>
            <button
              className="flex items-center space-x-2 px-3 py-2 border dark:border-gray-700 rounded hover:bg-gray-100 dark:hover:bg-gray-700"
              onClick={toggleDropdown}
            >
              <Tag className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              <span className="text-sm text-gray-700 dark:text-gray-300">
                {selectedTag ? selectedTag : "Filter by Tag"}
              </span>
              {selectedTag ? (
                <span
                  className="ml-2 cursor-pointer text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedTag('');
                    setCurrentPage(1);
                  }}
                >
                  <X className="w-4 h-4" />
                </span>
              ) : (
                <ChevronDown className="w-4 h-4 text-gray-500 dark:text-gray-400" />
              )}
            </button>

            {isTagDropdownOpen && (
              <div className="fixed min-w-[250px] shadow-xl border border-gray-200 dark:border-gray-700 rounded-md bg-white dark:bg-gray-800 py-1"
                style={{
                  top: `${(tagDropdownRef.current?.getBoundingClientRect().bottom || 0) + window.scrollY + 5}px`,
                  left: `${(tagDropdownRef.current?.getBoundingClientRect().left || 0) + window.scrollX}px`,
                  zIndex: 9999
                }}>
                <div className="max-h-60 overflow-y-auto">
                  <button
                    className={`w-full text-left px-4 py-2 text-sm ${!selectedTag ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'}`}
                    onClick={() => {
                      setSelectedTag('');
                      setCurrentPage(1);
                      setIsTagDropdownOpen(false);
                    }}
                  >
                    Show All Files
                  </button>

                  {availableTags.length > 0 ? (
                    availableTags.map((tag) => (
                      <button
                        key={tag}
                        className={`w-full text-left px-4 py-2 text-sm ${selectedTag === tag ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'}`}
                        onClick={() => {
                          setSelectedTag(tag);
                          setCurrentPage(1);
                          setIsTagDropdownOpen(false);
                        }}
                      >
                        {tag}
                      </button>
                    ))
                  ) : (
                    <div className="px-4 py-2 text-sm text-gray-500 dark:text-gray-400 italic">
                      No tags available
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          <span className="text-sm text-gray-600 dark:text-gray-400">
            {totalCount.toLocaleString()} file{totalCount !== 1 ? 's' : ''} found
            {isPaginated && ` (showing ${files.length})`}
          </span>
        </div>
      </div>

      {/* Headers */}
      <div className="flex border-b dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        {isTriageMode && (
          <div className="w-8 px-2 py-2"></div>
        )}
        <SortableHeader
          column="agent_id"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-32"
        >
          Agent ID
        </SortableHeader>
        <SortableHeader
          column="source"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-40"
        >
          Source
        </SortableHeader>
        <SortableHeader
          column="size"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-24"
        >
          Size
        </SortableHeader>
        <SortableHeader
          column="timestamp"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-44"
        >
          Time Uploaded
        </SortableHeader>
        <SortableHeader
          column="magic_type"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-48"
        >
          Magic Type
        </SortableHeader>
        <SortableHeader
          column="findings"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-shrink-0 w-12 justify-center"
        >
          Findings
        </SortableHeader>
        <SortableHeader
          column="path"
          currentSort={sortColumn}
          currentDirection={sortDirection}
          onSort={handleSort}
          className="flex-grow px-4"
        >
          Path
        </SortableHeader>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2 m-4">
          <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
          <div className="flex flex-col">
            <span className="text-red-600 dark:text-red-400">Error loading files: {error}</span>
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
      {!isLoading && !error && files.length === 0 && totalCount === 0 && (
        <div className="flex flex-col items-center justify-center p-12 text-center">
          <div className="text-gray-500 dark:text-gray-400 mb-6">
            {totalCount > 0 ? (
              <>
                <Search className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium mb-2">No matching files found</h3>
                <p className="max-w-md mx-auto">
                  No files match your current filters.
                </p>
              </>
            ) : (
              <>
                <AlertTriangle className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium mb-2">No files found</h3>
                <p className="max-w-md mx-auto mb-4">
                  No files have been ingested into Nemesis yet.
                </p>
                <div>
                  <Link
                    to="/upload"
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors inline-flex items-center"
                  >
                    <span className="mr-2">Upload Files</span>
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-upload">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                      <polyline points="17 8 12 3 7 8" />
                      <line x1="12" y1="3" x2="12" y2="15" />
                    </svg>
                  </Link>
                </div>
              </>
            )}
          </div>
          {totalCount > 0 && (
            <Link
              to="/files?view_state=all"
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors inline-flex items-center"
            >
              <span>Show All Files</span>
            </Link>
          )}
        </div>
      )}

      {/* List or Table based on pagination */}
      {!isLoading && !error && files.length > 0 && (
        <>
          {isPaginated ? (
            // Paginated table view
            <div className="overflow-x-auto">
              <div className="min-w-full">
                {files.map((file, index) => (
                  <Row
                    key={file.object_id}
                    index={index}
                    style={{ height: ROW_HEIGHT }}
                    data={{
                      files,
                      isTriageMode,
                      selectedIndex: selectedIndex - (currentPage - 1) * PAGE_SIZE,
                      selectedFiles,
                      handleRowClick,
                      navigate,
                      username
                    }}
                  />
                ))}
              </div>
            </div>
          ) : (
            // Virtualized list view
            <div className="h-[calc(100vh-150px)]">
              <AutoSizer>
                {({ height, width }) => (
                  <List
                    ref={listRef}
                    height={height}
                    width={width}
                    itemCount={files.length}
                    itemSize={ROW_HEIGHT}
                    itemData={{
                      files,
                      isTriageMode,
                      selectedIndex,
                      selectedFiles,
                      handleRowClick,
                      navigate,
                      username
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

export default FileList;
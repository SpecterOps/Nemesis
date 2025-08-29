import React, { useCallback, useEffect, useState, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  CheckCircle,
  Clock,
  FileArchive,
  Server,
  Download,
  AlertCircle,
  Search,
  Filter,
  ArrowUpDown,
  X,
  HardDrive,
  Activity
} from 'lucide-react';

// Custom tooltip component
const CustomTooltip = ({ children, content }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [position, setPosition] = useState('top');
  const tooltipRef = useRef(null);
  const containerRef = useRef(null);

  const updatePosition = useCallback(() => {
    if (containerRef.current && tooltipRef.current) {
      const containerRect = containerRef.current.getBoundingClientRect();
      const viewportHeight = window.innerHeight;
      const viewportWidth = window.innerWidth;

      // Check if there's enough space above
      const spaceAbove = containerRect.top;
      const spaceBelow = viewportHeight - containerRect.bottom;
      const spaceOnRight = viewportWidth - containerRect.right;
      const tooltipWidth = 300;
      const tooltipHeight = 100;

      if (spaceAbove > tooltipHeight) {
        setPosition('top');
      } else if (spaceBelow > tooltipHeight) {
        setPosition('bottom');
      } else if (spaceOnRight > tooltipWidth) {
        setPosition('right');
      } else {
        setPosition('left');
      }
    }
  }, []);

  const handleMouseEnter = useCallback(() => {
    setIsVisible(true);
    setTimeout(updatePosition, 0);
  }, [updatePosition]);

  const handleMouseLeave = useCallback(() => {
    setIsVisible(false);
  }, []);

  return (
    <div
      ref={containerRef}
      className="relative"
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      {children}
      {isVisible && (
        <div
          ref={tooltipRef}
          className={`absolute z-50 p-3 text-sm bg-gray-800 text-white rounded shadow-lg whitespace-nowrap ${
            position === 'top'
              ? 'bottom-full mb-2 left-1/2 transform -translate-x-1/2'
              : position === 'bottom'
              ? 'top-full mt-2 left-1/2 transform -translate-x-1/2'
              : position === 'right'
              ? 'left-full ml-2 top-1/2 transform -translate-y-1/2'
              : 'right-full mr-2 top-1/2 transform -translate-y-1/2'
          }`}
        >
          {content}
        </div>
      )}
    </div>
  );
};

// Progress circle component
const ProgressCircle = ({ percentage, size = 60, strokeWidth = 6, label, tooltip }) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const strokeDasharray = circumference;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  const getColor = (percentage) => {
    if (percentage === 100) return '#10B981'; // green
    if (percentage >= 75) return '#3B82F6'; // blue
    if (percentage >= 50) return '#F59E0B'; // amber
    if (percentage >= 25) return '#EF4444'; // red
    return '#6B7280'; // gray
  };

  const content = (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          className="transform -rotate-90"
          width={size}
          height={size}
        >
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#E5E7EB"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={getColor(percentage)}
            strokeWidth={strokeWidth}
            strokeDasharray={strokeDasharray}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-300 ease-in-out"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-xs font-semibold text-gray-700 dark:text-gray-300">
            {Math.round(percentage)}%
          </span>
        </div>
      </div>
      <span className="text-xs text-gray-600 dark:text-gray-400 mt-1 text-center">{label}</span>
    </div>
  );

  return tooltip ? (
    <CustomTooltip content={tooltip}>
      {content}
    </CustomTooltip>
  ) : content;
};

// Status badge component
const StatusBadge = ({ status }) => {
  const getStatusConfig = (status) => {
    switch (status) {
      case 'completed':
        return { icon: CheckCircle, className: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200', label: 'Completed' };
      case 'processing':
        return { icon: Activity, className: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200', label: 'Processing' };
      case 'submitted':
        return { icon: Clock, className: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200', label: 'Submitted' };
      case 'failed':
        return { icon: AlertTriangle, className: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200', label: 'Failed' };
      default:
        return { icon: AlertCircle, className: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200', label: status };
    }
  };

  const { icon: Icon, className, label } = getStatusConfig(status);

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${className}`}>
      <Icon className="w-3 h-3 mr-1" />
      {label}
    </span>
  );
};

// Container card component
const ContainerCard = ({ container }) => {
  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  const getProcessingTime = () => {
    if (!container.processing_started_at) return 'Not started';

    const start = new Date(container.processing_started_at);
    const end = container.processing_completed_at ?
      new Date(container.processing_completed_at) :
      new Date();

    const diffMs = end - start;
    const diffMinutes = Math.floor(diffMs / 60000);
    const diffSeconds = Math.floor((diffMs % 60000) / 1000);

    if (diffMinutes > 0) {
      return `${diffMinutes}m ${diffSeconds}s`;
    }
    return `${diffSeconds}s`;
  };

  const fileProgressPercentage = container.total_files_extracted > 0 ?
    (container.workflows_completed / container.total_files_extracted) * 100 : 0;

  const byteProgressPercentage = container.total_bytes_extracted > 0 ?
    (container.total_bytes_processed / container.total_bytes_extracted) * 100 : 0;

  return (
    <div className="flex-shrink-0 w-80 bg-white dark:bg-gray-800 rounded-lg shadow-md border border-gray-200 dark:border-gray-700 p-4 mx-2">
      {/* Header */}
      <div className="mb-3">
        <div className="flex items-center space-x-2 mb-2">
          <FileArchive className="h-5 w-5 text-blue-500 flex-shrink-0" />
          <div className="min-w-0 flex-1">
            <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate" title={container.original_filename || 'Unknown File'}>
              {container.original_filename || 'Unknown File'}
            </h3>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {container.container_type}
            </p>
          </div>
        </div>
        <div className="flex justify-end">
          <StatusBadge status={container.status} />
        </div>
      </div>

      {/* Metadata */}
      <div className="space-y-2 mb-4">
        <div className="flex justify-between text-xs">
          <span className="text-gray-500 dark:text-gray-400">Agent:</span>
          <span className="text-gray-900 dark:text-gray-100 font-mono">{container.agent_id || 'N/A'}</span>
        </div>
        <div className="flex justify-between text-xs">
          <span className="text-gray-500 dark:text-gray-400">Source:</span>
          <span className="text-gray-900 dark:text-gray-100 truncate ml-2">{container.source || 'N/A'}</span>
        </div>
        <div className="flex justify-between text-xs">
          <span className="text-gray-500 dark:text-gray-400">Container ID:</span>
          <span className="text-gray-900 dark:text-gray-100 font-mono">{container.container_id || 'N/A'}</span>
        </div>
        <div className="flex justify-between text-xs">
          <span className="text-gray-500 dark:text-gray-400">Size:</span>
          <span className="text-gray-900 dark:text-gray-100">{formatBytes(container.original_size || 0)}</span>
        </div>
        <div className="flex justify-between text-xs">
          <span className="text-gray-500 dark:text-gray-400">Submitted:</span>
          <span className="text-gray-900 dark:text-gray-100">{formatDate(container.submitted_at)}</span>
        </div>
        {container.processing_completed_at && (
          <div className="flex justify-between text-xs">
            <span className="text-gray-500 dark:text-gray-400">Completed:</span>
            <span className="text-gray-900 dark:text-gray-100">{formatDate(container.processing_completed_at)}</span>
          </div>
        )}
        <div className="flex justify-between text-xs">
          <span className="text-gray-500 dark:text-gray-400">Processing Time:</span>
          <span className="text-gray-900 dark:text-gray-100">{getProcessingTime()}</span>
        </div>
      </div>

      {/* Progress Section */}
      <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
        <div className="flex justify-around items-center mb-3">
          <ProgressCircle
            percentage={fileProgressPercentage}
            label="Processed Files"
            tooltip={
              <div className="space-y-1">
                <div className="font-medium">File Processing Progress</div>
                <div>Processed: {container.workflows_completed?.toLocaleString() || 0}</div>
                <div>Total Extracted: {container.total_files_extracted?.toLocaleString() || 0}</div>
                <div>Progress: {Math.round(fileProgressPercentage)}%</div>
              </div>
            }
          />

          <ProgressCircle
            percentage={byteProgressPercentage}
            label="Processed Bytes"
            tooltip={
              <div className="space-y-1">
                <div className="font-medium">Byte Processing Progress</div>
                <div>Processed: {formatBytes(container.total_bytes_processed || 0)}</div>
                <div>Total Extracted: {formatBytes(container.total_bytes_extracted || 0)}</div>
                <div>Progress: {Math.round(byteProgressPercentage)}%</div>
              </div>
            }
          />
        </div>

        {/* Failed workflows counter */}
        {container.workflows_failed > 0 && (
          <div className="flex items-center justify-center space-x-2 bg-red-50 dark:bg-red-900/20 rounded p-2">
            <AlertTriangle className="h-4 w-4 text-red-500" />
            <span className="text-sm text-red-600 dark:text-red-400">
              {container.workflows_failed} Failed File Workflows
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

// Filter and sort controls
const FilterControls = ({ filters, onFilterChange, sortBy, sortOrder, onSortChange }) => {
  const [showFilters, setShowFilters] = useState(false);

  const sortOptions = [
    { value: 'submitted_at', label: 'Time Submitted' },
    { value: 'original_filename', label: 'File Path' },
    { value: 'agent_id', label: 'Agent ID' },
    { value: 'source', label: 'Source' },
    { value: 'status', label: 'Status' },
    { value: 'original_size', label: 'File Size' }
  ];

  const statusOptions = ['processing', 'extracted', 'workflows_complete', 'failed'];

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4 mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Container Processing</h2>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="flex items-center space-x-1 px-3 py-2 text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-200 dark:hover:bg-gray-600"
          >
            <Filter className="h-4 w-4" />
            <span>Filters</span>
          </button>

          <div className="flex items-center space-x-2">
            <select
              value={sortBy}
              onChange={(e) => onSortChange(e.target.value, sortOrder)}
              className="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300"
            >
              {sortOptions.map(option => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>

            <button
              onClick={() => onSortChange(sortBy, sortOrder === 'asc' ? 'desc' : 'asc')}
              className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
            >
              <ArrowUpDown className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {showFilters && (
        <div className="grid grid-cols-1 md:grid-cols-6 gap-4 pt-4 border-t border-gray-200 dark:border-gray-700">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              File Path
            </label>
            <input
              type="text"
              value={filters.original_filename || ''}
              onChange={(e) => onFilterChange('original_filename', e.target.value)}
              placeholder="Filter by filename..."
              className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Agent ID
            </label>
            <input
              type="text"
              value={filters.agent_id || ''}
              onChange={(e) => onFilterChange('agent_id', e.target.value)}
              placeholder="Filter by agent..."
              className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Source
            </label>
            <input
              type="text"
              value={filters.source || ''}
              onChange={(e) => onFilterChange('source', e.target.value)}
              placeholder="Filter by source..."
              className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Container ID
            </label>
            <input
              type="text"
              value={filters.container_id || ''}
              onChange={(e) => onFilterChange('container_id', e.target.value)}
              placeholder="Enter complete UUID..."
              className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Status
            </label>
            <select
              value={filters.status || ''}
              onChange={(e) => onFilterChange('status', e.target.value)}
              className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300"
            >
              <option value="">All statuses</option>
              {statusOptions.map(status => (
                <option key={status} value={status}>{status}</option>
              ))}
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={() => onFilterChange('reset', null)}
              className="flex items-center space-x-1 px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200"
            >
              <X className="h-4 w-4" />
              <span>Clear</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// Main Containers component
const Containers = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [containers, setContainers] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [hasMore, setHasMore] = useState(true);
  const [page, setPage] = useState(0);
  const scrollContainerRef = useRef(null);

  // Filter and sort state initialized from URL parameters
  const [filters, setFilters] = useState(() => ({
    original_filename: searchParams.get('filename') || '',
    agent_id: searchParams.get('agent_id') || '',
    source: searchParams.get('source') || '',
    status: searchParams.get('status') || '',
    container_id: searchParams.get('container_id') || ''
  }));
  const [sortBy, setSortBy] = useState(() => searchParams.get('sort_by') || 'submitted_at');
  const [sortOrder, setSortOrder] = useState(() => searchParams.get('sort_order') || 'desc');

  const POLL_INTERVAL = 5000; // Poll every 5 seconds
  const PAGE_SIZE = 20;


  const fetchContainers = useCallback(async (pageNum = 0, reset = false) => {
    try {
      // Build filter variables instead of inline conditions
      const variables = {
        limit: PAGE_SIZE,
        offset: pageNum * PAGE_SIZE
      };

      // Build where conditions as GraphQL variables
      const whereConditions = [];

      if (filters.original_filename) {
        whereConditions.push({ original_filename: { _ilike: `%${filters.original_filename}%` } });
      }
      if (filters.agent_id) {
        whereConditions.push({ agent_id: { _ilike: `%${filters.agent_id}%` } });
      }
      if (filters.source) {
        whereConditions.push({ source: { _ilike: `%${filters.source}%` } });
      }
      if (filters.status) {
        whereConditions.push({ status: { _eq: filters.status } });
      }
      if (filters.container_id) {
        // Only filter when we have a complete UUID to avoid casting errors
        // Check if it's a valid UUID format (8-4-4-4-12 hex characters)
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (uuidRegex.test(filters.container_id)) {
          whereConditions.push({ container_id: { _eq: filters.container_id } });
        }
        // If we want to support partial matching, we'd need a computed field or custom function in Hasura
      }

      // Only add where clause if we have conditions
      if (whereConditions.length > 0) {
        variables.where = { _and: whereConditions };
      }

      // Build order by
      variables.order_by = { [sortBy]: sortOrder };

      const query = `
        query GetContainers($where: container_processing_bool_exp, $order_by: [container_processing_order_by!], $limit: Int!, $offset: Int!) {
          container_processing(
            where: $where
            order_by: $order_by
            limit: $limit
            offset: $offset
          ) {
            container_id
            container_type
            original_filename
            original_size
            agent_id
            source
            project
            status
            total_files_extracted
            total_bytes_extracted
            submitted_at
            processing_started_at
            processing_completed_at
            error_message
            workflows_completed
            workflows_failed
            workflows_total
            total_bytes_processed
          }
        }
      `;

      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify({
          query,
          variables
        })
      });

      if (!response.ok) {
        throw new Error(`Network response error: ${response.status}`);
      }

      const result = await response.json();

      if (result.errors) {
        console.error('GraphQL errors:', result.errors);
        throw new Error(result.errors[0].message);
      }

      const newContainers = result.data.container_processing || [];

      if (reset || pageNum === 0) {
        setContainers(newContainers);
      } else {
        setContainers(prev => [...prev, ...newContainers]);
      }

      setHasMore(newContainers.length === PAGE_SIZE);
      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      console.error('Error fetching containers:', err);
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  }, [filters, sortBy, sortOrder]);


  // Handle filter changes
  const handleFilterChange = useCallback((key, value) => {
    if (key === 'reset') {
      setFilters({});
    } else {
      setFilters(prev => ({
        ...prev,
        [key]: value || undefined
      }));
    }
    setPage(0);
  }, []);

  // Handle sort changes
  const handleSortChange = useCallback((newSortBy, newSortOrder) => {
    setSortBy(newSortBy);
    setSortOrder(newSortOrder);
    setPage(0);
  }, []);

  // Update URL parameters when filters change
  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.original_filename) {
      params.set('filename', filters.original_filename);
    }
    if (filters.agent_id) {
      params.set('agent_id', filters.agent_id);
    }
    if (filters.source) {
      params.set('source', filters.source);
    }
    if (filters.status) {
      params.set('status', filters.status);
    }
    if (filters.container_id) {
      params.set('container_id', filters.container_id);
    }
    if (sortBy !== 'submitted_at') {
      params.set('sort_by', sortBy);
    }
    if (sortOrder !== 'desc') {
      params.set('sort_order', sortOrder);
    }
    
    // Use replace: true to avoid adding to browser history for every filter change
    setSearchParams(params, { replace: true });
  }, [filters, sortBy, sortOrder, setSearchParams]);

  // Watch for URL changes and update the state
  useEffect(() => {
    const filenameParam = searchParams.get('filename');
    const agentIdParam = searchParams.get('agent_id');
    const sourceParam = searchParams.get('source');
    const statusParam = searchParams.get('status');
    const containerIdParam = searchParams.get('container_id');
    const sortByParam = searchParams.get('sort_by');
    const sortOrderParam = searchParams.get('sort_order');

    setFilters({
      original_filename: filenameParam || '',
      agent_id: agentIdParam || '',
      source: sourceParam || '',
      status: statusParam || '',
      container_id: containerIdParam || ''
    });
    setSortBy(sortByParam || 'submitted_at');
    setSortOrder(sortOrderParam || 'desc');
  }, [searchParams]);

  // Handle infinite scroll
  const handleScroll = useCallback(() => {
    if (!scrollContainerRef.current || isLoading || !hasMore) return;

    const { scrollLeft, scrollWidth, clientWidth } = scrollContainerRef.current;
    const scrollPercentage = (scrollLeft + clientWidth) / scrollWidth;

    if (scrollPercentage > 0.8) {
      const nextPage = page + 1;
      setPage(nextPage);
      fetchContainers(nextPage, false);
    }
  }, [isLoading, hasMore, page, fetchContainers]);

  // Initial fetch and polling
  useEffect(() => {
    fetchContainers(0, true);

    const intervalId = setInterval(() => {
      fetchContainers(0, true);
    }, POLL_INTERVAL);

    return () => clearInterval(intervalId);
  }, [fetchContainers]);

  // Scroll event listener
  useEffect(() => {
    const scrollContainer = scrollContainerRef.current;
    if (scrollContainer) {
      scrollContainer.addEventListener('scroll', handleScroll);
      return () => scrollContainer.removeEventListener('scroll', handleScroll);
    }
  }, [handleScroll]);

  // Visibility change handler
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (!document.hidden) {
        fetchContainers(0, true);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [fetchContainers]);

  if (error) {
    return (
      <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2 transition-colors">
        <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
        <div className="flex flex-col">
          <span className="text-red-600 dark:text-red-400">Error loading containers: {error}</span>
          <span className="text-sm text-red-500 dark:text-red-400">Check browser console for details</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-800 dark:text-white">Container Processing</h1>
        <div className="text-sm text-gray-500 dark:text-gray-400 flex items-center space-x-1">
          <Clock className="w-4 h-4" />
          <span>{lastUpdated ? `Last updated: ${lastUpdated.toLocaleTimeString()}` : 'Updating...'}</span>
        </div>
      </div>

      <FilterControls
        filters={filters}
        onFilterChange={handleFilterChange}
        sortBy={sortBy}
        sortOrder={sortOrder}
        onSortChange={handleSortChange}
      />

      {/* Container cards with horizontal scroll */}
      <div className="relative">
        <div
          ref={scrollContainerRef}
          className="flex overflow-x-auto space-x-0 pb-4 scrollbar-thin scrollbar-thumb-gray-300 dark:scrollbar-thumb-gray-600 scrollbar-track-transparent"
          style={{ scrollbarWidth: 'thin' }}
        >
          {isLoading && containers.length === 0 ? (
            <div className="flex justify-center items-center w-full py-8">
              <div className="animate-spin h-8 w-8 border-2 border-blue-500 rounded-full border-t-transparent" />
            </div>
          ) : containers.length > 0 ? (
            <>
              {containers.map((container) => (
                <ContainerCard key={container.container_id} container={container} />
              ))}
              {hasMore && (
                <div className="flex-shrink-0 w-80 flex items-center justify-center mx-2">
                  <div className="animate-spin h-6 w-6 border-2 border-blue-500 rounded-full border-t-transparent" />
                </div>
              )}
            </>
          ) : (
            <div className="w-full text-center py-8 text-gray-500 dark:text-gray-400">
              No containers found matching the current filters.
            </div>
          )}
        </div>
      </div>

      {/* Summary stats */}
      {containers.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-6">
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {containers.length}
            </div>
            <div className="text-sm text-gray-600 dark:text-gray-400">Total Containers</div>
          </div>

          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {containers.filter(c => c.status === 'completed' || c.status === 'workflows_complete').length}
            </div>
            <div className="text-sm text-gray-600 dark:text-gray-400">Completed Containers</div>
          </div>

          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {containers.filter(c => c.status === 'processing' || c.status === 'extracted').length}
            </div>
            <div className="text-sm text-gray-600 dark:text-gray-400">Processing Containers</div>
          </div>

          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="text-2xl font-bold text-red-600 dark:text-red-400">
              {containers.filter(c => c.status === 'failed').length}
            </div>
            <div className="text-sm text-gray-600 dark:text-gray-400">Failed Containers</div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Containers;
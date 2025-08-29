import React, { useState, useEffect, useCallback } from 'react';
import { 
  Folder, 
  File, 
  ArrowLeft, 
  Home, 
  ChevronRight, 
  AlertTriangle, 
  Clock, 
  CheckCircle, 
  XCircle, 
  HardDrive,
  Search,
  List,
  FolderTree
} from 'lucide-react';

// Status badge component
const StatusBadge = ({ status, count }) => {
  const configs = {
    collected: { icon: CheckCircle, className: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200', label: 'Collected' },
    needs_to_be_collected: { icon: Clock, className: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200', label: 'Needs Collection' },
    not_exists: { icon: XCircle, className: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200', label: 'Not Found' },
    not_wanted: { icon: AlertTriangle, className: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200', label: 'Not Wanted' }
  };

  const config = configs[status] || { icon: File, className: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200', label: status };
  const Icon = config.icon;

  return (
    <div className="flex items-center justify-between">
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.className}`}>
        <Icon className="w-3 h-3 mr-1" />
        {config.label}
      </span>
      {count && (
        <span className="text-sm font-semibold text-gray-600 dark:text-gray-400">
          {count.toLocaleString()}
        </span>
      )}
    </div>
  );
};

// Source card component
const SourceCard = ({ source, totalFiles, statusCounts, onSourceClick }) => {
  const formatNumber = (num) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  return (
    <div 
      onClick={() => onSourceClick(source)}
      className="bg-white dark:bg-gray-800 rounded-lg shadow-md border border-gray-200 dark:border-gray-700 p-4 cursor-pointer hover:shadow-lg transition-shadow"
    >
      <div className="mb-3">
        <div className="flex items-center space-x-2 mb-2">
          <HardDrive className="h-5 w-5 text-blue-500 flex-shrink-0" />
          <div className="min-w-0 flex-1">
            <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate" title={source}>
              {source}
            </h3>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {formatNumber(totalFiles)} files
            </p>
          </div>
        </div>
      </div>
      <div className="space-y-2">
        {Object.entries(statusCounts).map(([status, count]) => 
          count > 0 && <StatusBadge key={status} status={status} count={count} />
        )}
      </div>
    </div>
  );
};

// Breadcrumb navigation
const Breadcrumb = ({ currentPath, onNavigate }) => {
  const pathParts = currentPath ? currentPath.split('/').filter(Boolean) : [];
  
  return (
    <div className="flex items-center space-x-1 text-sm text-gray-600 dark:text-gray-400 mb-4">
      <button 
        onClick={() => onNavigate('')}
        className="flex items-center hover:text-blue-600 dark:hover:text-blue-400"
      >
        <Home className="w-4 h-4 mr-1" />
        Root
      </button>
      
      {pathParts.map((part, index) => {
        const partialPath = pathParts.slice(0, index + 1).join('/');
        const isLast = index === pathParts.length - 1;
        
        return (
          <React.Fragment key={index}>
            <ChevronRight className="w-4 h-4" />
            <button 
              onClick={() => !isLast && onNavigate(partialPath)}
              className={`hover:text-blue-600 dark:hover:text-blue-400 ${
                isLast ? 'text-gray-900 dark:text-gray-100 font-medium' : ''
              }`}
            >
              {part}
            </button>
          </React.Fragment>
        );
      })}
    </div>
  );
};

// File/Folder item component
const FileItem = ({ item, onItemClick, onFileClick }) => {
  const isFile = item.item_type === 'file';
  const Icon = isFile ? File : Folder;
  
  const handleClick = () => {
    if (isFile && item.status === 'collected' && item.object_id) {
      onFileClick(item.object_id);
    } else if (!isFile) {
      onItemClick(item.path);
    }
  };

  return (
    <div 
      onClick={handleClick}
      className={`
        flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700 
        cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors
        ${isFile && item.status === 'collected' && item.object_id ? 'hover:bg-blue-50 dark:hover:bg-blue-900/20' : ''}
      `}
    >
      <div className="flex items-center space-x-3 min-w-0 flex-1">
        <Icon className={`w-5 h-5 ${isFile ? 'text-gray-500' : 'text-blue-500'} flex-shrink-0`} />
        <span className="text-sm text-gray-900 dark:text-gray-100 truncate" title={item.name}>
          {item.name}
        </span>
      </div>
      
      {isFile && <StatusBadge status={item.status} />}
    </div>
  );
};

// Simple file path item for collection list view
const FilePathItem = ({ filePath }) => {
  return (
    <div className="p-2 border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700">
      <div className="flex items-center space-x-2">
        <Clock className="w-4 h-4 text-yellow-500 flex-shrink-0" />
        <span className="text-sm text-gray-900 dark:text-gray-100 font-mono break-all">
          {filePath}
        </span>
      </div>
    </div>
  );
};

// Main FileBrowser component
const FileBrowser = () => {
  const [sources, setSources] = useState([]);
  const [selectedSource, setSelectedSource] = useState(null);
  const [currentPath, setCurrentPath] = useState('');
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showCollectionList, setShowCollectionList] = useState(false);
  const [collectionPaths, setCollectionPaths] = useState([]);

  // Efficient single-query approach for sources and their counts
  const fetchSources = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Single query to get all data we need
      const query = {
        query: `
          query GetSourcesAndCounts {
            file_listings {
              source
              status
            }
          }
        `
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

      // Process data efficiently in memory
      const sourceData = {};
      result.data.file_listings.forEach(({ source, status }) => {
        if (!sourceData[source]) {
          sourceData[source] = { total: 0, statusCounts: {} };
        }
        sourceData[source].total++;
        sourceData[source].statusCounts[status] = (sourceData[source].statusCounts[status] || 0) + 1;
      });

      const sourcesArray = Object.entries(sourceData).map(([source, data]) => ({
        source,
        totalFiles: data.total,
        statusCounts: data.statusCounts
      }));

      setSources(sourcesArray);
    } catch (err) {
      console.error('Error fetching sources:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Efficient path contents fetching with smart filtering
  const fetchPathContents = useCallback(async (source, path) => {
    try {
      setLoading(true);
      setError(null);

      // Use LIKE patterns for efficient database filtering
      const pathPrefix = path === '' ? '' : `${path}/`;
      const pathPattern = path === '' ? '%' : `${path}/%`;

      const query = {
        query: `
          query GetPathContents($source: String!, $path_pattern: String!) {
            file_listings(
              where: {
                source: {_eq: $source},
                path: {_like: $path_pattern}
              },
              order_by: {path: asc}
            ) {
              path
              object_id
              status
            }
          }
        `,
        variables: { source, path_pattern: pathPattern }
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

      // Efficiently process paths to extract immediate children only
      const childrenMap = new Map();
      const currentLevel = path === '' ? 0 : path.split('/').length;

      result.data.file_listings.forEach(item => {
        const itemPath = item.path;
        const pathParts = itemPath.split('/');
        
        // Only process items at the next level down
        if (pathParts.length === currentLevel + 1 || 
           (pathParts.length > currentLevel + 1 && pathParts.slice(0, currentLevel + 1).join('/') === (path === '' ? pathParts[0] : `${path}/${pathParts[currentLevel]}`))) {
          
          const childName = pathParts[currentLevel];
          const childPath = pathParts.slice(0, currentLevel + 1).join('/');
          
          if (!childrenMap.has(childName)) {
            const isFile = pathParts.length === currentLevel + 1;
            childrenMap.set(childName, {
              source,
              path: childPath,
              item_type: isFile ? 'file' : 'folder',
              object_id: isFile ? item.object_id : null,
              status: isFile ? item.status : 'folder',
              name: childName
            });
          }
        }
      });

      const processedItems = Array.from(childrenMap.values());
      processedItems.sort((a, b) => {
        if (a.item_type !== b.item_type) {
          return a.item_type === 'folder' ? -1 : 1;
        }
        return a.name.localeCompare(b.name);
      });

      setItems(processedItems);
    } catch (err) {
      console.error('Error fetching path contents:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch all files that need to be collected for a source
  const fetchCollectionPaths = useCallback(async (source) => {
    try {
      setLoading(true);
      setError(null);

      const query = {
        query: `
          query GetCollectionPaths($source: String!) {
            file_listings(
              where: {
                source: {_eq: $source},
                status: {_eq: "needs_to_be_collected"}
              },
              order_by: {path: asc}
            ) {
              path
            }
          }
        `,
        variables: { source }
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

      const paths = result.data.file_listings.map(item => item.path);
      setCollectionPaths(paths);
    } catch (err) {
      console.error('Error fetching collection paths:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Effects and handlers
  useEffect(() => {
    fetchSources();
  }, [fetchSources]);

  useEffect(() => {
    if (selectedSource) {
      if (showCollectionList) {
        fetchCollectionPaths(selectedSource);
      } else {
        fetchPathContents(selectedSource, currentPath);
      }
    }
  }, [selectedSource, currentPath, showCollectionList, fetchPathContents, fetchCollectionPaths]);

  const handleSourceClick = (source) => {
    setSelectedSource(source);
    setCurrentPath('');
  };

  const handleBackToSources = () => {
    setSelectedSource(null);
    setCurrentPath('');
    setItems([]);
    setShowCollectionList(false);
    setCollectionPaths([]);
  };

  const handlePathNavigate = (path) => {
    setCurrentPath(path);
  };

  const handleItemClick = (path) => {
    setCurrentPath(path);
  };

  const handleFileClick = (objectId) => {
    window.open(`/files/${objectId}`, '_blank');
  };

  const handleToggleView = () => {
    setShowCollectionList(!showCollectionList);
    setSearchTerm(''); // Clear search when switching views
  };

  // Filter items based on search term
  const filteredItems = items.filter(item =>
    item.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Filter collection paths based on search term
  const filteredCollectionPaths = collectionPaths.filter(path =>
    path.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (error) {
    return (
      <div className="space-y-6 p-6">
        <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2">
          <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
          <div className="flex flex-col">
            <span className="text-red-600 dark:text-red-400">Error loading file browser: {error}</span>
            <span className="text-sm text-red-500 dark:text-red-400">Check browser console for details</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex justify-between items-center">
        <div className="flex items-center space-x-4">
          {selectedSource && (
            <button 
              onClick={handleBackToSources}
              className="flex items-center space-x-2 px-3 py-2 text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-200 dark:hover:bg-gray-600"
            >
              <ArrowLeft className="h-4 w-4" />
              <span>Back to Sources</span>
            </button>
          )}
          
          <h1 className="text-2xl font-bold text-gray-800 dark:text-white">
            {selectedSource ? `Files - ${selectedSource}` : 'File Browser'}
          </h1>
        </div>
        
        {selectedSource && (
          <div className="flex items-center space-x-4">
            {/* View Toggle */}
            <div className="flex items-center space-x-3">
              <span className="text-sm text-gray-600 dark:text-gray-400">View:</span>
              <button
                onClick={handleToggleView}
                className={`flex items-center space-x-2 px-3 py-2 text-sm rounded-md transition-colors ${
                  !showCollectionList
                    ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                }`}
              >
                <FolderTree className="w-4 h-4" />
                <span>Tree</span>
              </button>
              <button
                onClick={handleToggleView}
                className={`flex items-center space-x-2 px-3 py-2 text-sm rounded-md transition-colors ${
                  showCollectionList
                    ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                }`}
              >
                <List className="w-4 h-4" />
                <span>Needs Collection ({collectionPaths.length})</span>
              </button>
            </div>

            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder={showCollectionList ? "Search collection paths..." : "Search files and folders..."}
                className="pl-10 pr-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300"
              />
            </div>
          </div>
        )}
      </div>

      {/* Source selection view */}
      {!selectedSource && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {loading && sources.length === 0 ? (
            <div className="flex justify-center items-center w-full py-8 col-span-full">
              <div className="animate-spin h-8 w-8 border-2 border-blue-500 rounded-full border-t-transparent" />
            </div>
          ) : sources.length > 0 ? (
            sources.map((sourceData) => (
              <SourceCard
                key={sourceData.source}
                source={sourceData.source}
                totalFiles={sourceData.totalFiles}
                statusCounts={sourceData.statusCounts}
                onSourceClick={handleSourceClick}
              />
            ))
          ) : (
            <div className="w-full text-center py-8 text-gray-500 dark:text-gray-400 col-span-full">
              No file sources found.
            </div>
          )}
        </div>
      )}

      {/* Path browser view */}
      {selectedSource && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
          {/* Header - only show breadcrumbs in tree view */}
          {!showCollectionList && (
            <div className="p-4 border-b border-gray-200 dark:border-gray-700">
              <Breadcrumb 
                currentPath={currentPath} 
                onNavigate={handlePathNavigate} 
              />
            </div>
          )}

          {/* Collection List Header */}
          {showCollectionList && (
            <div className="p-4 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-center space-x-2">
                <Clock className="w-5 h-5 text-yellow-500" />
                <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                  Files Requiring Collection
                </h3>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  ({filteredCollectionPaths.length} {filteredCollectionPaths.length === 1 ? 'file' : 'files'})
                </span>
              </div>
            </div>
          )}

          <div className={showCollectionList ? "max-h-96 overflow-y-auto" : "divide-y divide-gray-200 dark:divide-gray-700"}>
            {loading ? (
              <div className="flex justify-center items-center w-full py-8">
                <div className="animate-spin h-6 w-6 border-2 border-blue-500 rounded-full border-t-transparent" />
              </div>
            ) : showCollectionList ? (
              filteredCollectionPaths.length > 0 ? (
                filteredCollectionPaths.map((filePath, index) => (
                  <FilePathItem key={`${filePath}-${index}`} filePath={filePath} />
                ))
              ) : (
                <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                  {searchTerm ? 'No collection paths match your search.' : 'No files need to be collected from this source.'}
                </div>
              )
            ) : (
              filteredItems.length > 0 ? (
                filteredItems.map((item, index) => (
                  <FileItem
                    key={`${item.path}-${index}`}
                    item={item}
                    onItemClick={handleItemClick}
                    onFileClick={handleFileClick}
                  />
                ))
              ) : (
                <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                  {searchTerm ? 'No items match your search.' : 'No files or folders found in this location.'}
                </div>
              )
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default FileBrowser;
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle,
  ChevronRight,
  Clock,
  File,
  Folder,
  FolderTree,
  HardDrive,
  Home,
  List,
  Search,
  XCircle
} from 'lucide-react';
import React, { useCallback, useEffect, useRef, useState } from 'react';

// Status badge component
const StatusBadge = ({ status, count = null }) => {
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

// Keyboard activation (Enter/Space) for clickable non-button elements
const onActivateKey = (handler) => (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    handler();
  }
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
      role="button"
      tabIndex={0}
      onClick={() => onSourceClick(source)}
      onKeyDown={onActivateKey(() => onSourceClick(source))}
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
              className={`hover:text-blue-600 dark:hover:text-blue-400 ${isLast ? 'text-gray-900 dark:text-gray-100 font-medium' : ''
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
      role="button"
      tabIndex={0}
      onClick={handleClick}
      onKeyDown={onActivateKey(handleClick)}
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
const FilePathItem = ({ pathData }) => {
  const { path, linkings } = pathData;

  const handleFileClick = (objectId) => {
    if (objectId) {
      window.open(`/files/${objectId}`, '_blank');
    }
  };

  return (
    <div className="p-3 border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700">
      <div className="flex items-start space-x-2">
        <div className="flex-1 min-w-0">
          <div className="text-sm text-gray-900 dark:text-gray-100 font-mono break-all mb-1">
            {path}
          </div>
          {linkings && linkings.length > 0 && (
            <div className="space-y-1 mt-2">
              {linkings.map((linking, idx) => (
                <div key={idx} className="text-xs text-gray-600 dark:text-gray-400 pl-3 border-l-2 border-yellow-300 dark:border-yellow-600">
                  <div className="font-medium text-yellow-700 dark:text-yellow-400">
                    Collection reason: {linking.reason}
                  </div>
                  <div className="font-mono text-gray-500 dark:text-gray-500">
                    Linked to by{' '}
                    {linking.requiredByObjectId ? (
                      <button
                        onClick={() => handleFileClick(linking.requiredByObjectId)}
                        className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 hover:underline break-all inline"
                      >
                        {linking.requiredBy}
                      </button>
                    ) : (
                      <span className="break-all">{linking.requiredBy}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const PAGE_SIZE = 200;
const SEARCH_DEBOUNCE_MS = 300;

const fetchJson = async (url, signal) => {
  const response = await fetch(url, { signal });
  if (!response.ok) {
    let detail = '';
    try {
      detail = (await response.json()).detail || '';
    } catch {
      // ignore non-JSON error bodies
    }
    throw new Error(`Network response error: ${response.status}${detail ? ` - ${detail}` : ''}`);
  }
  return response.json();
};

// Prev/next pager with a "showing X-Y of N" summary
const Pager = ({ start, count, total, canPrev, canNext, onPrev, onNext, noun = 'files' }) => {
  if (!total) return null;
  return (
    <div className="flex items-center justify-between px-4 py-2 text-sm text-gray-600 dark:text-gray-400 border-t border-gray-200 dark:border-gray-700">
      <span>
        {count > 0 ? `${(start + 1).toLocaleString()}-${(start + count).toLocaleString()} of ` : ''}
        {total.toLocaleString()} {noun}
      </span>
      {(canPrev || canNext) && (
        <div className="flex items-center space-x-2">
          <button
            onClick={onPrev}
            disabled={!canPrev}
            className="px-3 py-1 rounded-md bg-gray-100 dark:bg-gray-700 disabled:opacity-40 hover:bg-gray-200 dark:hover:bg-gray-600"
          >
            Previous
          </button>
          <button
            onClick={onNext}
            disabled={!canNext}
            className="px-3 py-1 rounded-md bg-gray-100 dark:bg-gray-700 disabled:opacity-40 hover:bg-gray-200 dark:hover:bg-gray-600"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
};

// Main FileBrowser component
//
// All tree navigation is server-side (web_api /file-browser/*): one folder level per request,
// files paged with a keyset cursor, so very wide folders (100k+ entries) and deep trees only ever
// transfer and render one page.
const FileBrowser = () => {
  const [sources, setSources] = useState([]);
  const [selectedSource, setSelectedSource] = useState(null);
  const [currentPath, setCurrentPath] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [showCollectionList, setShowCollectionList] = useState(false);

  // Tree view state: folders of the current level + current page of files
  const [folders, setFolders] = useState([]);
  const [foldersTruncated, setFoldersTruncated] = useState(false);
  const [files, setFiles] = useState([]);
  const [totalFiles, setTotalFiles] = useState(0);
  const [nextCursor, setNextCursor] = useState(null);
  // cursorStack[i] = cursor used to load page i (null for the first page)
  const [cursorStack, setCursorStack] = useState([null]);

  // Collection view state
  const [collectionPaths, setCollectionPaths] = useState([]);
  const [collectionTotal, setCollectionTotal] = useState(0);
  const [collectionOffset, setCollectionOffset] = useState(0);

  const requestRef = useRef(null);
  const startRequest = () => {
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    return controller;
  };
  useEffect(() => () => requestRef.current?.abort(), []);

  // Back to the first page (of files or of collection paths)
  const resetPaging = () => {
    setCursorStack([null]);
    setCollectionOffset(0);
  };

  // Debounce the search box: searching is server-side
  useEffect(() => {
    const timer = setTimeout(() => {
      const value = searchTerm.trim();
      setDebouncedSearch(prev => {
        if (prev !== value) resetPaging();
        return value;
      });
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  const fetchSources = useCallback(async () => {
    const controller = startRequest();
    try {
      setLoading(true);
      setError(null);
      const data = await fetchJson('/api/file-browser/sources', controller.signal);
      setSources(data.map(s => ({ source: s.source, totalFiles: s.total_files, statusCounts: s.status_counts })));
    } catch (err) {
      if (err.name === 'AbortError') return;
      console.error('Error fetching sources:', err);
      setError(err.message);
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, []);

  const fetchPathContents = useCallback(async (source, path, cursor, search) => {
    const controller = startRequest();
    try {
      setLoading(true);
      setError(null);
      const params = new URLSearchParams({ source, path, limit: String(PAGE_SIZE) });
      if (cursor) params.set('cursor', cursor);
      if (search) params.set('search', search);
      const data = await fetchJson(`/api/file-browser/children?${params}`, controller.signal);
      if (!cursor) {
        setFolders(data.folders.map(f => ({ ...f, item_type: 'folder', status: 'folder' })));
        setFoldersTruncated(data.folders_truncated);
      }
      setFiles(data.files.map(f => ({ ...f, item_type: 'file' })));
      setTotalFiles(data.total_files);
      setNextCursor(data.next_cursor);
    } catch (err) {
      if (err.name === 'AbortError') return;
      console.error('Error fetching path contents:', err);
      setError(err.message);
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, []);

  const fetchCollectionPaths = useCallback(async (source, offset, search) => {
    const controller = startRequest();
    try {
      setLoading(true);
      setError(null);
      const params = new URLSearchParams({ source, offset: String(offset), limit: String(PAGE_SIZE) });
      if (search) params.set('search', search);
      const data = await fetchJson(`/api/file-browser/collection?${params}`, controller.signal);
      setCollectionPaths(data.paths);
      setCollectionTotal(data.total);
    } catch (err) {
      if (err.name === 'AbortError') return;
      console.error('Error fetching collection paths:', err);
      setError(err.message);
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, []);

  // Effects and handlers
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- data fetch on source deselect; sets loading state before the request
    if (!selectedSource) fetchSources();
  }, [selectedSource, fetchSources]);

  const currentCursor = cursorStack[cursorStack.length - 1];
  useEffect(() => {
    if (!selectedSource) return;
    if (showCollectionList) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- data fetch keyed on view/paging state; sets loading state before the request
      fetchCollectionPaths(selectedSource, collectionOffset, debouncedSearch);
    } else {
      fetchPathContents(selectedSource, currentPath, currentCursor, debouncedSearch);
    }
  }, [selectedSource, currentPath, showCollectionList, debouncedSearch, currentCursor, collectionOffset, fetchPathContents, fetchCollectionPaths]);

  // Clears the current level and goes back to its first page (source / folder / view changes)
  const resetLevel = () => {
    resetPaging();
    setFolders([]);
    setFiles([]);
    setTotalFiles(0);
    setNextCursor(null);
    setFoldersTruncated(false);
  };

  const handleSourceClick = (source) => {
    resetLevel();
    setSelectedSource(source);
    setCurrentPath('');
  };

  const handleBackToSources = () => {
    setSelectedSource(null);
    setCurrentPath('');
    resetLevel();
    setShowCollectionList(false);
    setCollectionPaths([]);
    setCollectionTotal(0);
  };

  const navigateTo = (path) => {
    if (path === currentPath) return;
    resetLevel();
    setSearchTerm('');
    setDebouncedSearch('');
    setCurrentPath(path);
  };

  const handleFileClick = (objectId) => {
    window.open(`/files/${objectId}`, '_blank');
  };

  const handleToggleView = () => {
    resetPaging();
    setShowCollectionList(!showCollectionList);
    setSearchTerm(''); // Clear search when switching views
    setDebouncedSearch('');
  };

  const pageIndex = cursorStack.length - 1;
  const items = pageIndex === 0 ? [...folders, ...files] : files;

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
                className={`flex items-center space-x-2 px-3 py-2 text-sm rounded-md transition-colors ${!showCollectionList
                  ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                  }`}
              >
                <FolderTree className="w-4 h-4" />
                <span>Tree</span>
              </button>
              <button
                onClick={handleToggleView}
                className={`flex items-center space-x-2 px-3 py-2 text-sm rounded-md transition-colors ${showCollectionList
                  ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                  }`}
              >
                <List className="w-4 h-4" />
                <span>Files That Need Collection</span>
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
                onNavigate={navigateTo}
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
                  ({collectionTotal.toLocaleString()} {collectionTotal === 1 ? 'file' : 'files'})
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
              collectionPaths.length > 0 ? (
                collectionPaths.map((pathData, index) => (
                  <FilePathItem key={`${pathData.path}-${index}`} pathData={pathData} />
                ))
              ) : (
                <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                  {debouncedSearch ? 'No collection paths match your search.' : 'No files need to be collected from this source.'}
                </div>
              )
            ) : (
              items.length > 0 ? (
                items.map((item) => (
                  <FileItem
                    key={`${item.item_type}-${item.path}`}
                    item={item}
                    onItemClick={navigateTo}
                    onFileClick={handleFileClick}
                  />
                ))
              ) : (
                <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                  {debouncedSearch ? 'No items match your search.' : 'No files or folders found in this location.'}
                </div>
              )
            )}
          </div>

          {!showCollectionList && foldersTruncated && pageIndex === 0 && (
            <div className="px-4 py-2 text-xs text-yellow-700 dark:text-yellow-400 border-t border-gray-200 dark:border-gray-700">
              Only the first {folders.length.toLocaleString()} sub-folders are shown; use search to narrow them down.
            </div>
          )}

          {showCollectionList ? (
            <Pager
              start={collectionOffset}
              count={collectionPaths.length}
              total={collectionTotal}
              canPrev={!loading && collectionOffset > 0}
              canNext={!loading && collectionOffset + PAGE_SIZE < collectionTotal}
              onPrev={() => setCollectionOffset(Math.max(0, collectionOffset - PAGE_SIZE))}
              onNext={() => setCollectionOffset(collectionOffset + PAGE_SIZE)}
            />
          ) : (
            <Pager
              start={pageIndex * PAGE_SIZE}
              count={files.length}
              total={totalFiles}
              canPrev={!loading && pageIndex > 0}
              canNext={!loading && !!nextCursor}
              onPrev={() => setCursorStack(stack => stack.slice(0, -1))}
              onNext={() => setCursorStack(stack => [...stack, nextCursor])}
            />
          )}
        </div>
      )}
    </div>
  );
};

export default FileBrowser;

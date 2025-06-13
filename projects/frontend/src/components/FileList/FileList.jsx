import Tooltip from '@/components/shared/Tooltip2';
import { useTriageMode } from '@/contexts/TriageModeContext';
import { useUser } from '@/contexts/UserContext';
import { createClient } from 'graphql-ws';
import { AlertTriangle, ChevronDown, Clock, Eye, Search, Tag, X } from 'lucide-react';
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
      <div className="px-2 flex-shrink-0 w-32 text-sm text-gray-500 dark:text-gray-400 text-left">{file.agent_id}</div>
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
      <div className="px-6 flex-grow text-sm text-gray-500 dark:text-gray-400 truncate text-left">
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
          <span>{file.path}</span>
        </Tooltip>
      </div>
    </div>
  );
});


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

  // Filter states initialized from URL parameters
  const [fileTypeFilter, setFileTypeFilter] = useState(() => searchParams.get('type') || 'all');
  const [agentIdFilter, setAgentIdFilter] = useState(() => searchParams.get('agent_id') || '');
  const [pathFilter, setPathFilter] = useState(() => searchParams.get('path') || '');
  const [objectIdFilter, setObjectIdFilter] = useState(() => searchParams.get('object_id') || '');
  const [sortNewestFirst, setSortNewestFirst] = useState(true);
  const [viewFilter, setViewFilter] = useState(() => searchParams.get('view_state') || 'unviewed_by_me');
  const [showOnlyWithFindings, setShowOnlyWithFindings] = useState(false);

  const [availableTags, setAvailableTags] = useState([]);
  const [selectedTag, setSelectedTag] = useState('');
  const [isTagDropdownOpen, setIsTagDropdownOpen] = useState(false);
  const tagDropdownRef = useRef(null);

  const handleRowClick = (e, file, index) => {
    if (isTriageMode) {
      if (e.shiftKey && selectedIndex !== -1) {
        const start = Math.min(selectedIndex, index);
        const end = Math.max(selectedIndex, index);
        const newSelection = new Set(selectedFiles);
        for (let i = start; i <= end; i++) {
          newSelection.add(filteredFiles[i].object_id);
        }
        setSelectedFiles(newSelection);
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
      setSelectedIndex(index);
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
    if (listRef.current && isTriageMode && selectedIndex >= 0) {
      listRef.current.scrollToItem(selectedIndex, 'center');
    }
  }, [selectedIndex, isTriageMode]);


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

    if (agentIdFilter) {
      params.set('agent_id', agentIdFilter);
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

    // Add sort order to URL params
    params.set('sort', sortNewestFirst ? 'newest' : 'oldest');

    // Add findings filter to URL params
    if (showOnlyWithFindings) {
      params.set('findings', 'true');
    }

    // Use replace: true to avoid adding to browser history for every filter change
    setSearchParams(params, { replace: true });
  }, [fileTypeFilter, agentIdFilter, pathFilter, viewFilter, objectIdFilter, selectedTag, sortNewestFirst, showOnlyWithFindings]);

  // Watch for URL changes and update the state
  useEffect(() => {
    // Get values from URL params
    const typeParam = searchParams.get('type');
    const agentIdParam = searchParams.get('agent_id');
    const pathParam = searchParams.get('path');
    const viewStateParam = searchParams.get('view_state');
    const objectIdParam = searchParams.get('object_id');
    const tagParam = searchParams.get('tag');
    const sortParam = searchParams.get('sort');
    const findingsParam = searchParams.get('findings');

    // Update component state based on URL params
    setFileTypeFilter(typeParam || 'all');
    setAgentIdFilter(agentIdParam || '');
    setPathFilter(pathParam || '');
    setViewFilter(viewStateParam || 'unviewed_by_me');
    setObjectIdFilter(objectIdParam || '');
    setSelectedTag(tagParam || '');
    
    // Update sort order from URL
    if (sortParam !== null) {
      setSortNewestFirst(sortParam === 'newest');
    }
    
    // Update findings filter from URL
    setShowOnlyWithFindings(findingsParam === 'true');
  }, [searchParams]);

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

  // Create filteredFiles here so it's available throughout the component
  const filteredFiles = files
    .filter(file => {
      if (showOnlyWithFindings && file.findingsByObjectId_aggregate.aggregate.count === 0) return false;
      if (objectIdFilter && file.object_id !== objectIdFilter) return false;
      if (fileTypeFilter === 'plaintext' && !file.is_plaintext) return false;
      if (fileTypeFilter === 'binary' && file.is_plaintext) return false;
      if (fileTypeFilter === 'source' && !SOURCE_CODE_EXTENSIONS.includes(file.extension?.toLowerCase())) return false;
      if (fileTypeFilter === 'office' && !OFFICE_EXTENSIONS.includes(file.extension?.toLowerCase())) return false;
      if (fileTypeFilter === 'config' && !CONFIG_FILE_EXTENSIONS.includes(file.extension?.toLowerCase())) return false;
      if (agentIdFilter && !file.agent_id.toString().includes(agentIdFilter)) return false;
      if (pathFilter) {
        const pathRegex = wildcardToRegExp(pathFilter);
        if (!pathRegex.test(file.path)) return false;
      }

      if (selectedTag && selectedTag.trim() !== '') {
        // Make sure we're working with arrays and handle different possible structures
        let fileTags = [];

        if (file.file_tags) {
          if (Array.isArray(file.file_tags)) {
            fileTags = file.file_tags;
          } else if (typeof file.file_tags === 'string') {
            // Handle case where tags might be a comma-separated string
            fileTags = file.file_tags.split(',').map(tag => tag.trim());
          }
        }

        // Normalize tags for comparison (trim whitespace, lowercase)
        const normalizedTags = fileTags.map(tag =>
          typeof tag === 'string' ? tag.trim().toLowerCase() : String(tag).trim().toLowerCase()
        );
        const normalizedSelectedTag = selectedTag.trim().toLowerCase();

        // Check if normalized tags include the normalized selected tag
        if (!normalizedTags.includes(normalizedSelectedTag)) {
          return false;
        }
      }

      if (viewFilter !== 'all') {
        const hasBeenViewed = file.files_view_histories && file.files_view_histories.length > 0;
        const viewedByMe = file.files_view_histories?.some(h => h.username === username);

        switch (viewFilter) {
          case 'unviewed':
            if (hasBeenViewed) return false;
            break;
          case 'unviewed_by_me':
            if (viewedByMe) return false;
            break;
        }
      }

      return true;
    })
    .sort((a, b) => {
      const dateA = new Date(a.timestamp);
      const dateB = new Date(b.timestamp);
      return sortNewestFirst ? dateB - dateA : dateA - dateB;
    });


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
          const newSelection = new Set(filteredFiles.map(f => f.object_id));
          setSelectedFiles(newSelection);
        }
        return;
      }

      if (e.key === 't' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        setIsTriageMode(prev => {
          const newMode = !prev;
          if (newMode && selectedIndex === -1) {
            setSelectedIndex(0);
          }
          return newMode;
        });
        return;
      }

      if (!isTriageMode) return;

      const filteredFilesLength = filteredFiles.length;

      switch (e.key) {
        case 'ArrowUp':
          e.preventDefault();
          lastDirection.current = 'up';
          if (e.shiftKey) {
            const prevIndex = Math.max(0, selectedIndex - 1);
            const newSelection = new Set(selectedFiles);
            newSelection.add(filteredFiles[selectedIndex].object_id);
            newSelection.add(filteredFiles[prevIndex].object_id);
            setSelectedFiles(newSelection);
            setSelectedIndex(prevIndex);
          } else {
            setSelectedIndex(prev => Math.max(0, prev - 1));
          }
          break;
        case 'ArrowDown':
          e.preventDefault();
          lastDirection.current = 'down';
          if (e.shiftKey) {
            const nextIndex = Math.min(filteredFilesLength - 1, selectedIndex + 1);
            const newSelection = new Set(selectedFiles);
            newSelection.add(filteredFiles[selectedIndex].object_id);
            newSelection.add(filteredFiles[nextIndex].object_id);
            setSelectedFiles(newSelection);
            setSelectedIndex(nextIndex);
          } else {
            setSelectedIndex(prev => Math.min(filteredFilesLength - 1, prev + 1));
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
          if (selectedIndex >= 0 && selectedIndex < filteredFilesLength) {
            navigate(`/files/${filteredFiles[selectedIndex].object_id}`);
          }
          break;
        case 'v':
          e.preventDefault();
          if (selectedIndex >= 0 && selectedIndex < filteredFilesLength) {
            recordFileView(filteredFiles[selectedIndex].object_id);
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
  }, [isTriageMode, selectedIndex, filteredFiles, navigate, setIsTriageMode, setSelectedIndex, selectedFiles]);

  // Handle maintained triage mode state
  useEffect(() => {
    if (location.state?.maintainTriageMode) {
      setIsTriageMode(true);
      if (location.state?.maintainSelectedIndex >= 0) {
        setSelectedIndex(location.state.maintainSelectedIndex);
      }
    }
  }, [location.state, setIsTriageMode, setSelectedIndex]);

  // Initial data fetch
  useEffect(() => {
    const fetchFiles = async () => {
      const query = {
        query: `
          query GetFiles {
            files_enriched(
            where: {
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
            }
            ) {
              object_id
              agent_id
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
                aggregate{
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

        if (!response.ok) {
          throw new Error(`Network response error: ${response.status}`);
        }

        const result = await response.json();
        if (result.errors) {
          throw new Error(result.errors[0].message);
        }

        setFiles(result.data.files_enriched);
      } catch (err) {
        console.error('Error fetching files:', err);
        setError(err.message);
      } finally {
        setIsLoading(false);
      }
    };

    fetchFiles();
  }, []);

  // Set up subscription
  useEffect(() => {
    const subscription = {
      query: `
        subscription WatchFiles {
          files_enriched(
            where: {
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
            }
          ) {
            object_id
            agent_id
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
              aggregate{
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
      `
    };

    let unsubscribe;

    (async () => {
      unsubscribe = wsClient.subscribe(
        subscription,
        {
          next: ({ data }) => {
            if (data?.files_enriched) {
              setFiles(data.files_enriched);
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
  }, []);

  if (error) {
    return (
      <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2">
        <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
        <div className="flex flex-col">
          <span className="text-red-600 dark:text-red-400">Error loading files: {error}</span>
          <span className="text-sm text-red-500 dark:text-red-400">Check browser console for details</span>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-32">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-dark-secondary rounded-lg shadow">
      {isTriageMode && (
        <div className="p-1 bg-blue-50 dark:bg-blue-900/20 border-b dark:border-gray-700">
          <p className="text-sm text-blue-600 dark:text-blue-400">
            Triage Mode Active - Use ↑↓ to navigate. Use Shift+↑↓ to select multiple rows. Ctrl/Cmd+A to select all.
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
              onChange={(e) => setViewFilter(e.target.value)}
            >
              <option value="unviewed">Unviewed Files</option>
              <option value="unviewed_by_me">Files Unviewed by Me</option>
              <option value="all">All Files</option>
            </select>
          </div>

          {/* <div className="flex items-center space-x-2">
            <Filter className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <select
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={fileTypeFilter}
              onChange={(e) => setFileTypeFilter(e.target.value)}
            >
              <option value="all">All File Types</option>
              <option value="plaintext">Plaintext Files</option>
              <option value="binary">Binary Files</option>
              <option value="source">Source Code Files</option>
              <option value="config">Configuration Files</option>
              <option value="office">Office Documents</option>
            </select>
          </div> */}

          <Tooltip content={showOnlyWithFindings ? "Click to show all files" : "Click to show only files with findings"}>
            <button
              className="flex items-center space-x-2 px-3 py-2 border dark:border-gray-700 rounded hover:bg-gray-100 dark:hover:bg-gray-700"
              onClick={() => setShowOnlyWithFindings(!showOnlyWithFindings)}
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
              placeholder="Filter by path (e.g. *.txt)"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={pathFilter}
              onChange={(e) => setPathFilter(e.target.value)}
            />
          </div>

          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <input
              type="text"
              placeholder="Filter by Agent ID"
              className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
              value={agentIdFilter}
              onChange={(e) => setAgentIdFilter(e.target.value)}
            />
          </div>

          <Tooltip content={sortNewestFirst ? "Showing newest first" : "Showing oldest first"}>
            <button
              className="flex items-center space-x-2 px-3 py-2 border dark:border-gray-700 rounded hover:bg-gray-100 dark:hover:bg-gray-700"
              onClick={() => setSortNewestFirst(!sortNewestFirst)}
            >
              <Clock className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              <span className="text-sm text-gray-700 dark:text-gray-300">
                {sortNewestFirst ? "Newest First" : "Oldest First"}
              </span>
            </button>
          </Tooltip>

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
            {filteredFiles.length} file{filteredFiles.length !== 1 ? 's' : ''} found
          </span>
        </div>
      </div>

      {/* Headers */}
      <div className="flex border-b dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        {isTriageMode && (
          <div className="w-8 px-2 py-2"></div>
        )}
        <div className="px-2 flex-shrink-0 w-32 text-sm font-medium text-gray-500 dark:text-gray-400 text-left">Agent ID</div>
        <div className="px-2 flex-shrink-0 w-24 text-sm font-medium text-gray-500 dark:text-gray-400 text-left">Size</div>
        <div className="px-2 flex-shrink-0 w-44 text-sm font-medium text-gray-500 dark:text-gray-400 text-left">Time Uploaded</div>
        <div className="px-2 flex-shrink-0 w-48 text-sm font-medium text-gray-500 dark:text-gray-400 text-left">Magic Type</div>
        <div className="px-2 flex-shrink-0 w-12 text-sm font-medium text-gray-500 dark:text-gray-400 flex items-center justify-center">Findings</div>
        <div className="px-6 flex-grow text-sm font-medium text-gray-500 dark:text-gray-400 text-left">Path</div>
      </div>


      {filteredFiles.length === 0 && (
        <div className="flex flex-col items-center justify-center p-12 text-center">
          <div className="text-gray-500 dark:text-gray-400 mb-6">
            {files.length > 0 ? (
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
          {files.length > 0 && (
            <Link
              to="/files?view_state=all"
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors inline-flex items-center"
            >
              <span>Show All Files</span>
            </Link>
          )}
        </div>
      )}


      {/* Virtualized List */}
      {filteredFiles.length > 0 && (
        <div className="h-[calc(100vh-150px)]">
          <AutoSizer>
            {({ height, width }) => (
              <List
                ref={listRef}
                height={height}
                width={width}
                itemCount={filteredFiles.length}
                itemSize={ROW_HEIGHT}
                itemData={{
                  files: filteredFiles,
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
    </div>
  );
};

export default FileList;
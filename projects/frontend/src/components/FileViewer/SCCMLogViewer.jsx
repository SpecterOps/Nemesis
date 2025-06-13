import { useTheme } from '@/components/ThemeProvider';
import Editor from "@monaco-editor/react";
import { AlertCircle, Clock, Download, Filter, Info, RefreshCw, Search, Server } from 'lucide-react';
import React, { useEffect, useRef, useState } from 'react';

const SCCMLogViewer = ({ fileContent, fileName }) => {
  const { isDark } = useTheme();
  const [logs, setLogs] = useState([]);
  const [filteredLogs, setFilteredLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverityFilters, setSelectedSeverityFilters] = useState({
    error: true,
    warning: true,
    info: true
  });
  const [selectedComponents, setSelectedComponents] = useState([]);
  const [availableComponents, setAvailableComponents] = useState([]);
  const [isAutoRefresh, setIsAutoRefresh] = useState(false);
  const [selectedLogEntry, setSelectedLogEntry] = useState(null);
  const autoRefreshInterval = useRef(null);
  const searchInputRef = useRef(null);

  // Parse SCCM log format
  useEffect(() => {
    try {
      if (!fileContent) {
        setLoading(false);
        return;
      }

      const parsedLogs = parseLogContent(fileContent);
      setLogs(parsedLogs);

      // Extract unique component names
      const components = [...new Set(parsedLogs.map(log => log.component))].sort();
      setAvailableComponents(components);

      // Default to showing all components
      setSelectedComponents(components);

      applyFilters(parsedLogs, searchTerm, selectedSeverityFilters, components);
      setLoading(false);
    } catch (err) {
      console.error('Error parsing log file:', err);
      setError(`Failed to parse log file: ${err.message}`);
      setLoading(false);
    }
  }, [fileContent]);

  // Handle auto-refresh (in a real application, this would fetch updated content)
  useEffect(() => {
    if (isAutoRefresh) {
      autoRefreshInterval.current = setInterval(() => {
        // In a real implementation, we would fetch the latest log data here
        console.log('Auto-refreshing logs...');
      }, 5000);
    } else if (autoRefreshInterval.current) {
      clearInterval(autoRefreshInterval.current);
    }

    return () => {
      if (autoRefreshInterval.current) {
        clearInterval(autoRefreshInterval.current);
      }
    };
  }, [isAutoRefresh]);

  // Apply filters when criteria change
  useEffect(() => {
    applyFilters(logs, searchTerm, selectedSeverityFilters, selectedComponents);
  }, [logs, searchTerm, selectedSeverityFilters, selectedComponents]);

  // Parse the log content into structured data
  const parseLogContent = (content) => {
    if (!content) return [];

    const logRegex = /<!\[LOG\[(.*?)\]LOG\]!><time="(.*?)" date="(.*?)" component="(.*?)" context="(.*?)" type="(.*?)" thread="(.*?)" file="(.*?)">/g;
    const parsedLogs = [];
    let match;

    while ((match = logRegex.exec(content)) !== null) {
      const logEntry = {
        message: match[1],
        time: match[2],
        date: match[3],
        component: match[4],
        context: match[5],
        type: parseInt(match[6]), // Type is numeric: 1=info, 2=warning, 3=error
        thread: match[7],
        file: match[8],
        raw: match[0], // Store the full raw log entry
        index: parsedLogs.length // Add index for key
      };

      parsedLogs.push(logEntry);
    }

    return parsedLogs;
  };

  // Apply search and filters to the logs
  const applyFilters = (allLogs, search, severityFilters, components) => {
    if (!allLogs) return;

    const filtered = allLogs.filter(log => {
      // Apply severity filters
      if (log.type === 3 && !severityFilters.error) return false;
      if (log.type === 2 && !severityFilters.warning) return false;
      if (log.type === 1 && !severityFilters.info) return false;

      // Apply component filter
      if (!components.includes(log.component)) return false;

      // Apply text search
      if (search && search.trim() !== '') {
        const searchLower = search.toLowerCase();
        return (
          log.message.toLowerCase().includes(searchLower) ||
          log.component.toLowerCase().includes(searchLower) ||
          log.file.toLowerCase().includes(searchLower) ||
          log.thread.toLowerCase().includes(searchLower)
        );
      }

      return true;
    });

    setFilteredLogs(filtered);
  };

  // Toggle a severity filter
  const toggleSeverityFilter = (severity) => {
    setSelectedSeverityFilters(prev => ({
      ...prev,
      [severity]: !prev[severity]
    }));
  };

  // Toggle a component filter
  const toggleComponent = (component) => {
    setSelectedComponents(prev => {
      if (prev.includes(component)) {
        return prev.filter(c => c !== component);
      } else {
        return [...prev, component];
      }
    });
  };

  // Select all components
  const selectAllComponents = () => {
    setSelectedComponents([...availableComponents]);
  };

  // Clear all component selections
  const clearAllComponents = () => {
    setSelectedComponents([]);
  };

  // Handle search input change
  const handleSearchChange = (e) => {
    setSearchTerm(e.target.value);
  };

  // Focus search input when Ctrl+F is pressed
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Get CSS class for severity level
  const getSeverityClass = (type) => {
    switch (type) {
      case 3: return 'text-red-600 dark:text-red-400';
      case 2: return 'text-yellow-600 dark:text-yellow-400';
      default: return 'text-gray-800 dark:text-gray-200';
    }
  };

  // Get background class for the selected log entry
  const getRowClass = (log) => {
    let baseClass = 'hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer';

    // Add highlight class based on severity
    if (log.type === 3) {
      baseClass += ' bg-red-50 dark:bg-red-900/20';
    } else if (log.type === 2) {
      baseClass += ' bg-yellow-50 dark:bg-yellow-900/20';
    }

    // Add selected class if this is the selected log
    if (selectedLogEntry && log.index === selectedLogEntry.index) {
      baseClass += ' bg-blue-100 dark:bg-blue-900/30 border-l-4 border-blue-500';
    }

    return baseClass;
  };

  // Format the ISO date/time for display
  const formatDateTime = (date, time) => {
    if (!date || !time) return '';
    // Handle the time format from SCCM logs (HH:MM:SS.mmm±TZ)
    const timeParts = time.split('-');
    const timeString = timeParts[0];

    // Format date as MM/DD/YYYY
    const [month, day, year] = date.split('-');
    return `${month}/${day}/${year} ${timeString}`;
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center">
        <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 mr-2" />
        <p className="text-red-600 dark:text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full border dark:border-gray-700 rounded-lg overflow-hidden">
      <div className="text-sm font-medium px-4 py-2 bg-gray-100 dark:bg-gray-800 border-b dark:border-gray-700 flex justify-between items-center">
        <span className="text-gray-900 dark:text-gray-200">SCCM Log Viewer: {fileName}</span>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setIsAutoRefresh(!isAutoRefresh)}
            className={`p-1 rounded-md ${isAutoRefresh
              ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400'
              : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300'
            }`}
            title={isAutoRefresh ? 'Disable auto refresh' : 'Enable auto refresh'}
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => {
              const blob = new Blob([fileContent], { type: 'text/plain' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = fileName;
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
            }}
            className="p-1 rounded-md bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600"
            title="Download log file"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left panel: Filters */}
        <div className="w-64 border-r dark:border-gray-700 bg-white dark:bg-gray-900 overflow-y-auto p-4">
          <h3 className="font-medium text-gray-900 dark:text-gray-100 mb-3">Filters</h3>

          {/* Search box */}
          <div className="relative mb-4">
            <Search className="w-4 h-4 absolute left-2 top-1/2 transform -translate-y-1/2 text-gray-400" />
            <input
              ref={searchInputRef}
              type="text"
              placeholder="Search logs..."
              value={searchTerm}
              onChange={handleSearchChange}
              className="w-full pl-8 pr-4 py-1 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-200 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Severity filters */}
          <div className="mb-4">
            <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 flex items-center">
              <Filter className="w-4 h-4 mr-1" />
              Severity
            </h4>
            <div className="space-y-1">
              <label className="flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={selectedSeverityFilters.error}
                  onChange={() => toggleSeverityFilter('error')}
                  className="rounded border-gray-300 dark:border-gray-600 text-red-600 focus:ring-red-500"
                />
                <span className="ml-2 text-sm text-red-600 dark:text-red-400">Errors</span>
              </label>
              <label className="flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={selectedSeverityFilters.warning}
                  onChange={() => toggleSeverityFilter('warning')}
                  className="rounded border-gray-300 dark:border-gray-600 text-yellow-600 focus:ring-yellow-500"
                />
                <span className="ml-2 text-sm text-yellow-600 dark:text-yellow-400">Warnings</span>
              </label>
              <label className="flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={selectedSeverityFilters.info}
                  onChange={() => toggleSeverityFilter('info')}
                  className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-600 dark:text-gray-400">Information</span>
              </label>
            </div>
          </div>

          {/* Component filters */}
          <div>
            <div className="flex justify-between items-center mb-2">
              <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center">
                <Server className="w-4 h-4 mr-1" />
                Components
              </h4>
              <div className="flex space-x-1">
                <button
                  onClick={selectAllComponents}
                  className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                >
                  All
                </button>
                <span className="text-gray-400">|</span>
                <button
                  onClick={clearAllComponents}
                  className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                >
                  None
                </button>
              </div>
            </div>
            <div className="max-h-48 overflow-y-auto space-y-1 border dark:border-gray-700 p-2 rounded-md">
              {availableComponents.map(component => (
                <label key={component} className="flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedComponents.includes(component)}
                    onChange={() => toggleComponent(component)}
                    className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300 truncate">{component}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Filter stats */}
          <div className="mt-4 text-xs text-gray-500 dark:text-gray-400">
            Showing {filteredLogs.length} of {logs.length} log entries
          </div>
        </div>

        {/* Right panel: Log entries */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Log entries table */}
          <div className="flex-1 overflow-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-100 dark:bg-gray-800 sticky top-0 z-10">
                <tr>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Time
                  </th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Component
                  </th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Message
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {filteredLogs.map(log => (
                  <tr
                    key={log.index}
                    className={getRowClass(log)}
                    onClick={() => setSelectedLogEntry(log)}
                  >
                    <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500 dark:text-gray-400">
                      <div className="flex items-center">
                        <Clock className="w-3 h-3 mr-1" />
                        {formatDateTime(log.date, log.time)}
                      </div>
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap text-xs">
                      <span className="px-2 py-1 rounded-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                        {log.component}
                      </span>
                    </td>
                    <td className={`px-3 py-2 text-sm ${getSeverityClass(log.type)}`}>
                      {log.message}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {filteredLogs.length === 0 && (
              <div className="flex flex-col items-center justify-center h-32 text-gray-500 dark:text-gray-400">
                <Info className="w-5 h-5 mb-2" />
                <p>No log entries match your filters</p>
              </div>
            )}
          </div>

          {/* Details panel for selected log */}
          {selectedLogEntry && (
            <div className="h-64 border-t dark:border-gray-700 p-4 bg-gray-50 dark:bg-gray-900 overflow-auto">
              <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">Log Entry Details</h3>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Date/Time</p>
                  <p className="text-sm text-gray-900 dark:text-gray-100">
                    {formatDateTime(selectedLogEntry.date, selectedLogEntry.time)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Severity</p>
                  <p className={`text-sm ${getSeverityClass(selectedLogEntry.type)}`}>
                    {selectedLogEntry.type === 3 ? 'Error' :
                     selectedLogEntry.type === 2 ? 'Warning' :
                     'Information'}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Component</p>
                  <p className="text-sm text-gray-900 dark:text-gray-100">{selectedLogEntry.component}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Thread</p>
                  <p className="text-sm text-gray-900 dark:text-gray-100">{selectedLogEntry.thread}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Source File</p>
                  <p className="text-sm text-gray-900 dark:text-gray-100">{selectedLogEntry.file}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Context</p>
                  <p className="text-sm text-gray-900 dark:text-gray-100">
                    {selectedLogEntry.context || '<empty>'}
                  </p>
                </div>
              </div>
              <div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Message</p>
                <p className={`text-sm ${getSeverityClass(selectedLogEntry.type)}`}>
                  {selectedLogEntry.message}
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SCCMLogViewer;
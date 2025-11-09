import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Copy, Check } from 'lucide-react';

const QueryModal = ({ queries }) => {
  const [expandedQueries, setExpandedQueries] = useState({});
  const [copiedIndex, setCopiedIndex] = useState(null);

  const toggleQuery = (index) => {
    setExpandedQueries(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  const copyToClipboard = async (text, index) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  if (!queries || queries.length === 0) return null;

  return (
    <div className="mb-4 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 shadow-sm">
      <div className="p-3 border-b border-gray-200 dark:border-gray-700">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">
          SQL Queries Executed
        </h3>
      </div>

      <div className="divide-y divide-gray-200 dark:divide-gray-700">
        {queries.map((query, index) => {
          const isExpanded = expandedQueries[index];
          const isCopied = copiedIndex === index;

          return (
            <div key={index} className="transition-colors">
              {/* Query Header - Collapsible */}
              <button
                onClick={() => toggleQuery(index)}
                className="w-full flex items-center justify-between p-3 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
              >
                <div className="flex items-center space-x-2 flex-1 min-w-0">
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-gray-500 flex-shrink-0" />
                  )}
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300 truncate">
                    {query.name || `Query ${index + 1}`}
                  </span>
                  {query.timestamp && (
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      {new Date(query.timestamp).toLocaleTimeString()}
                    </span>
                  )}
                </div>
                {query.rowCount !== undefined && (
                  <span className="text-xs text-gray-500 dark:text-gray-400 ml-2">
                    {query.rowCount} rows
                  </span>
                )}
              </button>

              {/* Query Content - Expandable */}
              {isExpanded && (
                <div className="px-3 pb-3">
                  <div className="relative">
                    {/* Copy Button */}
                    <button
                      onClick={() => copyToClipboard(query.sql, index)}
                      className="absolute top-2 right-2 p-1.5 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded transition-colors"
                      title="Copy to clipboard"
                    >
                      {isCopied ? (
                        <Check className="w-4 h-4 text-green-600 dark:text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4 text-gray-600 dark:text-gray-400" />
                      )}
                    </button>

                    {/* SQL Code Block */}
                    <pre className="bg-gray-50 dark:bg-gray-900 p-3 pr-12 rounded-lg overflow-x-auto text-xs font-mono">
                      <code className="text-gray-800 dark:text-gray-200">
                        {query.sql}
                      </code>
                    </pre>
                  </div>

                  {/* Query Metadata */}
                  {(query.executionTime || query.error) && (
                    <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                      {query.executionTime && (
                        <span>Execution time: {query.executionTime}ms</span>
                      )}
                      {query.error && (
                        <span className="text-red-600 dark:text-red-400">
                          Error: {query.error}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default QueryModal;

import { AlertTriangle, ChevronDown, FileText, Filter, Loader2, Search } from 'lucide-react';
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const DocumentSearch = () => {
  const navigate = useNavigate();
  const [searchParams] = useState(new URLSearchParams(window.location.search));
  const [searchQuery, setSearchQuery] = useState(searchParams.get('q') || '');
  const [debouncedQuery, setDebouncedQuery] = useState(searchParams.get('q') || '');
  const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);
  const [filters, setFilters] = useState({
    pathPattern: '',
    sourcePattern: '',
    agentPattern: '',
    project: '',
    dateRange: 'any'
  });
  const [searchResults, setSearchResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Debounce search effect
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(searchQuery);

      // Update URL with search query
      const newUrl = searchQuery
        ? `${window.location.pathname}?q=${encodeURIComponent(searchQuery)}`
        : window.location.pathname;

      window.history.replaceState({}, '', newUrl);
    }, 300);

    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Handle browser back/forward navigation
  useEffect(() => {
    const handlePopState = () => {
      const params = new URLSearchParams(window.location.search);
      const query = params.get('q') || '';
      setSearchQuery(query);
      setDebouncedQuery(query);
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const convertWildcardToLike = (pattern) => {
    if (!pattern) return '%';

    // First escape backslashes
    let sqlPattern = pattern.replace(/\\/g, '\\\\');

    // Then replace wildcards with %
    sqlPattern = sqlPattern.replace(/\*/g, '%');

    return sqlPattern;
  };


  const getSearchTerms = (query) => {
    const terms = [];
    let currentTerm = '';
    let inQuotes = false;

    for (let i = 0; i < query.length; i++) {
      const char = query[i];

      if (char === '"') {
        inQuotes = !inQuotes;
        if (!inQuotes && currentTerm) {
          terms.push(currentTerm.trim());
          currentTerm = '';
        }
      } else if (char === ' ' && !inQuotes) {
        if (currentTerm) {
          terms.push(currentTerm.trim());
          currentTerm = '';
        }
      } else {
        currentTerm += char;
      }
    }

    if (currentTerm) {
      terms.push(currentTerm.trim());
    }

    return terms.filter(term => term.length > 0);
  };

  const formatSearchQuery = (query) => {
    return query.trim().replace(/\s+/g, ' ');
  };

  const getContextSnippet = (content, searchTerms) => {
    const lines = content.split('\n');
    const matchedLines = new Set();
    const contextLines = 2;
    const maxTotalLines = 10;

    lines.forEach((line, index) => {
      const lowerLine = line.toLowerCase();
      if (searchTerms.some(term => {
        if (term.includes(' ')) {
          return lowerLine.includes(term.toLowerCase());
        } else {
          return lowerLine.includes(term.toLowerCase());
        }
      })) {
        for (let i = Math.max(0, index - contextLines); i <= Math.min(lines.length - 1, index + contextLines); i++) {
          matchedLines.add(i);
        }
      }
    });

    let sortedLines = Array.from(matchedLines).sort((a, b) => a - b);
    let totalMatchGroups = Math.ceil(maxTotalLines / (2 * contextLines + 1));
    if (sortedLines.length > maxTotalLines) {
      let groups = [];
      let currentGroup = [];

      for (let i = 0; i < sortedLines.length; i++) {
        if (i > 0 && sortedLines[i] > sortedLines[i - 1] + contextLines + 1) {
          groups.push(currentGroup);
          currentGroup = [];
        }
        currentGroup.push(sortedLines[i]);
      }
      if (currentGroup.length > 0) {
        groups.push(currentGroup);
      }

      sortedLines = groups.slice(0, totalMatchGroups)
        .flatMap(group => group);
    }

    let snippet = '';
    let lastLine = -1;
    sortedLines.forEach(lineNum => {
      if (lastLine !== -1 && lineNum > lastLine + 1) {
        snippet += '\n...\n';
      }
      snippet += lines[lineNum] + '\n';
      lastLine = lineNum;
    });

    if (matchedLines.size > sortedLines.length) {
      snippet += '\n... (additional matches truncated)';
    }

    return {
      snippet: snippet.trim(),
      matchedLineNumbers: sortedLines.map(i => i + 1),
      totalMatches: matchedLines.size
    };
  };

  // Effect to perform search when debouncedQuery changes
  useEffect(() => {
    const performSearch = async () => {
      if (!debouncedQuery.trim()) {
        setSearchResults([]);
        return;
      }

      setLoading(true);
      setError(null);

      try {
        const now = new Date();
        let startDate = null;
        let endDate = null;

        if (filters.dateRange !== 'any') {
          endDate = now;
          startDate = new Date();
          switch (filters.dateRange) {
            case 'day':
              startDate.setDate(now.getDate() - 1);
              break;
            case 'week':
              startDate.setDate(now.getDate() - 7);
              break;
            case 'month':
              startDate.setMonth(now.getMonth() - 1);
              break;
            default:
              break;
          }
        }

        const query = {
          query: `
            query SearchDocuments($searchQuery: String!, $pathPattern: String!, $sourcePattern: String!, $agentPattern: String!, $project: String, $startDate: timestamptz, $endDate: timestamptz) {
              search_documents(
                args: {
                  search_query: $searchQuery,
                  path_pattern: $pathPattern,
                  source_pattern: $sourcePattern,
                  agent_pattern: $agentPattern,
                  project_name: $project,
                  start_date: $startDate,
                  end_date: $endDate,
                  max_results: 100
                }
              ) {
                object_id
                chunk_number
                content
                file_name
                path
                extension
                project
                agent_id
                source
                timestamp
              }
            }
          `,
          variables: {
            searchQuery: formatSearchQuery(debouncedQuery),
            pathPattern: convertWildcardToLike(filters.pathPattern),
            sourcePattern: convertWildcardToLike(filters.sourcePattern),
            agentPattern: convertWildcardToLike(filters.agentPattern),
            project: filters.project || null,
            startDate: startDate?.toISOString() || null,
            endDate: endDate?.toISOString() || null
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
          throw new Error('Network response was not ok');
        }

        const data = await response.json();
        if (data.errors) {
          throw new Error(data.errors[0].message);
        }

        const searchTerms = getSearchTerms(debouncedQuery);
        const processedResults = data.data.search_documents.map(result => {
          const { snippet, matchedLineNumbers, totalMatches } = getContextSnippet(result.content, searchTerms);

          return {
            object_id: result.object_id,
            file_name: result.file_name,
            file_path: result.path,
            content_preview: snippet,
            file_type: result.extension.toUpperCase(),
            project: result.project,
            agent_id: result.agent_id,
            source: result.source,
            matched_lines: matchedLineNumbers,
            total_matches: totalMatches,
            timestamp: result.timestamp
          };
        });

        setSearchResults(processedResults);
      } catch (err) {
        setError(err.message);
        console.error('Search error:', err);
      } finally {
        setLoading(false);
      }
    };

    performSearch();
  }, [debouncedQuery, filters]);

  const highlightMatchedText = (text, query) => {
    if (!query.trim()) return text;

    const searchTerms = getSearchTerms(query);
    const parts = [];
    let lastIndex = 0;

    const patterns = searchTerms.map(term => {
      if (term.includes(' ')) {
        return term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      } else {
        return `\\b${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`;
      }
    });

    const regex = new RegExp(`(${patterns.join('|')})`, 'gi');

    text.split(regex).forEach((part, i) => {
      if (searchTerms.some(term => part.toLowerCase() === term.toLowerCase())) {
        parts.push(
          <span key={i} className="bg-teal-300 dark:bg-green-700 bg-opacity-70">{part}</span>

        );
      } else {
        parts.push(part);
      }
    });

    return <span>{parts}</span>;
  };

  return (
    <div className="max-w-8xl mx-auto">
      <div className="flex gap-2 mb-6">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500 w-5 h-5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder='Search documents... (use quotes for exact phrases: "example phrase")'
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-dark-secondary border dark:border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:text-gray-200 transition-colors"
          />
        </div>
        <button
          type="button"
          onClick={() => setIsAdvancedOpen(!isAdvancedOpen)}
          className="flex items-center gap-1 px-4 py-2 border dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 dark:text-gray-300 transition-colors"
        >
          <Filter className="w-4 h-4" />
          <ChevronDown className="w-4 h-4" />
        </button>
      </div>

      {isAdvancedOpen && (
        <div className="mt-4 p-4 border dark:border-gray-700 rounded-lg bg-gray-50 dark:bg-gray-800 transition-colors mb-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Path Pattern
              </label>
              <input
                type="text"
                value={filters.pathPattern}
                onChange={(e) => setFilters({ ...filters, pathPattern: e.target.value })}
                placeholder="e.g., *.py"
                className="w-full p-2 border dark:border-gray-700 rounded bg-white dark:bg-dark-secondary dark:text-gray-300 transition-colors"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Source
              </label>
              <input
                type="text"
                value={filters.sourcePattern}
                onChange={(e) => setFilters({ ...filters, sourcePattern: e.target.value })}
                placeholder="e.g., host://* or https://*"
                className="w-full p-2 border dark:border-gray-700 rounded bg-white dark:bg-dark-secondary dark:text-gray-300 transition-colors"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Agent ID
              </label>
              <input
                type="text"
                value={filters.agentPattern}
                onChange={(e) => setFilters({ ...filters, agentPattern: e.target.value })}
                placeholder="e.g., agent.*"
                className="w-full p-2 border dark:border-gray-700 rounded bg-white dark:bg-dark-secondary dark:text-gray-300 transition-colors"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Project
              </label>
              <input
                type="text"
                value={filters.project}
                onChange={(e) => setFilters({ ...filters, project: e.target.value })}
                placeholder="Enter project name"
                className="w-full p-2 border dark:border-gray-700 rounded bg-white dark:bg-dark-secondary dark:text-gray-300 transition-colors"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Date Range
              </label>
              <select
                value={filters.dateRange}
                onChange={(e) => setFilters({ ...filters, dateRange: e.target.value })}
                className="w-full p-2 border dark:border-gray-700 rounded bg-white dark:bg-dark-secondary dark:text-gray-300 transition-colors"
              >
                <option value="any">Any Time</option>
                <option value="day">Past 24 Hours</option>
                <option value="week">Past Week</option>
                <option value="month">Past Month</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-center gap-2 transition-colors">
          <AlertTriangle className="h-4 w-4 text-red-500 dark:text-red-400" />
          <span className="text-red-700 dark:text-red-400">{error}</span>
        </div>
      )}

      {loading && (
        <div className="flex justify-center py-8">
          <Loader2 className="h-8 w-8 animate-spin text-blue-600 dark:text-blue-400" />
        </div>
      )}

      {!loading && searchResults.length > 0 && (
        <div className="space-y-2">
          {searchResults.map((result) => (
            <div key={result.object_id} className="bg-white dark:bg-dark-secondary rounded-lg shadow p-4">
              <div className="flex items-start gap-3">
                <FileText className="w-4 h-5 text-gray-400 dark:text-gray-500 mt-1" />
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <h3
                      onClick={() => navigate(`/files/${result.object_id}`, {
                        state: { from: 'search' }
                      })}
                      className="text-lg font-medium text-blue-600 dark:text-blue-400 cursor-pointer hover:underline"
                    >
                      {result.file_name}
                    </h3>
                    <span className="text-sm text-gray-500 dark:text-gray-400">
                      {result.file_type}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                    {result.file_path}
                  </p>
                  <pre className="bg-gray-300 dark:bg-gray-800 p-3 rounded-lg text-sm font-mono whitespace-pre-wrap break-all text-gray-800 dark:text-gray-200 transition-colors">
                    {highlightMatchedText(result.content_preview, debouncedQuery)}
                  </pre>
                  <div className="mt-2 flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
                    <span>Project: {result.project}</span>
                    <span>Source: {result.source || 'Unknown'}</span>
                    <span>Agent ID: {result.agent_id}</span>
                    <span>
                      {new Date(result.timestamp).toLocaleDateString()}
                    </span>
                    <span>
                      Matches on lines: {result.matched_lines.join(', ')}
                    </span>
                    <span>
                      Total matches: {result.total_matches}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {!loading && searchQuery && searchResults.length === 0 && (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400">
          No results found for "{searchQuery}"
        </div>
      )}
    </div>
  );
};

export default DocumentSearch;
import { AlertTriangle, ChevronDown, ChevronRight, Loader2, X } from 'lucide-react';
import React, { useEffect, useState } from 'react';

const NoseyParkerViewer = () => {
  const [findings, setFindings] = useState([]);
  const [expandedFindings, setExpandedFindings] = useState({});
  const [dismissedFindings, setDismissedFindings] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchNoseyParkerResults();
  }, []);

  const fetchNoseyParkerResults = async () => {
    try {
      const query = {
        query: `
          query FetchNoseyParkerResults {
            files_enriched(where: {processors: {_has_key: "noseyparker"}}) {
              object_id
              file_name
              path
              timestamp
              processors
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
        throw new Error(`Network response was not ok: ${response.status} ${response.statusText}`);
      }

      const responseData = await response.json();

      if (responseData.errors) {
        throw new Error(responseData.errors[0].message);
      }

      const { files_enriched } = responseData.data;
      const allFindings = new Map();

      files_enriched.forEach(file => {
        const noseyParkerResults = file.processors?.noseyparker?.analysis?.results || [];

        noseyParkerResults.forEach(result => {
          if (!result || !result.finding_id) return;

          const finding = allFindings.get(result.finding_id) || {
            ...result,
            files: new Set(),
            allMatches: []
          };

          finding.files.add(file.file_name);
          const fileMatches = result.matches.map(match => ({
            ...match,
            file_name: file.file_name,
            file_path: file.path,
            timestamp: file.timestamp
          }));

          finding.allMatches.push(...fileMatches);
          allFindings.set(result.finding_id, finding);
        });
      });

      const processedFindings = Array.from(allFindings.values())
        .map(finding => ({
          finding_id: finding.finding_id,
          rule_name: finding.rule_name,
          num_matches: finding.allMatches.length,
          num_files: finding.files.size,
          matches: finding.allMatches.sort((a, b) =>
            new Date(b.timestamp) - new Date(a.timestamp)
          ),
          files: Array.from(finding.files)
        }))
        .sort((a, b) => b.num_matches - a.num_matches);

      setFindings(processedFindings);
    } catch (err) {
      console.error('Error fetching NoseyParker results:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const toggleFinding = (findingId) => {
    setExpandedFindings(prev => ({
      ...prev,
      [findingId]: !prev[findingId]
    }));
  };

  const dismissFinding = (findingId) => {
    setDismissedFindings(prev => ({
      ...prev,
      [findingId]: true
    }));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 text-blue-500 dark:text-blue-400 animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 transition-colors">
        <div className="flex items-start">
          <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400 mt-0.5 mr-2 flex-shrink-0" />
          <div>
            <h3 className="font-medium text-red-800 dark:text-red-300">Error loading NoseyParker results</h3>
            <p className="text-red-700 dark:text-red-400 mt-1 text-sm">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 transition-colors">
        <div className="flex items-center">
          <AlertTriangle className="w-5 h-5 text-yellow-500 dark:text-yellow-400 mr-2" />
          <p className="text-yellow-700 dark:text-yellow-300">No NoseyParker findings detected in the scanned files.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-4 transition-colors">
        <p className="text-blue-700 dark:text-blue-300">
          Found {findings.length} potential {findings.length === 1 ? 'issue' : 'issues'} across {
            findings.reduce((sum, f) => sum + f.num_files, 0)
          } {findings.reduce((sum, f) => sum + f.num_files, 0) === 1 ? 'file' : 'files'}.
        </p>
      </div>

      {findings
        .filter(f => !dismissedFindings[f.finding_id])
        .map((finding) => (
          <div key={finding.finding_id} className="bg-white dark:bg-dark-secondary rounded-lg shadow transition-colors">
            <div className="p-4 border-b dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <AlertTriangle className="w-5 h-5 text-yellow-500 dark:text-yellow-400" />
                  <button
                    onClick={() => toggleFinding(finding.finding_id)}
                    className="flex items-center space-x-2 text-gray-900 dark:text-gray-100"
                  >
                    {expandedFindings[finding.finding_id] ? (
                      <ChevronDown className="w-4 h-4" />
                    ) : (
                      <ChevronRight className="w-4 h-4" />
                    )}
                    <span className="font-medium">{finding.rule_name}</span>
                  </button>
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    ({finding.num_matches} {finding.num_matches === 1 ? 'match' : 'matches'} in {finding.num_files} {finding.num_files === 1 ? 'file' : 'files'})
                  </span>
                </div>
                <button
                  onClick={() => dismissFinding(finding.finding_id)}
                  className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded transition-colors"
                  title="Dismiss"
                >
                  <X className="w-4 h-4 text-gray-500 dark:text-gray-400" />
                </button>
              </div>
            </div>

            {expandedFindings[finding.finding_id] && (
              <div className="p-4 space-y-4">
                {finding.matches.map((match, index) => (
                  <div
                    key={`${finding.finding_id}-${index}`}
                    className="bg-gray-50 dark:bg-gray-800/50 p-4 rounded-lg transition-colors"
                  >
                    <div className="flex justify-between mb-2">
                      <div className="text-sm font-medium text-gray-900 dark:text-gray-100">
                        {match.file_name}
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        Line {match.location.source_span.start.line}, Column {match.location.source_span.start.column}
                      </div>
                    </div>
                    <div className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                      {match.file_path}
                    </div>
                    <div className="font-mono text-sm bg-gray-100 dark:bg-gray-800 p-3 rounded overflow-x-auto whitespace-pre transition-colors">
                      <span className="text-gray-500 dark:text-gray-400">{match.snippet.before}</span>
                      <span className="bg-yellow-200 dark:bg-yellow-500/30 px-1">{match.snippet.matching}</span>
                      <span className="text-gray-500 dark:text-gray-400">{match.snippet.after}</span>
                    </div>
                    <div className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                      {new Date(match.timestamp).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
    </div>
  );
};

export default NoseyParkerViewer;
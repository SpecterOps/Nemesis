// src/components/Yara/YaraManager.jsx
import { useTheme } from '@/components/ThemeProvider';
import { useUser } from '@/contexts/UserContext';
import Editor from "@monaco-editor/react";
import {
  AlertTriangle,
  Check,
  Clock,
  Edit,
  Filter, PlusCircle,
  Save,
  Search,
  X
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';

const Tooltip = ({ children, content, position = 'top' }) => {
  const [isVisible, setIsVisible] = useState(false);
  return (
    <div className="relative inline-block"
      onMouseEnter={() => setIsVisible(true)}
      onMouseLeave={() => setIsVisible(false)}>
      {children}
      {isVisible && (
        <div className={`absolute z-10 px-2 py-1 text-sm text-white bg-gray-900 rounded-md whitespace-nowrap left-1/2 transform -translate-x-1/2 ${position === 'bottom' ? 'top-full mt-2' : '-top-8'
          }`}>
          {content}
          <div className={`absolute left-1/2 transform -translate-x-1/2 w-2 h-2 bg-gray-900 rotate-45 ${position === 'bottom' ? '-top-1' : '-bottom-1'
            }`}></div>
        </div>
      )}
    </div>
  );
};

const Modal = ({ isOpen, onClose, children }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="fixed inset-0 bg-black bg-opacity-50 transition-opacity" onClick={onClose}></div>
      <div className="flex min-h-full items-center justify-center p-4">
        <div className="relative bg-white dark:bg-dark-secondary rounded-lg shadow-xl max-w-4xl w-full h-[80vh] overflow-hidden">
          {children}
        </div>
      </div>
    </div>
  );
};

const YaraRulesManager = () => {
  const { isDark } = useTheme();
  const { username } = useUser();
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [operationError, setOperationError] = useState(null);

  // Filter states
  const [nameFilter, setNameFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [enabledFilter, setEnabledFilter] = useState('all');
  const [sortNewest, setSortNewest] = useState(true);

  // Editor states
  const [selectedRule, setSelectedRule] = useState(null);
  const [editedContent, setEditedContent] = useState('');
  const [isEditorOpen, setIsEditorOpen] = useState(false);
  const [isNewRule, setIsNewRule] = useState(false);
  const [newRuleSource, setNewRuleSource] = useState('');
  const [needsReload, setNeedsReload] = useState(false);
  const [isReloading, setIsReloading] = useState(false);
  const [showReloadAlert, setShowReloadAlert] = useState(false);
  const [isBulkRunning, setIsBulkRunning] = useState(false);

  // Set source to username when creating a new rule
  useEffect(() => {
    if (isNewRule && username) {
      setNewRuleSource(username);
    }
  }, [isNewRule, username]);

  const extractRuleName = (content) => {
    const ruleRegex = /(?:private\s+)?rule\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\/\/[^\n]*)?[\s\n]*{/;
    const match = content.match(ruleRegex);
    return match ? match[1] : null;
  };

  // Fetch rules on component mount
  useEffect(() => {
    const fetchRules = async () => {
      try {
        const query = {
          query: `
            query YaraQuery {
              yara_rules {
                created_at
                source
                updated_at
                enabled
                name
                content
                alert_enabled
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

        setRules(result.data.yara_rules);
      } catch (err) {
        console.error('Error fetching rules:', err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchRules();
  }, []);

  // Filter and sort rules
  const filteredRules = useMemo(() => {
    return rules
      .filter(rule => {
        if (nameFilter && !rule.name.toLowerCase().includes(nameFilter.toLowerCase())) return false;
        if (sourceFilter && !rule.source.toLowerCase().includes(sourceFilter.toLowerCase())) return false;
        if (enabledFilter === 'enabled' && !rule.enabled) return false;
        if (enabledFilter === 'disabled' && rule.enabled) return false;
        return true;
      })
      .sort((a, b) => {
        const dateA = new Date(a.created_at);
        const dateB = new Date(b.created_at);
        return sortNewest ? dateB - dateA : dateA - dateB;
      });
  }, [rules, nameFilter, sourceFilter, enabledFilter, sortNewest]);

  // Handle rule updates
  const updateRule = async (rule, newContent) => {
    try {
      const mutation = {
        query: `
          mutation UpdateRule($name: String!, $content: String!) {
            update_yara_rules(
              where: { name: { _eq: $name }},
              _set: { content: $content, updated_at: "now()" }
            ) {
              affected_rows
            }
          }
        `,
        variables: {
          name: rule.name,
          content: newContent
        }
      };

      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(mutation)
      });

      if (!response.ok) throw new Error('Network error');

      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

      // Update local state
      setRules(rules.map(r =>
        r.name === rule.name ? { ...r, content: newContent } : r
      ));
      setNeedsReload(true);
      setShowReloadAlert(true);
      setIsEditorOpen(false);
    } catch (err) {
      setOperationError(`Failed to update rule: ${err.message}`);
    }
  };

  // Handle creating new rules
  const createRule = async () => {
    try {
      const ruleName = extractRuleName(editedContent);
      if (!ruleName) {
        throw new Error('No valid rule name found in content');
      }

      // Check if rule name exists
      const existingRule = rules.find(r => r.name === ruleName);
      if (existingRule) {
        throw new Error('Rule name already exists');
      }

      const mutation = {
        query: `
          mutation CreateRule($rule: yara_rules_insert_input!) {
            insert_yara_rules_one(object: $rule) {
              name
              content
              source
              enabled
              alert_enabled
              created_at
              updated_at
            }
          }
        `,
        variables: {
          rule: {
            name: ruleName,
            content: editedContent,
            source: newRuleSource,
            enabled: true,
            alert_enabled: true,
          }
        }
      };

      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(mutation)
      });

      if (!response.ok) throw new Error('Network error');

      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

      // Update local state
      setRules([...rules, result.data.insert_yara_rules_one]);
      setNeedsReload(true);
      setShowReloadAlert(true);
      setIsEditorOpen(false);
      setIsNewRule(false);
      setNewRuleSource('');
      setEditedContent('');
    } catch (err) {
      setOperationError(`Failed to create rule: ${err.message}`);
    }
  };

  // Handle toggling rule enabled state
  const toggleRuleEnabled = async (rule) => {
    try {
      const mutation = {
        query: `
          mutation ToggleRule($name: String!, $enabled: Boolean!) {
            update_yara_rules(
              where: { name: { _eq: $name }},
              _set: { enabled: $enabled }
            ) {
              affected_rows
            }
          }
        `,
        variables: {
          name: rule.name,
          enabled: !rule.enabled
        }
      };

      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(mutation)
      });

      if (!response.ok) throw new Error('Network error');

      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

      // Update local state
      setRules(rules.map(r =>
        r.name === rule.name ? { ...r, enabled: !r.enabled } : r
      ));
      setNeedsReload(true);
      setShowReloadAlert(true);
    } catch (err) {
      setOperationError(`Failed to toggle rule: ${err.message}`);
    }
  };

  // Add reload handler
  const handleReload = async () => {
    try {
      setIsReloading(true);
      setShowReloadAlert(false);
      await fetch('/api/system/yara/reload', { method: 'POST' });
      setNeedsReload(false);

      // Show reload notification for 20 seconds
      setTimeout(() => {
        setIsReloading(false);
      }, 20000);
    } catch (err) {
      setOperationError(`Failed to reload Yara engine: ${err.message}`);
      setIsReloading(false);
    }
  };

  // Add bulk re-run handler
  const handleBulkRerun = async () => {
    try {
      setIsBulkRunning(true);
      const response = await fetch('/api/enrichments/yara/bulk', { method: 'POST' });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Server returned ${response.status}: ${errorText || response.statusText}`);
      }

      // Show bulk re-run notification for 20 seconds
      setTimeout(() => {
        setIsBulkRunning(false);
      }, 20000);
    } catch (err) {
      setOperationError(`Failed to trigger bulk Yara re-run: ${err.message}`);
      setIsBulkRunning(false);
    }
  };

  if (error) {
    return (
      <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2">
        <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
        <div className="flex flex-col">
          <span className="text-red-600 dark:text-red-400">Error: {error}</span>
          <span className="text-sm text-red-500 dark:text-red-400">Please try again or check console for details</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 w-full overflow-x-hidden">
      <div className="bg-white dark:bg-dark-secondary rounded-lg shadow-lg overflow-hidden w-full">
        <div className="px-6 py-4 border-b dark:border-gray-700">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Yara Rules</h2>
            <div className="flex space-x-2">
              <button
                onClick={() => {
                  setIsNewRule(true);
                  setIsEditorOpen(true);
                  setEditedContent('');
                }}
                className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                <PlusCircle className="w-4 h-4" />
                <span>New Rule</span>
              </button>
              <Tooltip content="Signal the Nemesis Yara engine to reload the modified rule set" position="bottom">
                <button
                  onClick={handleReload}
                  disabled={!needsReload || isReloading}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${needsReload
                    ? 'bg-green-600 text-white hover:bg-green-700'
                    : 'bg-gray-300 text-gray-500 cursor-not-allowed dark:bg-gray-700 dark:text-gray-400'
                    }`}
                >
                  <Clock className="w-4 h-4" />
                  <span>Reload Yara Engine</span>
                </button>
              </Tooltip>
              <Tooltip content="Trigger a bulk re-run of all Yara rules against all files in the system" position="bottom">
                <button
                  onClick={handleBulkRerun}
                  disabled={isBulkRunning}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${isBulkRunning
                    ? 'bg-gray-300 text-gray-500 cursor-not-allowed dark:bg-gray-700 dark:text-gray-400'
                    : 'bg-orange-600 text-white hover:bg-orange-700'
                    }`}
                >
                  <Clock className="w-4 h-4" />
                  <span>Re-run Yara Rules</span>
                </button>
              </Tooltip>
            </div>
          </div>

          {/* Alert Messages */}
          {operationError && (
            <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400" />
                <span className="text-red-800 dark:text-red-300 font-medium">
                  {operationError}
                </span>
              </div>
              <button
                onClick={() => setOperationError(null)}
                className="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          )}

          {showReloadAlert && needsReload && !isReloading && (
            <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
              <span className="text-yellow-800 dark:text-yellow-300 font-medium">
                Click 'Reload Yara Engine' to Register Rule Changes
              </span>
            </div>
          )}

          {isReloading && (
            <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg flex items-center space-x-2">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600 dark:border-blue-400"></div>
              <span className="text-blue-800 dark:text-blue-300 font-medium">
                Yara Engine is Reloading...
              </span>
            </div>
          )}

          {isBulkRunning && (
            <div className="mt-4 p-3 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg flex items-center space-x-2">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-orange-600 dark:border-orange-400"></div>
              <span className="text-orange-800 dark:text-orange-300 font-medium">
                Re-running Yara Rules...
              </span>
            </div>
          )}
        </div>

        <div className="p-6">
          {/* Filters */}
          <div className="flex flex-wrap gap-4 items-center mb-6">
            <div className="flex items-center space-x-2">
              <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              <input
                type="text"
                placeholder="Filter by name"
                className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-100 rounded p-2"
                value={nameFilter}
                onChange={(e) => setNameFilter(e.target.value)}
              />
            </div>

            <div className="flex items-center space-x-2">
              <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              <input
                type="text"
                placeholder="Filter by source"
                className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-100 rounded p-2"
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
              />
            </div>

            <div className="flex items-center space-x-2">
              <Filter className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              <select
                className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
                value={enabledFilter}
                onChange={(e) => setEnabledFilter(e.target.value)}
              >
                <option value="all">All Rules</option>
                <option value="enabled">Enabled Only</option>
                <option value="disabled">Disabled Only</option>
              </select>
            </div>

            <Tooltip content={sortNewest ? "Showing newest first" : "Showing oldest first"}>
              <button
                className="flex items-center space-x-2 px-3 py-2 border dark:border-gray-700 rounded hover:bg-gray-100 dark:hover:bg-gray-700"
                onClick={() => setSortNewest(!sortNewest)}
              >
                <Clock className="w-5 h-5 text-gray-500 dark:text-gray-400" />
                <span className="text-sm text-gray-700 dark:text-gray-300">
                  {sortNewest ? "Newest First" : "Oldest First"}
                </span>
              </button>
            </Tooltip>
          </div>

          {/* Rules Table */}
          <div className="overflow-x-auto relative w-full">
            <table className="min-w-full table-fixed">
              <thead>
                <tr className="bg-gray-50 dark:bg-gray-800">
                  <th className="w-20 px-6 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">Status</th>
                  <th className="w-48 px-6 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">Name</th>
                  <th className="w-96 px-6 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">Source</th>
                  <th className="w-40 px-6 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">Created</th>
                  <th className="w-40 px-6 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">Updated</th>
                  <th className="w-24 px-6 py-3 text-left text-sm font-medium text-gray-500 dark:text-gray-400">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {loading ? (
                  <tr>
                    <td colSpan="6" className="px-6 py-4 text-center">
                      <div className="flex justify-center">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
                      </div>
                    </td>
                  </tr>
                ) : (
                  filteredRules.map((rule) => (
                    <tr
                      key={rule.name}
                      className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                    >
                      <td className="px-6 py-4">
                        <button
                          onClick={() => toggleRuleEnabled(rule)}
                          className={`p-1 rounded-full ${rule.enabled
                            ? 'bg-green-100 dark:bg-green-900/20 text-green-600 dark:text-green-400'
                            : 'bg-red-100 dark:bg-red-900/20 text-red-600 dark:text-red-400'
                            } hover:opacity-80 transition-opacity`}
                        >
                          {rule.enabled ? <Check className="w-4 h-4" /> : <X className="w-4 h-4" />}
                        </button>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-900 dark:text-gray-100 max-w-md truncate whitespace-normal break-words">
                        {rule.name}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                        {rule.source}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                        {new Date(rule.created_at).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                        {new Date(rule.updated_at).toLocaleString()}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex space-x-2">
                          <Tooltip content="Edit Rule">
                            <button
                              onClick={() => {
                                setSelectedRule(rule);
                                setEditedContent(rule.content);
                                setIsEditorOpen(true);
                                setIsNewRule(false);
                              }}
                              className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                            >
                              <Edit className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                            </button>
                          </Tooltip>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Editor Modal */}
      <Modal
        isOpen={isEditorOpen}
        onClose={() => {
          setIsEditorOpen(false);
          setSelectedRule(null);
          setEditedContent('');
          setIsNewRule(false);
          setNewRuleSource('');
        }}
      >
        <div className="flex flex-col h-full">
          <div className="px-6 py-4 border-b dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              {isNewRule ? 'Create New Yara Rule' : 'Edit Yara Rule'}
            </h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {isNewRule
                ? 'Create a new Yara rule. The rule name will be extracted from your rule definition.'
                : `Editing rule: ${selectedRule?.name}`
              }
            </p>
          </div>

          <div className="flex-1 overflow-y-auto p-6">
            {isNewRule && (
              <div className="flex flex-col space-y-4 mb-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Source
                  </label>
                  <input
                    type="text"
                    value={newRuleSource}
                    onChange={(e) => setNewRuleSource(e.target.value)}
                    className="w-full border dark:border-gray-700 rounded-md px-3 py-2 dark:bg-gray-800 dark:text-gray-100"
                    placeholder="Enter rule source"
                  />
                </div>
              </div>
            )}

            <div className="h-[calc(100%-2rem)]">
              <Editor
                height="100%"
                language="yara"
                theme={isDark ? "vs-dark" : "light"}
                value={editedContent}
                onChange={setEditedContent}
                options={{
                  minimap: { enabled: true },
                  scrollBeyondLastLine: false,
                  fontSize: 14,
                  wordWrap: 'on'
                }}
              />
            </div>
          </div>

          <div className="px-6 py-4 border-t dark:border-gray-700 flex justify-end space-x-2">
            <button
              onClick={() => {
                setIsEditorOpen(false);
                setSelectedRule(null);
                setEditedContent('');
                setIsNewRule(false);
                setNewRuleSource('');
              }}
              className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={() => {
                if (isNewRule) {
                  createRule();
                } else {
                  updateRule(selectedRule, editedContent);
                }
              }}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={isNewRule && (!newRuleSource || !editedContent || !extractRuleName(editedContent))}
            >
              <Save className="w-4 h-4" />
              <span>{isNewRule ? 'Create' : 'Save'}</span>
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default YaraRulesManager;
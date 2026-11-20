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
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

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

// Editor modal: closes on Escape, the X button or a click outside it. With unsaved edits those ask
// first (an inline "discard?" bar), so a stray click or keypress can't throw work away.
const Modal = ({ isOpen, onClose, isDirty = false, children }) => {
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const keepEditingRef = useRef(null);
  const [wasOpen, setWasOpen] = useState(isOpen);
  if (wasOpen !== isOpen) {
    setWasOpen(isOpen);
    setConfirmDiscard(false);
  }

  const requestClose = useCallback(() => {
    if (isDirty) setConfirmDiscard(true);
    else onClose();
  }, [isDirty, onClose]);

  useEffect(() => {
    if (!isOpen) return undefined;
    const handleEsc = (e) => {
      if (e.key !== 'Escape') return;
      // Let Monaco close its own popups (suggestions, find widget) first
      if (e.target instanceof Element && e.target.closest('.monaco-editor')
        && document.querySelector('.monaco-editor .suggest-widget.visible, .monaco-editor .find-widget.visible')) return;
      if (confirmDiscard) setConfirmDiscard(false);
      else requestClose();
    };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [isOpen, requestClose, confirmDiscard]);

  // Move focus to the safe choice so a stray Enter/Space keeps the edits
  useEffect(() => {
    if (confirmDiscard) keepEditingRef.current?.focus();
  }, [confirmDiscard]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="fixed inset-0 bg-black bg-opacity-50 transition-opacity" role="presentation" onClick={requestClose} />
      {/* Clicks on the area around the dialog (not inside it) count as "close"; keyboard users use
          Escape or the Close button */}
      <div
        className="relative flex min-h-full items-center justify-center p-4"
        role="presentation"
        onClick={(e) => { if (e.target === e.currentTarget) requestClose(); }}
      >
        <div role="dialog" aria-modal="true" className="relative bg-white dark:bg-dark-secondary rounded-lg shadow-xl max-w-4xl w-full h-[80vh] overflow-hidden">
          <button
            onClick={requestClose}
            className="absolute top-3 right-3 z-10 p-1 rounded hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
            aria-label="Close"
          >
            <X className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          </button>
          {confirmDiscard && (
            <div role="alertdialog" aria-label="Discard unsaved changes" className="absolute inset-x-0 top-0 z-20 px-6 py-3 bg-amber-50 dark:bg-amber-900/40 border-b border-amber-200 dark:border-amber-800 flex flex-wrap items-center gap-2 text-sm">
              <span className="text-amber-800 dark:text-amber-200 font-medium">Discard unsaved changes?</span>
              <span className="flex gap-2 ml-auto">
                <button onClick={onClose} className="px-3 py-1 rounded bg-amber-600 hover:bg-amber-700 text-white">Discard</button>
                <button ref={keepEditingRef} onClick={() => setConfirmDiscard(false)} className="px-3 py-1 rounded bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-800 dark:text-gray-200">Keep editing</button>
              </span>
            </div>
          )}
          {children}
        </div>
      </div>
    </div>
  );
};

const RULES_PAGE_SIZE = 100;

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
  const [page, setPage] = useState(0);

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
        const dateA = new Date(a.created_at).getTime();
        const dateB = new Date(b.created_at).getTime();
        return sortNewest ? dateB - dateA : dateA - dateB;
      });
  }, [rules, nameFilter, sourceFilter, enabledFilter, sortNewest]);

  // Only one page of rules is rendered (thousands of rows with tooltips are slow to mount).
  // The filter/sort handlers below reset to the first page.
  const pageCount = Math.max(1, Math.ceil(filteredRules.length / RULES_PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const pageRules = filteredRules.slice(currentPage * RULES_PAGE_SIZE, (currentPage + 1) * RULES_PAGE_SIZE);

  // Load a rule's body on demand and open it in the editor
  const openRuleEditor = async (rule) => {
    try {
      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify({
          query: `
            query GetYaraRuleContent($name: String!) {
              yara_rules_by_pk(name: $name) { content }
            }
          `,
          variables: { name: rule.name }
        })
      });
      if (!response.ok) throw new Error(`Network response error: ${response.status}`);
      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);
      const content = result.data.yara_rules_by_pk?.content ?? '';
      setSelectedRule({ ...rule, content });
      setEditedContent(content);
      setIsEditorOpen(true);
      setIsNewRule(false);
    } catch (err) {
      setOperationError(`Failed to load rule: ${err.message}`);
    }
  };

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
        r.name === rule.name ? { ...r, updated_at: new Date().toISOString() } : r
      ));
      setNeedsReload(true);
      setShowReloadAlert(true);
      setIsEditorOpen(false);
    } catch (err) {
      setOperationError(`Failed to update rule: ${err.message}`);
    }
  };

  // Derive duplicate-name check for the Create dialog
  const extractedRuleName = isNewRule ? extractRuleName(editedContent) : null;
  const isDuplicateName = extractedRuleName ? rules.some(r => r.name === extractedRuleName) : false;

  // Handle creating new rules
  const createRule = async () => {
    try {
      const ruleName = extractRuleName(editedContent);
      if (!ruleName) {
        throw new Error('No valid rule name found in content');
      }

      if (rules.some(r => r.name === ruleName)) {
        throw new Error(`A rule named "${ruleName}" already exists. Change the rule name to create a new rule.`);
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
      const createdRule = { ...result.data.insert_yara_rules_one };
      delete createdRule.content;
      setRules([...rules, createdRule]);
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
  // eslint-disable-next-line no-unused-vars -- button is temporarily disabled (commented out below); kept for re-enable
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
                  // Default the source to the current user
                  if (username) setNewRuleSource(`Created manually by ${username}`);
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
              {/* Temporarily disabled - will re-enable later */}
              {/* <Tooltip content="Trigger a bulk re-run of all Yara rules against all files in the system" position="bottom">
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
              </Tooltip> */}
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
                Click &apos;Reload Yara Engine&apos; to Register Rule Changes
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
                onChange={(e) => {
                  setNameFilter(e.target.value);
                  setPage(0);
                }}
              />
            </div>

            <div className="flex items-center space-x-2">
              <Search className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              <input
                type="text"
                placeholder="Filter by source"
                className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-100 rounded p-2"
                value={sourceFilter}
                onChange={(e) => {
                  setSourceFilter(e.target.value);
                  setPage(0);
                }}
              />
            </div>

            <div className="flex items-center space-x-2">
              <Filter className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              <select
                className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
                value={enabledFilter}
                onChange={(e) => {
                  setEnabledFilter(e.target.value);
                  setPage(0);
                }}
              >
                <option value="all">All Rules</option>
                <option value="enabled">Enabled Only</option>
                <option value="disabled">Disabled Only</option>
              </select>
            </div>

            <Tooltip content={sortNewest ? "Showing newest first" : "Showing oldest first"}>
              <button
                className="flex items-center space-x-2 px-3 py-2 border dark:border-gray-700 rounded hover:bg-gray-100 dark:hover:bg-gray-700"
                onClick={() => {
                  setSortNewest(!sortNewest);
                  setPage(0);
                }}
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
                  <th className="w-16 px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Status</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Name</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Source</th>
                  <th className="w-36 px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Created</th>
                  <th className="w-36 px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Updated</th>
                  <th className="w-16 px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {loading ? (
                  <tr>
                    <td colSpan={6} className="px-6 py-4 text-center">
                      <div className="flex justify-center">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
                      </div>
                    </td>
                  </tr>
                ) : (
                  pageRules.map((rule) => (
                    <tr
                      key={rule.name}
                      className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                    >
                      <td className="px-3 py-1.5">
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
                      <td className="px-3 py-1.5 text-sm text-gray-900 dark:text-gray-100 truncate">
                        {rule.name}
                      </td>
                      <td className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 truncate">
                        {rule.source}
                      </td>
                      <td className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 whitespace-nowrap">
                        {new Date(rule.created_at).toLocaleString()}
                      </td>
                      <td className="px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 whitespace-nowrap">
                        {new Date(rule.updated_at).toLocaleString()}
                      </td>
                      <td className="px-3 py-1.5">
                        <Tooltip content="Edit Rule">
                          <button
                            onClick={() => openRuleEditor(rule)}
                            className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                          >
                            <Edit className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                          </button>
                        </Tooltip>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {!loading && filteredRules.length > RULES_PAGE_SIZE && (
            <div className="flex items-center justify-between px-3 py-3 text-sm text-gray-600 dark:text-gray-400">
              <span>
                {(currentPage * RULES_PAGE_SIZE + 1).toLocaleString()}-
                {Math.min((currentPage + 1) * RULES_PAGE_SIZE, filteredRules.length).toLocaleString()} of{' '}
                {filteredRules.length.toLocaleString()} rules
              </span>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setPage(currentPage - 1)}
                  disabled={currentPage === 0}
                  className="px-3 py-1 rounded-md border dark:border-gray-700 disabled:opacity-40 hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  Previous
                </button>
                <span>Page {currentPage + 1} of {pageCount}</span>
                <button
                  onClick={() => setPage(currentPage + 1)}
                  disabled={currentPage >= pageCount - 1}
                  className="px-3 py-1 rounded-md border dark:border-gray-700 disabled:opacity-40 hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Editor Modal */}
      <Modal
        isOpen={isEditorOpen}
        isDirty={isNewRule ? editedContent.trim() !== '' : editedContent !== (selectedRule?.content ?? '')}
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
                  <label htmlFor="yara-new-rule-source" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Source
                  </label>
                  <input
                    id="yara-new-rule-source"
                    type="text"
                    value={newRuleSource}
                    onChange={(e) => setNewRuleSource(e.target.value)}
                    className="w-full border dark:border-gray-700 rounded-md px-3 py-2 dark:bg-gray-800 dark:text-gray-100"
                    placeholder="Rule source or origin"
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

          <div className="px-6 py-4 border-t dark:border-gray-700 flex items-center justify-between">
            {isNewRule && isDuplicateName ? (
              <div className="flex items-center space-x-2 text-yellow-600 dark:text-yellow-400">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                <span className="text-sm">A rule named &quot;{extractedRuleName}&quot; already exists. Change the rule name to create a new rule.</span>
              </div>
            ) : (
              <div />
            )}
            <div className="flex space-x-2">
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
                disabled={isNewRule
                  ? (!newRuleSource || !editedContent || !extractRuleName(editedContent) || isDuplicateName)
                  : (editedContent === selectedRule?.content)
                }
              >
                <Save className="w-4 h-4" />
                <span>{isNewRule ? 'Create' : 'Save'}</span>
              </button>
            </div>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default YaraRulesManager;
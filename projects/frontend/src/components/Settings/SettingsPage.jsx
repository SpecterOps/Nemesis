import { useUser } from '@/contexts/UserContext';
import { AlertTriangle, Bell, Bot, Calendar, Clock, Database, Edit3, Save, Trash2, User, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import Dialog from '../ui/dialog';

// SettingsSection component remains the same
const SettingsSection = ({ icon: Icon, title, description, children }) => (
  <div className="bg-white dark:bg-dark-secondary rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
    <div className="p-6">
      <div className="flex items-center gap-2 mb-1">
        <Icon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
          {title}
        </h3>
      </div>
      {description && (
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          {description}
        </p>
      )}
      {children}
    </div>
  </div>
);

// Status badge component for agents
const StatusBadge = ({ enabled, hasPrompt }) => {
  if (!enabled) {
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200">
        <X className="w-3 h-3 mr-1" />
        Disabled
      </span>
    );
  }

  const isRuleBased = !hasPrompt;
  const badgeClasses = isRuleBased
    ? "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200"
    : "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";

  return (
    <span className={badgeClasses}>
      <Bot className="w-3 h-3 mr-1" />
      {hasPrompt ? 'LLM-based' : 'Rule-based'}
    </span>
  );
};

// Agent card component
const AgentCard = ({ agent, onEditClick, isEditing, editedPrompt, onPromptChange, onSaveClick, onCancelClick, saving }) => {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md border border-gray-200 dark:border-gray-700 p-4">
      {/* Header */}
      <div className="mb-3">
        <div className="flex items-center space-x-2 mb-2">
          <Bot className="h-5 w-5 text-blue-500 flex-shrink-0" />
          <div className="min-w-0 flex-1">
            <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate capitalize" title={agent.name}>
              {agent.name}
            </h3>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {agent.type ? agent.type.replace('_', ' ') : 'Agent'}
            </p>
          </div>
        </div>
        <div className="flex justify-between items-center">
          <StatusBadge enabled={agent.enabled} hasPrompt={agent.has_prompt} />
          {agent.has_prompt && (
            <button
              onClick={() => onEditClick(agent)}
              disabled={isEditing || saving}
              className="flex items-center gap-1 px-2 py-1 text-xs bg-blue-600 text-white hover:bg-blue-700 disabled:bg-gray-400 rounded transition-colors"
            >
              <Edit3 className="w-3 h-3" />
              Edit
            </button>
          )}
        </div>
      </div>

      {/* Description */}
      <div className="mb-4">
        <p className="text-sm text-gray-700 dark:text-gray-300">
          {agent.description}
        </p>
      </div>

      {/* Edit Section */}
      {isEditing && (
        <div className="space-y-3 border-t border-gray-200 dark:border-gray-700 pt-4">
          <div>
            <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
              System Prompt
            </label>
            <textarea
              value={editedPrompt}
              onChange={(e) => onPromptChange(e.target.value)}
              className="w-full h-48 p-2 text-sm border border-gray-300 dark:border-gray-600 rounded resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              placeholder="Enter the system prompt for this agent..."
            />
          </div>
          <div className="flex gap-2 justify-end">
            <button
              onClick={onCancelClick}
              disabled={saving}
              className="flex items-center gap-1 px-3 py-1 text-xs border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50 rounded transition-colors"
            >
              <X className="w-3 h-3" />
              Cancel
            </button>
            <button
              onClick={onSaveClick}
              disabled={saving || !editedPrompt.trim()}
              className="flex items-center gap-1 px-3 py-1 text-xs bg-green-600 text-white hover:bg-green-700 disabled:bg-gray-400 rounded transition-colors"
            >
              {saving ? (
                <div className="w-3 h-3 border border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Save className="w-3 h-3" />
              )}
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

const SettingsPage = () => {
  const {
    username,
    project,
    dataExpirationDays,
    dataExpirationDate,
    updateUser,
    updateDataExpiration
  } = useUser();

  const [newUsername, setNewUsername] = useState(username);
  const [newProject, setNewProject] = useState(project);
  const [newExpirationDays, setNewExpirationDays] = useState(dataExpirationDays || '100');
  const [showDatePicker, setShowDatePicker] = useState(false);
  const [newExpirationDate, setNewExpirationDate] = useState(dataExpirationDate);
  const [showSuccess, setShowSuccess] = useState(false);
  const [error, setError] = useState('');

  // New state variables for delete functionality
  const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false);
  const [deleteStatus, setDeleteStatus] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  // Version information state
  const [versionInfo, setVersionInfo] = useState(null);

  // Alert information state
  const [alertInfo, setAlertInfo] = useState(null);

  // Alert settings state
  const [alertSettings, setAlertSettings] = useState({
    alerting_enabled: true,
    minimum_severity: 4,
    category_excluded: [],
    category_included: [],
    file_path_excluded_regex: [],
    file_path_included_regex: [],
    llm_triage_values_to_alert: ['true_positive']
  });
  const [alertSettingsLoaded, setAlertSettingsLoaded] = useState(false);
  const [alertSettingsSaving, setAlertSettingsSaving] = useState(false);
  const [alertSettingsSaved, setAlertSettingsSaved] = useState(false);
  const [alertSettingsError, setAlertSettingsError] = useState('');

  // Agent settings state
  const [agents, setAgents] = useState([]);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [agentsError, setAgentsError] = useState(null);
  const [editingAgent, setEditingAgent] = useState(null);
  const [editedPrompt, setEditedPrompt] = useState('');
  const [agentSaving, setAgentSaving] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [spendData, setSpendData] = useState(null);
  const [spendLoading, setSpendLoading] = useState(true);

  // Fetch version information on component mount
  useEffect(() => {
    const fetchVersionInfo = async () => {
      try {
        const response = await fetch('/version.json');
        if (response.ok) {
          const data = await response.json();
          setVersionInfo(data);
        }
      } catch (error) {
        console.error('Failed to fetch version info:', error);
      }
    };

    fetchVersionInfo();
  }, []);

  // Fetch alert information on component mount
  useEffect(() => {
    const fetchAlertInfo = async () => {
      try {
        const response = await fetch('/api/system/apprise-info');
        if (response.ok) {
          const data = await response.json();
          if (data.channels && data.channels.length > 0) {
            setAlertInfo(data);
          }
        }
      } catch (error) {
        console.error('Failed to fetch alert info:', error);
      }
    };

    fetchAlertInfo();
  }, []);

  // Fetch alert settings on component mount
  useEffect(() => {
    const fetchAlertSettings = async () => {
      try {
        const response = await fetch('/hasura/v1/graphql', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
          },
          body: JSON.stringify({
            query: `
              query GetAlertSettings {
                alert_settings(limit: 1) {
                  alerting_enabled
                  minimum_severity
                  category_excluded
                  category_included
                  file_path_excluded_regex
                  file_path_included_regex
                  llm_triage_values_to_alert
                }
              }
            `
          })
        });

        if (response.ok) {
          const result = await response.json();
          if (result.data?.alert_settings?.[0]) {
            const settings = result.data.alert_settings[0];
            setAlertSettings({
              alerting_enabled: settings.alerting_enabled,
              minimum_severity: settings.minimum_severity,
              category_excluded: settings.category_excluded || [],
              category_included: settings.category_included || [],
              file_path_excluded_regex: settings.file_path_excluded_regex || [],
              file_path_included_regex: settings.file_path_included_regex || [],
              llm_triage_values_to_alert: settings.llm_triage_values_to_alert || ['true_positive']
            });
          }
          // Always mark as loaded, even if no settings exist (will use defaults)
          setAlertSettingsLoaded(true);
        }
      } catch (error) {
        console.error('Failed to fetch alert settings:', error);
        setAlertSettingsError('Failed to load alert settings');
        // Still mark as loaded so user can save default values
        setAlertSettingsLoaded(true);
      }
    };

    fetchAlertSettings();
  }, []);

  // Fetch agents on component mount
  useEffect(() => {
    const fetchAgents = async () => {
      try {
        setAgentsLoading(true);
        setAgentsError(null);

        const response = await fetch('/api/agents');

        if (!response.ok) {
          throw new Error('Failed to fetch agents');
        }

        const data = await response.json();
        setAgents(data.agents || []);
        setLastUpdated(new Date());

      } catch (err) {
        console.error('Error fetching agents:', err);
        setAgentsError(err.message);
      } finally {
        setAgentsLoading(false);
      }
    };

    fetchAgents();
  }, []);

  // Fetch spend data on component mount
  useEffect(() => {
    const fetchSpendData = async () => {
      try {
        setSpendLoading(true);

        const response = await fetch('/api/agents/spend-data');

        if (!response.ok) throw new Error('Network response error');
        const result = await response.json();

        // Transform the API response to match the expected format
        setSpendData({
          sum: {
            spend: result.total_spend,
            total_tokens: result.total_tokens,
            prompt_tokens: result.total_prompt_tokens,
            completion_tokens: result.total_completion_tokens
          },
          count: result.total_requests
        });

      } catch (err) {
        console.error('Error fetching spend data:', err);
        // Don't set error state for spend data to avoid breaking the main page
      } finally {
        setSpendLoading(false);
      }
    };

    fetchSpendData();
  }, []);

  // Event handlers remain the same
  const handleUserSubmit = (e) => {
    e.preventDefault();
    setError('');

    if (!newUsername.trim() || !newProject.trim()) {
      setError('Username and project name cannot be empty');
      return;
    }

    try {
      updateUser(newUsername.trim(), newProject.trim());
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 3000);
    } catch (err) {
      setError('Failed to update settings');
    }
  };

  const handleExpirationSubmit = (e) => {
    e.preventDefault();
    if (newExpirationDays) {
      updateDataExpiration(newExpirationDays, undefined);
    }
  };

  const handleDateSelect = (date) => {
    updateDataExpiration(undefined, date);
    setNewExpirationDays(''); // Clear the days input
    setShowDatePicker(false);
  };

  // Handler for toggling alerting enabled (auto-saves)
  const handleAlertingEnabledToggle = async () => {
    const newValue = !alertSettings.alerting_enabled;

    // Update local state immediately
    setAlertSettings({ ...alertSettings, alerting_enabled: newValue });

    try {
      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify({
          query: `
            mutation UpdateAlertingEnabled($alerting_enabled: Boolean!) {
              insert_alert_settings_one(
                object: {
                  id: 1,
                  alerting_enabled: $alerting_enabled
                },
                on_conflict: {
                  constraint: alert_settings_pkey,
                  update_columns: [alerting_enabled]
                }
              ) {
                id
              }
            }
          `,
          variables: {
            alerting_enabled: newValue
          }
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }

      const result = await response.json();
      if (result.errors) {
        throw new Error(result.errors[0].message);
      }
    } catch (error) {
      console.error('Error saving alerting enabled setting:', error);
      // Revert local state on error
      setAlertSettings({ ...alertSettings, alerting_enabled: !newValue });
      setAlertSettingsError('Failed to save alerting enabled setting');
    }
  };

  // Handler for saving alert settings
  const handleAlertSettingsSave = async () => {
    setAlertSettingsSaving(true);
    setAlertSettingsError('');

    try {
      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify({
          query: `
            mutation UpdateAlertSettings(
              $alerting_enabled: Boolean!,
              $minimum_severity: Int!,
              $category_excluded: [String!]!,
              $category_included: [String!]!,
              $file_path_excluded_regex: [String!]!,
              $file_path_included_regex: [String!]!,
              $llm_triage_values_to_alert: [String!]!
            ) {
              insert_alert_settings_one(
                object: {
                  id: 1,
                  alerting_enabled: $alerting_enabled,
                  minimum_severity: $minimum_severity,
                  category_excluded: $category_excluded,
                  category_included: $category_included,
                  file_path_excluded_regex: $file_path_excluded_regex,
                  file_path_included_regex: $file_path_included_regex,
                  llm_triage_values_to_alert: $llm_triage_values_to_alert
                },
                on_conflict: {
                  constraint: alert_settings_pkey,
                  update_columns: [
                    alerting_enabled,
                    minimum_severity,
                    category_excluded,
                    category_included,
                    file_path_excluded_regex,
                    file_path_included_regex,
                    llm_triage_values_to_alert
                  ]
                }
              ) {
                id
              }
            }
          `,
          variables: {
            alerting_enabled: alertSettings.alerting_enabled,
            minimum_severity: parseInt(alertSettings.minimum_severity),
            category_excluded: alertSettings.category_excluded,
            category_included: alertSettings.category_included,
            file_path_excluded_regex: alertSettings.file_path_excluded_regex,
            file_path_included_regex: alertSettings.file_path_included_regex,
            llm_triage_values_to_alert: alertSettings.llm_triage_values_to_alert
          }
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }

      const result = await response.json();
      if (result.errors) {
        throw new Error(result.errors[0].message);
      }

      setAlertSettingsSaved(true);
      setTimeout(() => setAlertSettingsSaved(false), 3000);
    } catch (error) {
      console.error('Error saving alert settings:', error);
      setAlertSettingsError('Failed to save alert settings');
    } finally {
      setAlertSettingsSaving(false);
    }
  };

  // New handler for delete data button
  const handleDeleteData = async () => {
    setIsDeleting(true);
    setDeleteStatus('');

    try {
      // Call the trigger-cleanup endpoint with "all" option
      const response = await fetch('/api/system/cleanup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          expiration: 'all'
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }

      setDeleteStatus('success');
      setShowDeleteConfirmation(false);
      setTimeout(() => setDeleteStatus(''), 5000);
    } catch (error) {
      console.error('Error deleting data:', error);
      setDeleteStatus('error');
    } finally {
      setIsDeleting(false);
    }
  };

  // Agent-related handlers
  const fetchCurrentPrompt = async (agentName) => {
    try {
      const query = {
        query: `
          query GetAgentPrompt($name: String!) {
            agent_prompts_by_pk(name: $name) {
              name
              description
              prompt
              enabled
            }
          }
        `,
        variables: { name: agentName }
      };

      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(query)
      });

      if (!response.ok) throw new Error('Network response error');
      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

      return result.data.agent_prompts_by_pk?.prompt || '';
    } catch (err) {
      console.error('Error fetching current prompt:', err);
      throw err;
    }
  };

  const savePrompt = async (agentName, prompt, description) => {
    try {
      const mutation = {
        query: `
          mutation UpsertAgentPrompt($name: String!, $prompt: String!, $description: String) {
            insert_agent_prompts_one(
              object: {
                name: $name,
                prompt: $prompt,
                description: $description,
                enabled: true
              },
              on_conflict: {
                constraint: agent_prompts_pkey,
                update_columns: [prompt, description, updated_at]
              }
            ) {
              name
            }
          }
        `,
        variables: {
          name: agentName,
          prompt: prompt,
          description: description
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

      if (!response.ok) throw new Error('Network response error');
      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

      return true;
    } catch (err) {
      console.error('Error saving prompt:', err);
      throw err;
    }
  };

  const handleEditClick = async (agent) => {
    try {
      setAgentsLoading(true);
      const currentPrompt = await fetchCurrentPrompt(agent.name);
      setEditedPrompt(currentPrompt);
      setEditingAgent(agent.name);
    } catch (err) {
      setAgentsError(`Failed to load current prompt: ${err.message}`);
    } finally {
      setAgentsLoading(false);
    }
  };

  const handleAgentSaveClick = async () => {
    const agent = agents.find(a => a.name === editingAgent);
    if (!agent) return;

    try {
      setAgentSaving(true);
      await savePrompt(editingAgent, editedPrompt, agent.description);
      setEditingAgent(null);
      setEditedPrompt('');
      setAgentsError(null);
    } catch (err) {
      setAgentsError(`Failed to save prompt: ${err.message}`);
    } finally {
      setAgentSaving(false);
    }
  };

  const handleAgentCancelClick = () => {
    setEditingAgent(null);
    setEditedPrompt('');
    setAgentsError(null);
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <div className="space-y-6">
        {/* User Settings section remains the same */}
        <SettingsSection
          icon={User}
          title="User Settings"
          description="Update your user information and preferences"
        >
          <form onSubmit={handleUserSubmit}>
            <div className="space-y-4">
              <div>
                <label
                  htmlFor="username"
                  className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
                >
                  Username
                </label>
                <input
                  id="username"
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400"
                  placeholder="Enter your username"
                />
              </div>

              <div>
                <label
                  htmlFor="project"
                  className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
                >
                  Project Name
                </label>
                <input
                  id="project"
                  type="text"
                  value={newProject}
                  onChange={(e) => setNewProject(e.target.value)}
                  className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400"
                  placeholder="Enter project name (e.g. ASSESS-123)"
                />
              </div>

              {error && (
                <div className="flex items-center gap-2 text-red-600 dark:text-red-400">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="text-sm">{error}</span>
                </div>
              )}

              {showSuccess && (
                <div className="text-sm text-green-600 dark:text-green-400">
                  Settings updated successfully!
                </div>
              )}

              <button
                type="submit"
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600 text-white rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Update Settings
              </button>
            </div>
          </form>
        </SettingsSection>

        {/* Alert Settings section */}
        <div className="bg-white dark:bg-dark-secondary rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
          <div className="p-6">
            {/* Header Row with Title and Enable Toggle */}
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2">
                <Bell className="w-5 h-5 text-gray-500 dark:text-gray-400" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                  Alert Settings
                </h3>
              </div>
              <button
                type="button"
                onClick={handleAlertingEnabledToggle}
                className={`px-4 py-2 rounded-md font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 ${alertSettings.alerting_enabled
                  ? 'bg-green-600 hover:bg-green-700 dark:bg-green-600 dark:hover:bg-green-700 text-white focus:ring-green-500'
                  : 'bg-red-600 hover:bg-red-700 dark:bg-red-600 dark:hover:bg-red-700 text-white focus:ring-red-500'
                  }`}
              >
                {alertSettings.alerting_enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>
            <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
              Configure alert filtering and notification preferences
            </p>

            <div className="space-y-4">
              {/* Row 1: Minimum Severity and LLM Triage Values */}
              <div className="grid grid-cols-2 gap-4 items-end">
                {/* Minimum Severity */}
                <div>
                  <label htmlFor="minimum_severity" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Minimum Severity (0-10)
                  </label>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                    Only send alerts for findings with severity at or above this threshold
                  </p>
                  <input
                    id="minimum_severity"
                    type="number"
                    min="0"
                    max="10"
                    value={alertSettings.minimum_severity}
                    onChange={(e) => setAlertSettings({ ...alertSettings, minimum_severity: e.target.value })}
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                {/* LLM Triage Values to Alert */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    LLM Triage Values to Alert On
                  </label>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                    When LLM functionality is enabled, only alert on findings with these triage values
                  </p>
                  <div className="flex gap-4">
                    <label className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        checked={alertSettings.llm_triage_values_to_alert.includes('true_positive')}
                        onChange={(e) => {
                          const newValues = e.target.checked
                            ? [...alertSettings.llm_triage_values_to_alert, 'true_positive']
                            : alertSettings.llm_triage_values_to_alert.filter(v => v !== 'true_positive');
                          setAlertSettings({ ...alertSettings, llm_triage_values_to_alert: newValues });
                        }}
                        className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-300">True Positive</span>
                    </label>
                    <label className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        checked={alertSettings.llm_triage_values_to_alert.includes('needs_review')}
                        onChange={(e) => {
                          const newValues = e.target.checked
                            ? [...alertSettings.llm_triage_values_to_alert, 'needs_review']
                            : alertSettings.llm_triage_values_to_alert.filter(v => v !== 'needs_review');
                          setAlertSettings({ ...alertSettings, llm_triage_values_to_alert: newValues });
                        }}
                        className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-300">Needs Review</span>
                    </label>
                    <label className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        checked={alertSettings.llm_triage_values_to_alert.includes('false_positive')}
                        onChange={(e) => {
                          const newValues = e.target.checked
                            ? [...alertSettings.llm_triage_values_to_alert, 'false_positive']
                            : alertSettings.llm_triage_values_to_alert.filter(v => v !== 'false_positive');
                          setAlertSettings({ ...alertSettings, llm_triage_values_to_alert: newValues });
                        }}
                        className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-300">False Positive</span>
                    </label>
                  </div>
                </div>
              </div>

              {/* Row 2: Category Included and Excluded */}
              <div className="grid grid-cols-2 gap-4 items-end">
                {/* Category Included */}
                <div>
                  <label htmlFor="category_included" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Included Categories
                  </label>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                    Comma-separated list of categories to include (empty = all allowed). Example: credential,pii
                  </p>
                  <input
                    id="category_included"
                    type="text"
                    value={alertSettings.category_included.join(',')}
                    onChange={(e) => setAlertSettings({
                      ...alertSettings,
                      category_included: e.target.value ? e.target.value.split(',').map(s => s.trim()) : []
                    })}
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="credential,pii,vulnerability"
                  />
                </div>

                {/* Category Excluded */}
                <div>
                  <label htmlFor="category_excluded" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Excluded Categories
                  </label>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                    Comma-separated list of categories to exclude. Example: informational,misc
                  </p>
                  <input
                    id="category_excluded"
                    type="text"
                    value={alertSettings.category_excluded.join(',')}
                    onChange={(e) => setAlertSettings({
                      ...alertSettings,
                      category_excluded: e.target.value ? e.target.value.split(',').map(s => s.trim()) : []
                    })}
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="informational,misc"
                  />
                </div>
              </div>

              {/* Row 3: File Path Regex Included and Excluded */}
              <div className="grid grid-cols-2 gap-4 items-end">
                {/* File Path Included Regex */}
                <div>
                  <label htmlFor="file_path_included_regex" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Included File Path Regex
                  </label>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                    Only alert on files matching these regex patterns (one per line, empty = all paths allowed)
                  </p>
                  <textarea
                    id="file_path_included_regex"
                    rows="3"
                    value={alertSettings.file_path_included_regex.join('\n')}
                    onChange={(e) => setAlertSettings({
                      ...alertSettings,
                      file_path_included_regex: e.target.value.split('\n').filter(line => line.trim())
                    })}
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                    placeholder=".*\.(config|ini|yaml)$&#10;/etc/.*"
                  />
                </div>

                {/* File Path Excluded Regex */}
                <div>
                  <label htmlFor="file_path_excluded_regex" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Excluded File Path Regex
                  </label>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                    Exclude alerts for files matching these regex patterns (one per line)
                  </p>
                  <textarea
                    id="file_path_excluded_regex"
                    rows="3"
                    value={alertSettings.file_path_excluded_regex.join('\n')}
                    onChange={(e) => setAlertSettings({
                      ...alertSettings,
                      file_path_excluded_regex: e.target.value.split('\n').filter(line => line.trim())
                    })}
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                    placeholder=".*(test|sample|example).*&#10;.*\.(tmp|bak)$"
                  />
                </div>
              </div>

              {/* Status Messages */}
              {alertSettingsError && (
                <div className="flex items-center gap-2 text-red-600 dark:text-red-400">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="text-sm">{alertSettingsError}</span>
                </div>
              )}

              {alertSettingsSaved && (
                <div className="text-sm text-green-600 dark:text-green-400">
                  Alert settings saved successfully!
                </div>
              )}

              {/* Save Button */}
              <button
                onClick={handleAlertSettingsSave}
                disabled={alertSettingsSaving || !alertSettingsLoaded}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600 text-white rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {alertSettingsSaving ? 'Saving...' : 'Save Alert Settings'}
              </button>
            </div>
          </div>
        </div>

        {/* Data Settings section with updated styling */}
        <SettingsSection
          icon={Database}
          title="Data Settings"
          description="Configure data retention and expiration settings (set either days or the date)"
        >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Data Expiration
              </label>
              <div className="space-y-4">
                <form onSubmit={handleExpirationSubmit} className="flex gap-2 w-full">
                  <div className="flex-grow">
                    <input
                      type="number"
                      min="1"
                      value={newExpirationDays}
                      onChange={(e) => setNewExpirationDays(e.target.value)}
                      className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Days (default: 100)"
                    />
                  </div>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600 text-white rounded-md transition-colors whitespace-nowrap"
                  >
                    Set Days
                  </button>
                </form>
                <button
                  onClick={() => setShowDatePicker(true)}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-transparent dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                >
                  <Calendar className="w-4 h-4 text-gray-500 dark:text-gray-400" />
                  {dataExpirationDate ? new Date(dataExpirationDate).toLocaleDateString() : 'Select Date'}
                </button>

                {/* New Delete Data button */}
                <button
                  onClick={() => setShowDeleteConfirmation(true)}
                  className="flex items-center justify-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 dark:bg-red-700 dark:hover:bg-red-800 text-white rounded-md transition-colors w-auto"
                >
                  <Trash2 className="w-4 h-4" />
                  Delete Nemesis Data
                </button>

                {/* Status message for delete operation */}
                {deleteStatus === 'success' && (
                  <div className="text-sm text-green-600 dark:text-green-400 mt-2">
                    Data deletion process started successfully!
                  </div>
                )}
                {deleteStatus === 'error' && (
                  <div className="flex items-center gap-2 text-red-600 dark:text-red-400 mt-2">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="text-sm">Failed to trigger data deletion.</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </SettingsSection>

        {/* Agents Configuration section */}
        <SettingsSection
          icon={Bot}
          title="Agents Configuration"
        >
          {agentsError && (
            <div className="mb-4 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
              <div className="flex flex-col">
                <span className="text-red-600 dark:text-red-400">Error: {agentsError}</span>
              </div>
            </div>
          )}

          <div className="space-y-6">
            {/* Agent cards in grid layout */}
            <div className="relative">
              {agentsLoading && agents.length === 0 ? (
                <div className="flex justify-center items-center w-full py-8">
                  <div className="animate-spin h-8 w-8 border-2 border-blue-500 rounded-full border-t-transparent" />
                </div>
              ) : agents.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                  {agents.map((agent) => (
                    <AgentCard
                      key={agent.name}
                      agent={agent}
                      onEditClick={handleEditClick}
                      isEditing={editingAgent === agent.name}
                      editedPrompt={editedPrompt}
                      onPromptChange={setEditedPrompt}
                      onSaveClick={handleAgentSaveClick}
                      onCancelClick={handleAgentCancelClick}
                      saving={agentSaving}
                    />
                  ))}
                </div>
              ) : (
                <div className="w-full text-center py-8 text-gray-500 dark:text-gray-400">
                  No agents available. The agents service may be unavailable.
                </div>
              )}
            </div>

            {/* Summary stats */}
            {agents.length > 0 && (
              <div className="space-y-6 mt-6">
                {/* Agent Stats */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
                    <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                      {agents.length}
                    </div>
                    <div className="text-sm text-gray-600 dark:text-gray-400">Total Agents</div>
                  </div>

                  <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
                    <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                      {agents.filter(a => a.has_prompt).length}
                    </div>
                    <div className="text-sm text-gray-600 dark:text-gray-400">LLM-based Agents</div>
                  </div>

                  <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
                    <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                      {agents.filter(a => !a.has_prompt).length}
                    </div>
                    <div className="text-sm text-gray-600 dark:text-gray-400">Rule-based Agents</div>
                  </div>
                </div>

                {/* LLM Usage Stats */}
                <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4">
                  <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4">LLM Usage Statistics</h3>
                  {spendLoading ? (
                    <div className="flex justify-center items-center py-4">
                      <div className="animate-spin h-6 w-6 border-2 border-blue-500 rounded-full border-t-transparent" />
                    </div>
                  ) : spendData ? (
                    <>
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                        <div className="text-center">
                          <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                            ${spendData.sum?.spend ? spendData.sum.spend.toFixed(4) : '0.0000'}
                          </div>
                          <div className="text-sm text-gray-600 dark:text-gray-400">Total Spend</div>
                        </div>

                        <div className="text-center">
                          <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                            {spendData.sum?.total_tokens ? spendData.sum.total_tokens.toLocaleString() : '0'}
                          </div>
                          <div className="text-sm text-gray-600 dark:text-gray-400">Total Tokens</div>
                        </div>

                        <div className="text-center">
                          <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                            {spendData.sum?.prompt_tokens ? spendData.sum.prompt_tokens.toLocaleString() : '0'}
                          </div>
                          <div className="text-sm text-gray-600 dark:text-gray-400">Prompt Tokens</div>
                        </div>

                        <div className="text-center">
                          <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                            {spendData.sum?.completion_tokens ? spendData.sum.completion_tokens.toLocaleString() : '0'}
                          </div>
                          <div className="text-sm text-gray-600 dark:text-gray-400">Completion Tokens</div>
                        </div>

                        <div className="text-center">
                          <div className="text-2xl font-bold text-gray-600 dark:text-gray-400">
                            {spendData.count ? spendData.count.toLocaleString() : '0'}
                          </div>
                          <div className="text-sm text-gray-600 dark:text-gray-400">Total Requests</div>
                        </div>
                      </div>

                      {/* Detailed tracking links */}
                      <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                        <div className="text-sm text-gray-600 dark:text-gray-400 text-center">
                          For detailed tracking, visit{' '}
                          <a
                            href="/llm/"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 underline"
                          >
                            LiteLLM Dashboard
                          </a>
                          {' '}or{' '}
                          <a
                            href="/phoenix/"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 underline"
                          >
                            Phoenix Tracing
                          </a>
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="text-center py-4 text-gray-500 dark:text-gray-400">
                      No usage data available
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </SettingsSection>

        {/* Alert Information section - only shown if alert info is available */}
        {alertInfo && alertInfo.channels && alertInfo.channels.length > 0 && (
          <SettingsSection
            icon={Bell}
            title="Alert Information"
          >
            <div className="space-y-2 text-sm">
              {alertInfo.channels.map((channel, index) => (
                <div key={index} className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">
                    {channel.type === 'main' ? 'Main Alert Channel' : `${channel.tag.charAt(0).toUpperCase() + channel.tag.slice(1)} Channel`}
                  </span>
                  <span className="text-gray-900 dark:text-gray-100">
                    #{channel.name}
                  </span>
                </div>
              ))}
            </div>
          </SettingsSection>
        )}

        {/* System Information section with version details */}
        <SettingsSection
          icon={AlertTriangle}
          title="System Information"
        >
          <div className="space-y-2 text-sm">
            {versionInfo ? (
              <>
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Git SHA</span>
                  <span className="text-gray-900 dark:text-gray-100 font-mono">
                    {versionInfo.git.shaShort}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Branch</span>
                  <span className="text-gray-900 dark:text-gray-100">
                    {versionInfo.git.branch}
                  </span>
                </div>
                {versionInfo.git.tag && (
                  <div className="flex justify-between">
                    <span className="text-gray-500 dark:text-gray-400">Release</span>
                    <span className="text-gray-900 dark:text-gray-100">
                      {versionInfo.git.tag}
                    </span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Build Date</span>
                  <span className="text-gray-900 dark:text-gray-100">
                    {new Date(versionInfo.build.timestamp).toLocaleString()}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Build Source</span>
                  <span className="text-gray-900 dark:text-gray-100">
                    {versionInfo.build.source}
                  </span>
                </div>
                {versionInfo.git.dirty && (
                  <div className="flex justify-between">
                    <span className="text-gray-500 dark:text-gray-400">Status</span>
                    <span className="text-yellow-600 dark:text-yellow-400">
                      Uncommitted changes
                    </span>
                  </div>
                )}
                <div className="flex justify-between items-start">
                  <span className="text-gray-500 dark:text-gray-400">Last Commit</span>
                  <span className="text-gray-900 dark:text-gray-100 text-right max-w-xs">
                    {versionInfo.git.commitMessage}
                  </span>
                </div>
              </>
            ) : (
              <div className="text-gray-500 dark:text-gray-400">
                Loading version information...
              </div>
            )}
          </div>
        </SettingsSection>
      </div>

      {/* Date picker dialog */}
      <Dialog open={showDatePicker} onOpenChange={setShowDatePicker}>
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Select Expiration Date
          </h2>
          <input
            type="datetime-local"
            className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={newExpirationDate}
            onChange={(e) => handleDateSelect(e.target.value)}
          />
        </div>
      </Dialog>

      {/* Delete confirmation dialog */}
      <Dialog open={showDeleteConfirmation} onOpenChange={setShowDeleteConfirmation}>
        <div className="space-y-6 p-2">
          <div className="flex flex-col items-center text-center">
            <AlertTriangle className="w-12 h-12 text-red-500 mb-2" />
            <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
              Delete Nemesis Data
            </h2>
            <p className="text-gray-600 dark:text-gray-400 mt-2">
              Do you really want to delete data from the Nemesis database and files from the Nemesis datalake?
            </p>
          </div>

          <div className="flex justify-center gap-4 mt-4">
            <button
              onClick={() => setShowDeleteConfirmation(false)}
              className="px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-800 dark:text-gray-200 rounded-md transition-colors"
              disabled={isDeleting}
            >
              No, Cancel
            </button>
            <button
              onClick={handleDeleteData}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 dark:bg-red-700 dark:hover:bg-red-800 text-white rounded-md transition-colors"
              disabled={isDeleting}
            >
              {isDeleting ? 'Deleting...' : 'Yes, Delete All Data'}
            </button>
          </div>
        </div>
      </Dialog>
    </div>
  );
};

export default SettingsPage;

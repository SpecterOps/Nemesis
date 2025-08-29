import React, { useState, useEffect } from 'react';
import { Bot, Edit3, Save, X, AlertCircle, Clock } from 'lucide-react';

// Status badge component
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

const AgentsPage = () => {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [editingAgent, setEditingAgent] = useState(null);
  const [editedPrompt, setEditedPrompt] = useState('');
  const [saving, setSaving] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [spendData, setSpendData] = useState(null);
  const [spendLoading, setSpendLoading] = useState(true);

  useEffect(() => {
    fetchAgents();
    fetchSpendData();
  }, []);

  const fetchAgents = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/agents');

      if (!response.ok) {
        throw new Error('Failed to fetch agents');
      }

      const data = await response.json();
      setAgents(data.agents || []);
      setLastUpdated(new Date());

    } catch (err) {
      console.error('Error fetching agents:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

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
      setLoading(true);
      const currentPrompt = await fetchCurrentPrompt(agent.name);
      setEditedPrompt(currentPrompt);
      setEditingAgent(agent.name);
    } catch (err) {
      setError(`Failed to load current prompt: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveClick = async () => {
    const agent = agents.find(a => a.name === editingAgent);
    if (!agent) return;

    try {
      setSaving(true);
      await savePrompt(editingAgent, editedPrompt, agent.description);
      setEditingAgent(null);
      setEditedPrompt('');
      setError(null);
    } catch (err) {
      setError(`Failed to save prompt: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleCancelClick = () => {
    setEditingAgent(null);
    setEditedPrompt('');
    setError(null);
  };

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

  if (error) {
    return (
      <div className="space-y-6 p-6">
        <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2 transition-colors">
          <AlertCircle className="w-5 h-5 text-red-500 dark:text-red-400" />
          <div className="flex flex-col">
            <span className="text-red-600 dark:text-red-400">Error loading agents: {error}</span>
            <span className="text-sm text-red-500 dark:text-red-400">Check browser console for details</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-800 dark:text-white">Agents</h1>
        <div className="text-sm text-gray-500 dark:text-gray-400 flex items-center space-x-1">
          <Clock className="w-4 h-4" />
          <span>{lastUpdated ? `Last updated: ${lastUpdated.toLocaleTimeString()}` : 'Updating...'}</span>
        </div>
      </div>

      {/* Agent cards in grid layout */}
      <div className="relative">
        {loading && agents.length === 0 ? (
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
                onSaveClick={handleSaveClick}
                onCancelClick={handleCancelClick}
                saving={saving}
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
  );
};

export default AgentsPage;
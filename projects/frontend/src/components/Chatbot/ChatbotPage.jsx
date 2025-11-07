import React, { useState, useEffect, useRef } from 'react';
import { Bot, Send, Trash2, Settings as SettingsIcon, AlertCircle } from 'lucide-react';
import ExampleQueries from './ExampleQueries';
import MessageBubble from './MessageBubble';

const ChatbotPage = () => {
  const [messages, setMessages] = useState([]);
  const [currentMessage, setCurrentMessage] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [useHistory, setUseHistory] = useState(true);
  const [temperature, setTemperature] = useState(0.7);
  const [error, setError] = useState(null);
  const [showSettings, setShowSettings] = useState(false);
  const [systemPrompt, setSystemPrompt] = useState('');
  const [originalPrompt, setOriginalPrompt] = useState('');
  const [savingPrompt, setSavingPrompt] = useState(false);
  const [promptError, setPromptError] = useState(null);

  const messagesEndRef = useRef(null);
  const abortControllerRef = useRef(null);

  // Auto-scroll to bottom when messages change
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Fetch system prompt when settings are opened
  useEffect(() => {
    if (showSettings && !systemPrompt) {
      fetchSystemPrompt();
    }
  }, [showSettings]);

  const fetchSystemPrompt = async () => {
    try {
      const query = {
        query: `
          query GetChatbotPrompt {
            agent_prompts_by_pk(name: "chatbot") {
              name
              prompt
              description
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

      if (!response.ok) throw new Error('Network response error');
      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

      const prompt = result.data.agent_prompts_by_pk?.prompt || '';
      setSystemPrompt(prompt);
      setOriginalPrompt(prompt);
    } catch (err) {
      console.error('Error fetching system prompt:', err);
      setPromptError('Failed to load system prompt');
    }
  };

  const saveSystemPrompt = async () => {
    if (systemPrompt === originalPrompt) return;

    setSavingPrompt(true);
    setPromptError(null);

    try {
      const mutation = {
        query: `
          mutation UpsertChatbotPrompt($prompt: String!) {
            insert_agent_prompts_one(
              object: {
                name: "chatbot",
                prompt: $prompt,
                description: "Interactive chatbot for querying Nemesis data"
              },
              on_conflict: {
                constraint: agent_prompts_pkey,
                update_columns: [prompt]
              }
            ) {
              name
              prompt
            }
          }
        `,
        variables: { prompt: systemPrompt }
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

      setOriginalPrompt(systemPrompt);
      alert('System prompt saved successfully!');
    } catch (err) {
      console.error('Error saving system prompt:', err);
      setPromptError('Failed to save system prompt');
    } finally {
      setSavingPrompt(false);
    }
  };

  const cancelPromptEdit = () => {
    setSystemPrompt(originalPrompt);
    setPromptError(null);
  };

  const sendMessage = async (messageText) => {
    if (!messageText.trim() || isStreaming) return;

    const userMessage = { role: 'user', content: messageText.trim() };
    setMessages(prev => [...prev, userMessage]);
    setCurrentMessage('');
    setIsStreaming(true);
    setError(null);

    // Create abort controller for this request
    abortControllerRef.current = new AbortController();

    try {
      const response = await fetch('/api/chatbot/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: messageText.trim(),
          history: useHistory ? messages : [],
          use_history: useHistory,
          temperature: temperature
        }),
        signal: abortControllerRef.current.signal
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let assistantMessage = '';

      // Add empty assistant message that we'll update
      setMessages(prev => [...prev, { role: 'assistant', content: '' }]);

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        assistantMessage += chunk;

        // Update the last message (assistant's response) in real-time
        setMessages(prev => {
          const updated = [...prev];
          updated[updated.length - 1] = {
            role: 'assistant',
            content: assistantMessage
          };
          return updated;
        });
      }

    } catch (err) {
      if (err.name === 'AbortError') {
        console.log('Request aborted');
      } else {
        console.error('Streaming error:', err);
        setError(err.message || 'Failed to get response from chatbot');

        // Remove the empty assistant message if there was an error
        setMessages(prev => prev.filter(msg => msg.content !== ''));
      }
    } finally {
      setIsStreaming(false);
      abortControllerRef.current = null;
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    sendMessage(currentMessage);
  };

  const handleExampleClick = (example) => {
    setCurrentMessage(example);
  };

  const clearHistory = () => {
    if (window.confirm('Clear all conversation history?')) {
      setMessages([]);
      setError(null);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-1rem)] max-w-6xl mx-auto px-4 pt-4 pb-2">
      {/* Header */}
      <div className="flex items-center justify-between mb-4 pb-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center space-x-3">
          <Bot className="w-8 h-8 text-blue-500" />
          <div>
            <h1 className="text-2xl font-bold text-gray-800 dark:text-white">Chatbot</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Query Nemesis data with natural language
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          {/* Settings Toggle */}
          <button
            onClick={() => setShowSettings(!showSettings)}
            className={`p-2 rounded-lg transition-colors ${
              showSettings
                ? 'bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-300'
                : 'hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-400'
            }`}
            title="Settings"
          >
            <SettingsIcon className="w-5 h-5" />
          </button>

          {/* Clear History */}
          <button
            onClick={clearHistory}
            disabled={messages.length === 0}
            className="flex items-center space-x-1 px-3 py-2 text-sm bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
            title="Clear conversation history"
          >
            <Trash2 className="w-4 h-4" />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {/* Settings Panel */}
      {showSettings && (
        <div className="mb-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 max-h-96 overflow-y-auto flex-shrink-0">
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Settings</h3>

          <div className="space-y-4">
            {/* Temperature Control */}
            <div>
              <label className="flex justify-between text-sm text-gray-600 dark:text-gray-400 mb-1">
                <span>Temperature: {temperature.toFixed(1)}</span>
                <span className="text-xs text-gray-500">
                  {temperature < 0.3 ? 'Focused' : temperature < 0.7 ? 'Balanced' : 'Creative'}
                </span>
              </label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.1"
                value={temperature}
                onChange={(e) => setTemperature(parseFloat(e.target.value))}
                className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer dark:bg-gray-700"
              />
            </div>

            {/* Use History Toggle */}
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">Use Conversation History</span>
              <button
                onClick={() => setUseHistory(!useHistory)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  useHistory ? 'bg-blue-600' : 'bg-gray-300 dark:bg-gray-600'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    useHistory ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>

            {/* System Prompt Editor */}
            <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
              <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">System Prompt</h4>

              {promptError && (
                <div className="mb-3 p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-sm text-red-600 dark:text-red-400">
                  {promptError}
                </div>
              )}

              <textarea
                value={systemPrompt}
                onChange={(e) => setSystemPrompt(e.target.value)}
                className="w-full h-64 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono"
                placeholder="Loading system prompt..."
              />

              <div className="flex space-x-2 mt-3">
                <button
                  onClick={saveSystemPrompt}
                  disabled={savingPrompt || systemPrompt === originalPrompt}
                  className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
                >
                  {savingPrompt ? 'Saving...' : 'Save Prompt'}
                </button>
                <button
                  onClick={cancelPromptEdit}
                  disabled={savingPrompt || systemPrompt === originalPrompt}
                  className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scrollable Content Area */}
      <div className="flex-1 overflow-y-auto space-y-4 min-h-0">
        {/* Error Display */}
        {error && (
          <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-start space-x-2">
            <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </div>
          </div>
        )}

        {/* Example Queries (show when no messages) */}
        {messages.length === 0 && (
          <ExampleQueries onExampleClick={handleExampleClick} />
        )}

        {/* Messages */}
        <div className="space-y-4 px-2">
          {messages.map((msg, idx) => (
            <MessageBubble
              key={idx}
              message={msg}
              isStreaming={isStreaming && idx === messages.length - 1}
            />
          ))}
          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="flex-shrink-0 border-t border-gray-200 dark:border-gray-700 pt-4 mt-4 pb-4">
        <div className="flex space-x-2">
          <textarea
            value={currentMessage}
            onChange={(e) => setCurrentMessage(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Ask a question about your data..."
            disabled={isStreaming}
            className="flex-1 px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 disabled:bg-gray-100 dark:disabled:bg-gray-800 disabled:cursor-not-allowed"
            rows={2}
          />
          <button
            type="submit"
            disabled={!currentMessage.trim() || isStreaming}
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors flex items-center space-x-2"
          >
            <Send className="w-5 h-5" />
            <span>{isStreaming ? 'Sending...' : 'Send'}</span>
          </button>
        </div>
        <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
          Press Enter to send, Shift+Enter for new line
        </p>
      </form>
    </div>
  );
};

export default ChatbotPage;

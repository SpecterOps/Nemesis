import React from 'react';
import { Bot, User } from 'lucide-react';
import ReactMarkdown from 'react-markdown';

const TypingIndicator = () => (
  <div className="flex space-x-1">
    <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
    <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
    <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
  </div>
);

const MessageBubble = ({ message, isStreaming }) => {
  const isUser = message.role === 'user';

  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
      <div className={`flex max-w-3xl ${isUser ? 'flex-row-reverse' : 'flex-row'} items-start space-x-3`}>
        {/* Avatar */}
        <div
          className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
            isUser
              ? 'bg-blue-600 text-white'
              : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300'
          }`}
        >
          {isUser ? <User className="w-5 h-5" /> : <Bot className="w-5 h-5" />}
        </div>

        {/* Message Content */}
        <div
          className={`flex-1 px-4 py-3 rounded-lg ${
            isUser
              ? 'bg-blue-600 text-white ml-3'
              : 'bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-gray-100 mr-3'
          }`}
        >
          {isUser ? (
            // User messages are plain text
            <p className="text-sm whitespace-pre-wrap break-words">{message.content}</p>
          ) : (
            // Assistant messages support markdown
            <>
              {message.content ? (
                <div className="prose prose-sm dark:prose-invert max-w-none">
                  <ReactMarkdown
                    components={{
                      // Customize code blocks
                      code({ node, inline, className, children, ...props }) {
                        return inline ? (
                          <code
                            className="px-1 py-0.5 bg-gray-200 dark:bg-gray-700 rounded text-xs"
                            {...props}
                          >
                            {children}
                          </code>
                        ) : (
                          <pre className="bg-gray-200 dark:bg-gray-900 p-3 rounded-lg overflow-x-auto">
                            <code className="text-xs" {...props}>
                              {children}
                            </code>
                          </pre>
                        );
                      },
                      // Customize tables
                      table({ children }) {
                        return (
                          <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-300 dark:divide-gray-600">
                              {children}
                            </table>
                          </div>
                        );
                      },
                    }}
                  >
                    {message.content}
                  </ReactMarkdown>
                </div>
              ) : isStreaming ? (
                <TypingIndicator />
              ) : null}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default MessageBubble;

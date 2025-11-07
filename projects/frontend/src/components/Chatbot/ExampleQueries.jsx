import React from 'react';
import { Lightbulb } from 'lucide-react';

const ExampleQueries = ({ onExampleClick }) => {
  const examples = [
    {
      title: 'High Severity Findings',
      query: 'How many findings have severity greater than 7?',
      description: 'Count critical security findings',
    },
    {
      title: 'Exposed Credentials',
      query: 'What decrypted passwords are available from host://WORKSTATION01?',
      description: 'Find credentials from a specific source',
    },
    {
      title: 'Lateral Movement',
      query: 'Show me Chrome login credentials that could be used for lateral movement to other hosts',
      description: 'Identify exploitation opportunities',
    },
  ];

  return (
    <div className="mb-6 space-y-4">
      <div className="flex items-center space-x-2 text-gray-600 dark:text-gray-400">
        <Lightbulb className="w-5 h-5" />
        <h3 className="text-sm font-semibold">Try these example queries:</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {examples.map((example, idx) => (
          <button
            key={idx}
            onClick={() => onExampleClick(example.query)}
            className="text-left p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg hover:border-blue-500 dark:hover:border-blue-400 hover:shadow-md transition-all group"
          >
            <h4 className="font-semibold text-sm text-gray-800 dark:text-gray-200 mb-1 group-hover:text-blue-600 dark:group-hover:text-blue-400">
              {example.title}
            </h4>
            <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">
              {example.description}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-500 italic line-clamp-2">
              "{example.query}"
            </p>
          </button>
        ))}
      </div>
    </div>
  );
};

export default ExampleQueries;

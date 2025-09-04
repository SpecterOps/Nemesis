import React from 'react';
import { AlertTriangle } from 'lucide-react';

const DpapiMasterKeys = () => {
  return (
    <div className="p-6">
      {/* Placeholder content */}
      <div className="flex items-center justify-center h-64 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg">
        <div className="text-center">
          <AlertTriangle className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-gray-100">
            Master Keys
          </h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            This will display data from <code>dpapi.masterkeys</code> table when available.
          </p>
        </div>
      </div>
    </div>
  );
};

export default DpapiMasterKeys;
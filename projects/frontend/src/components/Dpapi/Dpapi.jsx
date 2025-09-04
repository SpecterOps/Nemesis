import React, { useState } from 'react';
import DpapiMasterKeys from './DpapiMasterKeys';
import DpapiDomainBackupKeys from './DpapiDomainBackupKeys';
import DpapiSubmitCredential from './DpapiSubmitCredential';

const Dpapi = () => {
  const [activeTab, setActiveTab] = useState('masterKeys');

  const tabs = [
    { id: 'masterKeys', label: 'Master Keys', component: DpapiMasterKeys },
    { id: 'domainBackupKeys', label: 'Domain Backup Keys', component: DpapiDomainBackupKeys },
    { id: 'submitCredential', label: 'Submit Credential Material', component: DpapiSubmitCredential }
  ];

  const ActiveComponent = tabs.find(tab => tab.id === activeTab)?.component;

  const handleTabChange = (tabId) => {
    setActiveTab(tabId);
  };

  return (
    <div className="bg-white dark:bg-dark-secondary rounded-lg shadow">
      {/* Tab Headers */}
      <div className="border-b dark:border-gray-700">
        <div className="flex justify-between items-center px-6 py-3">
          <nav className="-mb-px flex space-x-8">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => handleTabChange(tab.id)}
                className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Tab Content */}
      <div className="p-0">
        {ActiveComponent && <ActiveComponent />}
      </div>
    </div>
  );
};

export default Dpapi;
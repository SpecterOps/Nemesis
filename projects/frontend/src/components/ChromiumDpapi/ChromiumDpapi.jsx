import React, { useState } from 'react';
import ChromiumHistory from '../Chromium/ChromiumHistory';
import ChromiumDownloads from '../Chromium/ChromiumDownloads';
import ChromiumLogins from '../Chromium/ChromiumLogins';
import ChromiumCookies from '../Chromium/ChromiumCookies';
import ChromiumStateKeys from '../Chromium/ChromiumStateKeys';
import DpapiMasterKeys from '../Dpapi/DpapiMasterKeys';
import DpapiDomainBackupKeys from '../Dpapi/DpapiDomainBackupKeys';
import DpapiSubmitCredential from '../Dpapi/DpapiSubmitCredential';

const ChromiumDpapi = () => {
  const [activeTab, setActiveTab] = useState('history');
  const [tabActions, setTabActions] = useState(null);

  const tabs = [
    { id: 'history', label: 'History', component: ChromiumHistory },
    { id: 'downloads', label: 'Downloads', component: ChromiumDownloads },
    { id: 'logins', label: 'Logins', component: ChromiumLogins },
    { id: 'cookies', label: 'Cookies', component: ChromiumCookies },
    { id: 'stateKeys', label: 'State Keys', component: ChromiumStateKeys },
    { id: 'masterKeys', label: 'Master Keys', component: DpapiMasterKeys },
    { id: 'domainBackupKeys', label: 'Domain Backup Keys', component: DpapiDomainBackupKeys },
    { id: 'submitCredential', label: 'Submit Key Material', component: DpapiSubmitCredential }
  ];

  const ActiveComponent = tabs.find(tab => tab.id === activeTab)?.component;

  // Clear actions when switching away from tabs that provide them
  const handleTabChange = (tabId) => {
    if (tabId !== activeTab && ['history', 'downloads', 'logins', 'cookies', 'stateKeys'].includes(activeTab)) {
      setTabActions(null);
    }
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
          <div className="flex items-center space-x-2">
            {tabActions}
          </div>
        </div>
      </div>

      {/* Tab Content */}
      <div className="p-0">
        {ActiveComponent && (
          ['history', 'downloads', 'logins', 'cookies', 'stateKeys'].includes(activeTab) ? (
            <ActiveComponent renderActions={setTabActions} />
          ) : (
            <ActiveComponent />
          )
        )}
      </div>
    </div>
  );
};

export default ChromiumDpapi;

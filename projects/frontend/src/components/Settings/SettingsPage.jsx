import { useUser } from '@/contexts/UserContext';
import { AlertTriangle, Bell, Calendar, Database, Trash2, User } from 'lucide-react';
import React, { useState, useEffect } from 'react';
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
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
        {description}
      </p>
      {children}
    </div>
  </div>
);

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

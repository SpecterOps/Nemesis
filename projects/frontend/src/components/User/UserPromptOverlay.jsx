// src/components/User/UserPromptOverlay.jsx
import { useUser } from '@/contexts/UserContext';
import React, { useState } from 'react';

const UserPromptOverlay = () => {
  const { username, project, updateUser } = useUser();
  const [inputUsername, setInputUsername] = useState('');
  const [inputProject, setInputProject] = useState('');
  const [isOpen, setIsOpen] = useState(!username || !project);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (inputUsername.trim() && inputProject.trim()) {
      updateUser(inputUsername.trim(), inputProject.trim());
      setIsOpen(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-dark-secondary rounded-lg p-6 w-96 mx-4 shadow-xl">
        <div className="text-center mb-4">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
            Welcome to Nemesis
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Please enter your details to continue
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Username
            </label>
            <input
              id="username"
              type="text"
              value={inputUsername}
              onChange={(e) => setInputUsername(e.target.value)}
              className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:ring-2 focus:ring-blue-500"
              placeholder="Enter your username"
              required
              autoFocus
            />
          </div>

          <div>
            <label htmlFor="project" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Project Name
            </label>
            <input
              id="project"
              type="text"
              value={inputProject}
              onChange={(e) => setInputProject(e.target.value)}
              className="w-full px-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:ring-2 focus:ring-blue-500"
              placeholder="Enter project name"
              required
            />
          </div>

          <button
            type="submit"
            className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600 text-white rounded-md transition-colors"
          >
            Continue
          </button>
        </form>
      </div>
    </div>
  );
};

export default UserPromptOverlay;
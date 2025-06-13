// src/contexts/UserContext.jsx
import React, { createContext, useContext, useEffect, useState } from 'react';

const DEFAULT_EXPIRATION_DAYS = '100';

const UserContext = createContext();

export const UserProvider = ({ children }) => {
  const [username, setUsername] = useState(() => localStorage.getItem('username') || '');
  const [project, setProject] = useState(() => localStorage.getItem('project') || '');
  const [dataExpirationDays, setDataExpirationDays] = useState(
    () => localStorage.getItem('dataExpirationDays') || DEFAULT_EXPIRATION_DAYS
  );
  const [dataExpirationDate, setDataExpirationDate] = useState(
    () => localStorage.getItem('dataExpirationDate') || ''
  );

  useEffect(() => {
    localStorage.setItem('username', username);
    localStorage.setItem('project', project);
    localStorage.setItem('dataExpirationDays', dataExpirationDays);
    localStorage.setItem('dataExpirationDate', dataExpirationDate);
  }, [username, project, dataExpirationDays, dataExpirationDate]);

  const updateUser = (newUsername, newProject) => {
    if (newUsername) setUsername(newUsername);
    if (newProject) setProject(newProject);
  };

  const updateDataExpiration = (days, date) => {
    // Only update one at a time - they are mutually exclusive
    if (days !== undefined) {
      setDataExpirationDays(days);
      setDataExpirationDate('');
    } else if (date !== undefined) {
      setDataExpirationDate(date);
      setDataExpirationDays('');
    }
  };

  return (
    <UserContext.Provider
      value={{
        username,
        project,
        dataExpirationDays,
        dataExpirationDate,
        updateUser,
        updateDataExpiration
      }}
    >
      {children}
    </UserContext.Provider>
  );
};

export const useUser = () => {
  const context = useContext(UserContext);
  if (!context) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
};

export default UserContext;
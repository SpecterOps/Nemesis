import React, { createContext, useContext, useState } from 'react';

const TriageModeContext = createContext();

export const TriageModeProvider = ({ children }) => {
  const [isTriageMode, setIsTriageMode] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);

  return (
    <TriageModeContext.Provider value={{ isTriageMode, setIsTriageMode, selectedIndex, setSelectedIndex }}>
      {children}
    </TriageModeContext.Provider>
  );
};

export const useTriageMode = () => useContext(TriageModeContext);
import { createContext, useCallback, useContext, useState } from 'react';

const TriageModeContext = createContext(null);

export const TriageModeProvider = ({ children }) => {
  const [isTriageMode, setIsTriageMode] = useState(false);
  // Selected row index per list (e.g. 'files', 'findings') so switching pages doesn't carry
  // one list's index over to another
  const [selectedIndices, setSelectedIndices] = useState({});

  return (
    <TriageModeContext.Provider value={{ isTriageMode, setIsTriageMode, selectedIndices, setSelectedIndices }}>
      {children}
    </TriageModeContext.Provider>
  );
};

export const useTriageMode = (list = 'default') => {
  const { isTriageMode, setIsTriageMode, selectedIndices, setSelectedIndices } = useContext(TriageModeContext);
  const selectedIndex = selectedIndices[list] ?? -1;

  const setSelectedIndex = useCallback((value) => {
    setSelectedIndices(prev => {
      const current = prev[list] ?? -1;
      const next = typeof value === 'function' ? value(current) : value;
      return next === current ? prev : { ...prev, [list]: next };
    });
  }, [list, setSelectedIndices]);

  return { isTriageMode, setIsTriageMode, selectedIndex, setSelectedIndex };
};

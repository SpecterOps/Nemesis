import Tooltip from '@/components/shared/Tooltip2';
import { Moon, Sun } from 'lucide-react';
import React from 'react';
import { useTheme } from './ThemeProvider';

const ThemeToggle = ({ isCollapsed }) => {
  const { isDark, toggleTheme } = useTheme();

  const button = (
    <button
      onClick={toggleTheme}
      className={`w-full flex items-center ${isCollapsed ? 'justify-center px-2' : 'px-3'} py-3 text-left transition-colors
        text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800`}
      aria-label="Toggle theme"
    >
      {isDark ? (
        <Sun className={`w-5 h-5 ${isCollapsed ? '' : 'mr-3'}`} />
      ) : (
        <Moon className={`w-5 h-5 ${isCollapsed ? '' : 'mr-3'}`} />
      )}
      {!isCollapsed && (
        <span className="text-sm font-medium min-w-0 truncate">
          {isDark ? 'Light Mode' : 'Dark Mode'}
        </span>
      )}
    </button>
  );

  if (isCollapsed) {
    return (
      <div className="w-full flex justify-center">
        <Tooltip
          content={isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          side="right"
          align="center"
          sideOffset={12}
        >
          {button}
        </Tooltip>
      </div>
    );
  }

  return button;
};

export default ThemeToggle;
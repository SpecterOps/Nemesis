// src/components/ui/dialog.jsx
import React from 'react';

const Dialog = ({ open, onOpenChange, children }) => {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
      onClick={() => onOpenChange(false)}
    >
      <div
        className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 mx-4 shadow-xl"
        onClick={e => e.stopPropagation()}
      >
        {children}
      </div>
    </div>
  );
};

export default Dialog;
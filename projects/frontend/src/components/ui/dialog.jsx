// src/components/ui/dialog.jsx

const Dialog = ({ open, onOpenChange, children }) => {
  if (!open) return null;

  return (
    // Backdrop: clicking outside the panel or pressing Escape inside it closes the dialog
    <div
      role="presentation"
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
      onClick={e => {
        if (e.target === e.currentTarget) onOpenChange(false);
      }}
      onKeyDown={e => {
        if (e.key === 'Escape') onOpenChange(false);
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 mx-4 shadow-xl"
      >
        {children}
      </div>
    </div>
  );
};

export default Dialog;
// Confirmation / progress / result bar for bulk actions (see hooks/useBulkAction.js)
const BulkActionBar = ({ bulk, onConfirm, onCancel }) => {
  if (!bulk) return null;

  if (bulk.phase === 'confirm') {
    return (
      <div role="alertdialog" className="px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border-b border-amber-200 dark:border-amber-800 flex flex-wrap items-center gap-2 text-sm">
        <span className="text-amber-800 dark:text-amber-300 font-medium">{bulk.message}</span>
        <span className="text-amber-700 dark:text-amber-400">Enter to confirm, Esc to cancel.</span>
        <span className="flex gap-2 ml-auto">
          <button onClick={onConfirm} className="px-3 py-1 rounded bg-amber-600 hover:bg-amber-700 text-white">Confirm</button>
          <button onClick={onCancel} className="px-3 py-1 rounded bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-800 dark:text-gray-200">Cancel</button>
        </span>
      </div>
    );
  }

  if (bulk.phase === 'running') {
    const pct = bulk.total ? Math.min(100, Math.round((bulk.done / bulk.total) * 100)) : 0;
    return (
      <div role="status" className="px-3 py-2 bg-blue-50 dark:bg-blue-900/20 border-b dark:border-gray-700 text-sm">
        <div className="flex justify-between text-blue-700 dark:text-blue-300">
          <span>{bulk.label}…</span>
          <span>{bulk.done.toLocaleString()} / {(bulk.total || 0).toLocaleString()}</span>
        </div>
        <div className="mt-1 h-1.5 rounded bg-blue-100 dark:bg-blue-900/40 overflow-hidden">
          <div className="h-full bg-blue-600 dark:bg-blue-400 transition-all" style={{ width: `${pct}%` }} />
        </div>
      </div>
    );
  }

  const isError = bulk.phase === 'error';
  return (
    <div role="status" className={`px-3 py-2 border-b text-sm flex items-center gap-2 ${isError ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300' : 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-700 dark:text-green-300'}`}>
      <span>{bulk.message}</span>
      <button onClick={onCancel} className="ml-auto underline">Dismiss</button>
    </div>
  );
};

export default BulkActionBar;

import { triageRowClasses } from '@/hooks/pagedList';
import { ChevronDown, ChevronUp } from 'lucide-react';

// Shared look of the paginated Files and Findings tables: compact rows, sortable header buttons,
// the triage-mode ✓ column and row highlight classes.

/** Height of one list row in px (the paging/scroll math in usePagedList depends on it). */
export const LIST_ROW_HEIGHT = 42;

/**
 * Sortable column header; clicking toggles asc/desc on the active column.
 * @param {{ children: any, column: string, currentSort: string, currentDirection: string,
 *   onSort: (column: string, direction: string) => void, className?: string }} props
 */
export const SortableHeader = ({ children, column, currentSort, currentDirection, onSort, className = '' }) => {
  const isActive = currentSort === column;
  const nextDirection = isActive && currentDirection === 'asc' ? 'desc' : 'asc';

  return (
    <button
      type="button"
      className={`flex items-center cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 px-2 py-2 ${className}`}
      onClick={() => onSort(column, nextDirection)}
    >
      {/* Centered headers: balance the sort-arrow slot so the label sits over the column's center */}
      {className.includes('justify-center') && <div className="mr-1 w-3 h-3" />}
      <span className="text-sm font-medium text-gray-500 dark:text-gray-400">{children}</span>
      <div className="ml-1 flex flex-col">
        {isActive ? (
          currentDirection === 'asc' ? (
            <ChevronUp className="w-3 h-3 text-gray-600 dark:text-gray-300" />
          ) : (
            <ChevronDown className="w-3 h-3 text-gray-600 dark:text-gray-300" />
          )
        ) : (
          <div className="w-3 h-3" />
        )}
      </div>
    </button>
  );
};

/** Header cell above the triage-mode ✓ column. */
export const CheckHeaderCell = () => <div className="flex-shrink-0 w-8" />;

/** Triage-mode ✓ cell: marks selected rows (the active row is shown by its outline). */
export const CheckCell = ({ checked }) => (
  <div className="flex-shrink-0 w-8 text-sm font-medium text-gray-500 dark:text-gray-400 text-center">
    {checked ? '✓' : ''}
  </div>
);

/**
 * Class list for a list row: base layout/hover plus the triage selection/active highlight.
 * @param {boolean} isTriageMode
 * @param {boolean} isChecked
 * @param {boolean} isActive
 */
export const listRowClassName = (isTriageMode, isChecked, isActive) =>
  'flex items-center border-b dark:border-gray-700 cursor-pointer transition-colors '
  + 'dark:bg-dark-secondary hover:bg-gray-100 dark:hover:bg-gray-700 '
  + triageRowClasses(isTriageMode, isChecked, isActive);

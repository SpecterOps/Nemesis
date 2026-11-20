import { ChevronLeft, ChevronRight } from 'lucide-react';
import React from 'react';

const pageButton = 'relative inline-flex items-center px-4 py-2 text-sm font-medium';
const idleButton = 'bg-white dark:bg-dark-secondary border dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700';

// Page navigation bar shared by the Files and Findings lists
const PaginationControls = ({ currentPage, totalPages, totalCount, pageSize, onPageChange, itemLabel = 'results' }) => {
  if (totalPages <= 0) return null;
  const maxVisiblePages = 7;
  const startPage = Math.max(1, Math.min(currentPage - Math.floor(maxVisiblePages / 2), totalPages - maxVisiblePages + 1));
  const endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);

  const pageNumbers = [];
  for (let i = startPage; i <= endPage; i++) pageNumbers.push(i);

  return (
    <div className="flex items-center justify-between px-4 py-2 border-t dark:border-gray-700">
      <div className="flex-1 flex justify-between sm:hidden">
        <button
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage <= 1}
          className="relative inline-flex items-center px-4 py-2 border dark:border-gray-700 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-dark-secondary hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Previous
        </button>
        <button
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage >= totalPages}
          className="ml-3 relative inline-flex items-center px-4 py-2 border dark:border-gray-700 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-dark-secondary hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Next
        </button>
      </div>
      <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
        <p className="text-sm text-gray-700 dark:text-gray-300">
          Showing <span className="font-medium">{((currentPage - 1) * pageSize + 1).toLocaleString()}</span> to{' '}
          <span className="font-medium">{Math.min(currentPage * pageSize, totalCount).toLocaleString()}</span> of{' '}
          <span className="font-medium">{totalCount.toLocaleString()}</span> {itemLabel}
        </p>
        <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
          <button
            onClick={() => onPageChange(currentPage - 1)}
            disabled={currentPage <= 1}
            aria-label="Previous page"
            className="relative inline-flex items-center px-2 py-2 rounded-l-md border dark:border-gray-700 bg-white dark:bg-dark-secondary text-sm font-medium text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ChevronLeft className="h-5 w-5" />
          </button>

          {startPage > 1 && (
            <>
              <button onClick={() => onPageChange(1)} className={`${idleButton} ${pageButton}`}>1</button>
              {startPage > 2 && (
                <span className={`${pageButton} border dark:border-gray-700 bg-white dark:bg-dark-secondary text-gray-700 dark:text-gray-300`}>...</span>
              )}
            </>
          )}

          {pageNumbers.map((page) => (
            <button
              key={page}
              onClick={() => onPageChange(page)}
              aria-current={currentPage === page ? 'page' : undefined}
              className={`${currentPage === page
                ? 'z-10 bg-blue-50 dark:bg-blue-900/30 border border-blue-500 dark:border-blue-400 text-blue-600 dark:text-blue-400'
                : idleButton} ${pageButton}`}
            >
              {page.toLocaleString()}
            </button>
          ))}

          {endPage < totalPages && (
            <>
              {endPage < totalPages - 1 && (
                <span className={`${pageButton} border dark:border-gray-700 bg-white dark:bg-dark-secondary text-gray-700 dark:text-gray-300`}>...</span>
              )}
              <button onClick={() => onPageChange(totalPages)} className={`${idleButton} ${pageButton}`}>
                {totalPages.toLocaleString()}
              </button>
            </>
          )}

          <button
            onClick={() => onPageChange(currentPage + 1)}
            disabled={currentPage >= totalPages}
            aria-label="Next page"
            className="relative inline-flex items-center px-2 py-2 rounded-r-md border dark:border-gray-700 bg-white dark:bg-dark-secondary text-sm font-medium text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ChevronRight className="h-5 w-5" />
          </button>
        </nav>
      </div>
    </div>
  );
};

export default PaginationControls;

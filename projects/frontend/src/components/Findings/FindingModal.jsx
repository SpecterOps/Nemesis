import MarkdownRenderer from '@/components/shared/MarkdownRenderer';
import React, { useRef } from 'react';
import { useFileNavigation } from './navigation';


const FindingModal = ({
  isOpen,
  onClose,
  finding,
}) => {
  const navigateToFile = useFileNavigation();

  const handleFileNavigation = () => {
    navigateToFile(finding);
  };

  const contentRef = useRef(null);

  if (!isOpen || !finding) return null;

  const parsedData = finding.data ? JSON.parse(finding.data) : { type: 'string', data: 'No data available' };
  const findingData = parsedData;
  const readableData = findingData.type === 'finding_summary'
    ? { type: 'string', data: findingData.metadata.summary }
    : findingData;

  return (
    <div
      className="fixed inset-0 z-50 bg-black bg-opacity-30"
      onClick={onClose}
    >
      <div
        className="fixed inset-0 flex items-center justify-center pointer-events-none"
        style={{ marginLeft: 'calc(var(--navbar-width,0px)/2)' }}
      >
        <div
          className="w-11/12 max-w-6xl h-screen py-2 pointer-events-auto"
          onClick={e => e.stopPropagation()}
        >
          <div className="bg-white dark:bg-dark-secondary rounded-lg shadow-xl h-full flex flex-col relative">
            {/* Modal Header with integrated close button */}
            <div className="p-2 bg-blue-50 dark:bg-blue-900/20 border-b dark:border-gray-700 flex justify-between items-center">
              <p className="text-sm text-blue-600 dark:text-blue-400">
                Use → to view to the file, ← or ESC to go back.
              </p>
              <button
                onClick={onClose}
                className="p-1 text-gray-400 hover:text-gray-500 dark:text-gray-500 dark:hover:text-gray-400 rounded-full bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                aria-label="Close modal"
              >
                <svg className="w-5 h-5" fill="none" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 24 24" stroke="currentColor">
                  <path d="M6 18L18 6M6 6l12 12"></path>
                </svg>
              </button>
            </div>


            {/* Modal Content */}
            <div className="flex-1 overflow-y-auto" ref={contentRef}>
              <div className="p-2">
                <div className="prose dark:prose-invert max-w-none">
                  {/* Finding Details Card */}
                  <div className="mb-6 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg space-y-0">
                    <div className="flex items-center">
                      <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">Finding:</span>
                      <span className="text-gray-900 dark:text-gray-100">{finding.finding_name}</span>
                    </div>
                    <div className="flex items-center">
                      <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">File Path:</span>
                      <button
                        className="text-blue-600 dark:text-blue-400 hover:underline text-left"
                        onClick={handleFileNavigation}
                      >
                        {finding.files_enriched?.path || 'Unknown path'}
                      </button>
                    </div>
                    <div className="flex items-center">
                      <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">Category:</span>
                      <span className="text-gray-900 dark:text-gray-100">{finding.category}</span>
                    </div>
                    <div className="flex items-center">
                      <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">Agent ID:</span>
                      <span className="text-gray-900 dark:text-gray-100">
                        {finding.files_enriched?.agent_id || 'N/A'}
                      </span>
                    </div>
                    <div className="flex items-center">
                      <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">Magic Type:</span>
                      <span className="text-gray-900 dark:text-gray-100">
                        {finding.files_enriched?.magic_type || 'N/A'}
                      </span>
                    </div>
                  </div>

                  {/* Finding Content */}
                  <MarkdownRenderer content={readableData.data} />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FindingModal;
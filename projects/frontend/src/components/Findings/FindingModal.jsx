import MarkdownRenderer from '@/components/shared/MarkdownRenderer';
import { WrapText } from 'lucide-react';
import React, { useRef, useState } from 'react';
import { useFileNavigation } from './navigation';

const FindingModal = ({
  isOpen,
  onClose,
  finding,
}) => {
  const navigateToFile = useFileNavigation();
  const [wordWrapEnabled, setWordWrapEnabled] = useState(false);

  const handleFileNavigation = () => {
    navigateToFile(finding);
  };

  const contentRef = useRef(null);

  if (!isOpen || !finding) return null;

  const parsedData = finding.data ?
    (typeof finding.data === 'string' ? JSON.parse(finding.data) : finding.data)
    : { type: 'string', data: 'No data available' };

  // Handle case where data is an array (common format) - take first element
  let findingData = Array.isArray(parsedData) ? parsedData[0] : parsedData;

  // Handle double JSON encoding - if findingData is still a string, parse it again
  if (typeof findingData === 'string') {
    try {
      findingData = JSON.parse(findingData);
    } catch (e) {
      // If parsing fails, treat it as plain text
      findingData = { type: 'string', data: findingData };
    }
  }

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
              <div className="flex items-center space-x-2">
                {/* Word Wrap Toggle Button */}
                <button
                  onClick={() => setWordWrapEnabled(!wordWrapEnabled)}
                  className={`p-1 rounded-full transition-colors ${
                    wordWrapEnabled
                      ? 'bg-blue-100 dark:bg-blue-800 text-blue-600 dark:text-blue-400'
                      : 'bg-gray-100 dark:bg-gray-700 text-gray-400 hover:text-gray-500 dark:text-gray-500 dark:hover:text-gray-400'
                  } hover:bg-gray-200 dark:hover:bg-gray-600`}
                  aria-label={wordWrapEnabled ? "Disable word wrap" : "Enable word wrap"}
                  title={wordWrapEnabled ? "Disable word wrap" : "Enable word wrap"}
                >
                  <WrapText className="w-5 h-5" />
                </button>

                {/* Close Button */}
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
                      <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">Source:</span>
                      <span className="text-gray-900 dark:text-gray-100">
                        {finding.files_enriched?.source || 'Unknown'}
                      </span>
                    </div>
                    <div className="flex items-center">
                      <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">Magic Type:</span>
                      <span className="text-gray-900 dark:text-gray-100">
                        {finding.files_enriched?.magic_type || 'N/A'}
                      </span>
                    </div>
                  </div>

                  {/* Triage Details Card */}
                  {finding.finding_triage_histories && finding.finding_triage_histories.length > 0 && (
                    <div className="mb-6 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg space-y-0">
                      {(() => {
                        const triage = finding.finding_triage_histories[0];
                        return (
                          <>
                            <div className="flex items-center">
                              <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">Status:</span>
                              <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                                triage.value === 'true_positive' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300' :
                                triage.value === 'false_positive' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300' :
                                triage.value === 'informational' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300' :
                                'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                              }`}>
                                {triage.value.replace('_', ' ').toUpperCase()}
                              </span>
                            </div>
                            <div className="flex items-center">
                              <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">Triaged By:</span>
                              <span className="text-gray-900 dark:text-gray-100">
                                {triage.username}
                                {triage.automated && (
                                  <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">(Automated)</span>
                                )}
                              </span>
                            </div>
                            <div className="flex items-center">
                              <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">Timestamp:</span>
                              <span className="text-gray-900 dark:text-gray-100">
                                {new Date(triage.timestamp).toLocaleString()}
                              </span>
                            </div>
                            {triage.confidence && triage.confidence !== '' && (
                              <div className="flex items-center">
                                <span className="w-32 font-semibold text-gray-700 dark:text-gray-300">Confidence:</span>
                                <span className="text-gray-900 dark:text-gray-100">{triage.confidence}</span>
                              </div>
                            )}
                            {triage.explanation && triage.explanation !== '' && (
                              <div className="flex flex-col mt-2">
                                <span className="font-semibold text-gray-700 dark:text-gray-300 mb-1">Explanation:</span>
                                <div className="p-2 bg-white dark:bg-gray-900 rounded border border-gray-200 dark:border-gray-700">
                                  <span className="text-gray-900 dark:text-gray-100 whitespace-pre-wrap">{triage.explanation}</span>
                                </div>
                              </div>
                            )}
                            {triage.true_positive_context && triage.true_positive_context !== '' && (
                              <div className="flex flex-col mt-2">
                                <span className="font-semibold text-gray-700 dark:text-gray-300 mb-1">Risk Context:</span>
                                <div className="p-2 bg-white dark:bg-gray-900 rounded border border-gray-200 dark:border-gray-700">
                                  <span className="text-gray-900 dark:text-gray-100 whitespace-pre-wrap">{triage.true_positive_context}</span>
                                </div>
                              </div>
                            )}
                          </>
                        );
                      })()}
                    </div>
                  )}

                  {/* Finding Content with conditional word wrap */}
                  <div>
                    {wordWrapEnabled && (
                      <style dangerouslySetInnerHTML={{
                        __html: `
                          .word-wrap-container *,
                          .word-wrap-container pre,
                          .word-wrap-container code {
                            word-break: break-all !important;
                            overflow-wrap: anywhere !important;
                            white-space: pre-wrap !important;
                            word-wrap: break-word !important;
                          }
                        `
                      }} />
                    )}
                    <div className={wordWrapEnabled ? 'word-wrap-container' : 'overflow-x-auto'}>
                      <MarkdownRenderer content={readableData.data} />
                    </div>
                  </div>
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
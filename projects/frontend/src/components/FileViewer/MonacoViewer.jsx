import { useTheme } from '@/components/ThemeProvider';
import Tooltip from '@/components/shared/Tooltip';
import Editor from "@monaco-editor/react";
import React, { useEffect, useRef, useState } from 'react';

const MonacoContentViewer = ({ content, language, onLanguageChange, showLanguageSelect = true, isTruncated = false, onShowFullContent, isLoadingFullContent = false }) => {
  const { isDark } = useTheme();
  const editorRef = useRef(null);
  const [wordWrapEnabled, setWordWrapEnabled] = useState(false);

  const availableLanguages = [
    'abap', 'apex', 'azcli', 'bat', 'bicep', 'cameligo', 'clojure', 'coffeescript',
    'c', 'cpp', 'csharp', 'css', 'cypher', 'dart', 'dockerfile', 'elixir', 'flow9',
    'fsharp', 'go', 'graphql', 'handlebars', 'hcl', 'html', 'ini', 'java', 'javascript',
    'julia', 'kotlin', 'less', 'lexon', 'liquid', 'lua', 'm3', 'markdown', 'mdx',
    'mips', 'msdax', 'mysql', 'objective-c', 'pascal', 'pascaligo', 'perl', 'php',
    'pla', 'powerquery', 'powershell', 'proto', 'pug', 'python', 'qsharp', 'r',
    'razor', 'redis', 'redshift', 'restructuredtext', 'ruby', 'rust', 'sb', 'scala',
    'scheme', 'scss', 'shell', 'sol', 'sparql', 'sql', 'st', 'swift', 'systemverilog',
    'tcl', 'twig', 'typescript', 'vb', 'verilog', 'xml', 'yaml'
  ].sort();

  // Force layout updates when content changes
  useEffect(() => {
    if (editorRef.current) {
      // Small delay to ensure content is loaded before resizing
      setTimeout(() => {
        editorRef.current.layout();
      }, 100);
    }
  }, [content]);

  // Update word wrap setting when toggled
  useEffect(() => {
    if (editorRef.current) {
      editorRef.current.updateOptions({
        wordWrap: wordWrapEnabled ? 'on' : 'off'
      });
    }
  }, [wordWrapEnabled]);

  // Force layout updates when the component is visible
  useEffect(() => {
    // Create MutationObserver to detect visibility changes
    if (typeof MutationObserver !== 'undefined' && editorRef.current) {
      const observer = new MutationObserver(() => {
        if (editorRef.current) {
          editorRef.current.layout();
        }
      });

      // Start observing the editor's parent elements for attribute changes
      const editorElement = editorRef.current.getDomNode()?.parentElement;
      if (editorElement) {
        observer.observe(editorElement.parentElement, {
          attributes: true,
          childList: false,
          subtree: false
        });
      }

      return () => observer.disconnect();
    }
  }, []);

  const LoadingComponent = () => (
    <div className="flex items-center justify-center h-full bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 transition-colors">
      <div className="flex flex-col items-center space-y-4">
        <div className="animate-spin h-8 w-8 border-4 border-blue-500 dark:border-blue-400 rounded-full border-t-transparent"></div>
        <span>Loading editor...</span>
      </div>
    </div>
  );

  return (
    <div className="relative">
      <div className="w-full h-[600px] rounded-lg overflow-hidden border dark:border-gray-700 transition-colors">
        <div className="absolute top-2 right-2 z-10 flex items-center gap-3">
          {/* Word wrap toggle checkbox */}
          <div className="flex items-center gap-2 px-3 py-1 border dark:border-gray-700 rounded-md bg-white dark:bg-gray-800 text-sm">
            <input
              type="checkbox"
              id="word-wrap-toggle"
              checked={wordWrapEnabled}
              onChange={() => setWordWrapEnabled(!wordWrapEnabled)}
              className="rounded border-gray-300 dark:border-gray-600 text-blue-600 dark:text-blue-500 focus:ring-blue-500 dark:focus:ring-blue-400"
            />
            <label htmlFor="word-wrap-toggle" className="text-gray-900 dark:text-gray-100 select-none">
              Word Wrap
            </label>
          </div>

          {/* Content size selector - only when content is truncated */}
          {isTruncated && onShowFullContent && (
            <Tooltip content="Content is truncated to 10 MB for performance. Showing the full file may cause the UI to freeze or crash for very large files.">
              <select
                value="truncated"
                disabled={isLoadingFullContent}
                onChange={(e) => { if (e.target.value === 'full') onShowFullContent(); }}
                className="px-3 py-1 border dark:border-gray-700 rounded-md text-sm
                         bg-white dark:bg-gray-800
                         text-gray-900 dark:text-gray-100
                         focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400
                         focus:border-blue-500 dark:focus:border-blue-400
                         transition-colors"
              >
                <option value="truncated">
                  {isLoadingFullContent ? 'Loading full file...' : 'Truncated (10 MB)'}
                </option>
                <option value="full">Full File (may freeze UI)</option>
              </select>
            </Tooltip>
          )}

          {/* Language selector */}
          {showLanguageSelect && (
            <select
              value={language}
              onChange={(e) => onLanguageChange(e.target.value)}
              className="px-3 py-1 border dark:border-gray-700 rounded-md text-sm
                       bg-white dark:bg-gray-800
                       text-gray-900 dark:text-gray-100
                       focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400
                       focus:border-blue-500 dark:focus:border-blue-400
                       transition-colors"
            >
              {availableLanguages.map((lang) => (
                <option
                  key={lang}
                  value={lang}
                  className="bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                >
                  {lang}
                </option>
              ))}
            </select>
          )}
        </div>
        {isLoadingFullContent && (
          <div className="absolute inset-0 z-20 flex items-center justify-center bg-white/60 dark:bg-gray-900/60 backdrop-blur-sm">
            <div className="flex flex-col items-center space-y-3">
              <div className="animate-spin h-8 w-8 border-4 border-blue-500 dark:border-blue-400 rounded-full border-t-transparent"></div>
              <span className="text-sm text-gray-700 dark:text-gray-300">Loading full file...</span>
            </div>
          </div>
        )}
        <Editor
          height="100%"
          language={language}
          value={content}
          theme={isDark ? "vs-dark" : "light"}
          loading={<LoadingComponent />}
          options={{
            readOnly: true,
            minimap: { enabled: true },
            scrollBeyondLastLine: true, // Changed to true to allow scrolling past the last line
            wordWrap: wordWrapEnabled ? 'on' : 'off',
            lineNumbers: 'on',
            folding: true,
            fontSize: 14,
            ...(isDark && {
              backgroundColor: { regular: '#1a1a1a' },
              lineHighlightBackground: '#2a2a2a',
              scrollbarSliderBackground: '#404040',
              scrollbarSliderHoverBackground: '#505050',
              scrollbarSliderActiveBackground: '#606060'
            })
          }}
          onMount={(editor, monaco) => {
            // Store editor reference
            editorRef.current = editor;

            // Initial layout
            setTimeout(() => editor.layout(), 100);

            // Create proper resize handler function for consistent reference
            const handleResize = () => {
              editor.layout();
            };

            // Add event listener for window resize
            window.addEventListener('resize', handleResize);

            // Create an observer for parent element size changes
            if (typeof ResizeObserver !== 'undefined') {
              const resizeObserver = new ResizeObserver(() => {
                editor.layout();
              });

              // Observe the parent container for size changes
              const container = editor.getDomNode()?.parentElement;
              if (container) {
                resizeObserver.observe(container);

                // Also observe parent's parent for tab changes
                if (container.parentElement) {
                  resizeObserver.observe(container.parentElement);
                }
              }

              // Cleanup function
              return () => {
                window.removeEventListener('resize', handleResize);
                resizeObserver.disconnect();
              };
            } else {
              // Fallback for browsers without ResizeObserver
              return () => {
                window.removeEventListener('resize', handleResize);
              };
            }
          }}
        />
      </div>
    </div>
  );
};

export default MonacoContentViewer;
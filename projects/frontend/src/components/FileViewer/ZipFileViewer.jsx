import { useTheme } from '@/components/ThemeProvider';
import JSZip from 'jszip';
import { AlertCircle, ChevronDown, ChevronRight, FileText, Folder, Search, X } from 'lucide-react';
// NEW: Import useCallback for memoizing the resizing function
import React, { useCallback, useEffect, useRef, useState } from 'react';
import MonacoContentViewer from './MonacoViewer';
import { getMonacoLanguage } from './languageMap';

const MAX_DISPLAYABLE_SIZE = 2 * 1024 * 1024; // 2MB text file display limit

const ZipFileViewer = ({ fileBuffer, fileName }) => {
    const { isDark } = useTheme();
    const [zipContent, setZipContent] = useState(null);
    const [zipStructure, setZipStructure] = useState(null);
    const [expandedFolders, setExpandedFolders] = useState({});
    const [openFiles, setOpenFiles] = useState([]);
    const [activeTab, setActiveTab] = useState(null);
    const [fileContents, setFileContents] = useState({});
    const [loading, setLoading] = useState(true);
    const [extracting, setExtracting] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');
    const [error, setError] = useState(null);

    const fileExplorerRef = useRef(null);
    const searchInputRef = useRef(null);

    // --- RESIZING LOGIC START ---
    const [sidebarWidth, setSidebarWidth] = useState(256); // Default width (w-64 is 16rem = 256px)
    const isResizing = useRef(false);
    const minSidebarWidth = 150; // Minimum width for the sidebar
    const maxSidebarWidth = 800; // Maximum width for the sidebar

    // This function handles the mouse down event on the resizer handle
    const startResizing = useCallback((mouseDownEvent) => {
        isResizing.current = true;

        const handleMouseMove = (mouseMoveEvent) => {
            if (isResizing.current) {
                // Calculate the new width based on mouse movement
                let newWidth = mouseMoveEvent.clientX - fileExplorerRef.current.getBoundingClientRect().left;

                // Clamp the width between min and max values
                if (newWidth < minSidebarWidth) newWidth = minSidebarWidth;
                if (newWidth > maxSidebarWidth) newWidth = maxSidebarWidth;

                setSidebarWidth(newWidth);
            }
        };

        const stopResizing = () => {
            isResizing.current = false;
            // Clean up event listeners
            window.removeEventListener('mousemove', handleMouseMove);
            window.removeEventListener('mouseup', stopResizing);
            // Manually trigger a resize event for Monaco Editor to adjust its layout
            window.dispatchEvent(new Event('resize'));
        };

        // Attach listeners to the window to capture mouse movement anywhere on the page
        window.addEventListener('mousemove', handleMouseMove);
        window.addEventListener('mouseup', stopResizing);
    }, []);
    // --- RESIZING LOGIC END ---


    // Force layout updates when active tab changes
    useEffect(() => {
        if (activeTab) {
            const timer = setTimeout(() => {
                window.dispatchEvent(new Event('resize'));
            }, 50);

            return () => clearTimeout(timer);
        }
    }, [activeTab]);

    // Additional hook to force layout when viewing a new file
    useEffect(() => {
        if (activeTab && fileContents[activeTab]) {
            const timers = [50, 150, 300, 500].map(delay =>
                setTimeout(() => {
                    window.dispatchEvent(new Event('resize'));
                }, delay)
            );

            return () => timers.forEach(timer => clearTimeout(timer));
        }
    }, [activeTab, fileContents]);

    // Additional hook that triggers when fileContents is updated for any path
    useEffect(() => {
        if (activeTab && fileContents[activeTab]) {
            const timers = [100, 250, 400].map(delay =>
                setTimeout(() => {
                    window.dispatchEvent(new Event('resize'));
                }, delay)
            );

            return () => timers.forEach(timer => clearTimeout(timer));
        }
    }, [fileContents, activeTab]);

    // Load and process the ZIP file
    useEffect(() => {
        const loadZipContents = async () => {
            try {
                setLoading(true);

                if (!fileBuffer) {
                    throw new Error('No file data available');
                }

                const zip = new JSZip();
                const content = await zip.loadAsync(fileBuffer);
                setZipContent(content);

                const structure = buildZipStructure(content);
                setZipStructure(structure);
                setExpandedFolders({ '/': true });

                setLoading(false);
            } catch (err) {
                console.error('Error processing ZIP file:', err);
                setError(`Failed to process ZIP file: ${err.message}`);
                setLoading(false);
            }
        };

        loadZipContents();
    }, [fileBuffer]);

    // Make sure Monaco editor resizes properly when the window or container changes size
    useEffect(() => {
        const handleResize = () => {
            window.dispatchEvent(new Event('resize'));
        };

        window.addEventListener('resize', handleResize);

        if (activeTab) {
            setTimeout(handleResize, 50);
        }

        return () => {
            window.removeEventListener('resize', handleResize);
        };
    }, [activeTab]);

    // (The rest of your functions like buildZipStructure, toggleFolder, etc., remain unchanged)
    // ...
    // buildZipStructure, toggleFolder, openFile, closeTab, formatFileSize, isLikelyBinaryFile, handleSearchChange, filterTree, renderFileTree
    // ... (All these helper functions are identical to your original code)
    //
    const buildZipStructure = (zipContent) => {
        const structure = { name: '/', type: 'directory', path: '/', children: {} };
        Object.keys(zipContent.files).forEach(filePath => {
            const file = zipContent.files[filePath];
            if (file.dir) return;
            const pathSegments = filePath.split('/');
            const fileName = pathSegments.pop();
            let currentFolder = structure;
            let currentPath = '/';
            pathSegments.forEach(segment => {
                if (!segment) return;
                currentPath += segment + '/';
                if (!currentFolder.children[segment]) {
                    currentFolder.children[segment] = {
                        name: segment,
                        type: 'directory',
                        path: currentPath,
                        children: {}
                    };
                }
                currentFolder = currentFolder.children[segment];
            });
            currentFolder.children[fileName] = {
                name: fileName,
                type: 'file',
                path: filePath,
                size: file._data ? file._data.uncompressedSize : 0,
                compressedSize: file._data ? file._data.compressedSize : 0,
                zipObject: file
            };
        });
        return structure;
    };
    const toggleFolder = (path) => {
        setExpandedFolders(prev => ({ ...prev, [path]: !prev[path] }));
    };
    const openFile = async (file) => {
        if (!openFiles.find(f => f.path === file.path)) {
            setOpenFiles([...openFiles, file]);
        }
        setActiveTab(file.path);
        if (!fileContents[file.path]) {
            try {
                setExtracting(true);
                const zipObject = file.zipObject;
                if (file.size > MAX_DISPLAYABLE_SIZE) {
                    setFileContents(prev => ({ ...prev, [file.path]: `File is too large to display (${formatFileSize(file.size)}). Maximum size is ${formatFileSize(MAX_DISPLAYABLE_SIZE)}.` }));
                    setExtracting(false);
                    return;
                }
                const isBinary = isLikelyBinaryFile(file.name);
                if (isBinary) {
                    setFileContents(prev => ({ ...prev, [file.path]: `Binary file content cannot be displayed. File size: ${formatFileSize(file.size)}` }));
                } else {
                    const content = await zipObject.async('string');
                    setFileContents(prev => ({ ...prev, [file.path]: content }));
                }
                setExtracting(false);
            } catch (err) {
                console.error('Error extracting file:', err);
                setFileContents(prev => ({ ...prev, [file.path]: `Error loading file: ${err.message}` }));
                setExtracting(false);
            }
        }
    };
    const closeTab = (path, e) => {
        e.stopPropagation();
        const newOpenFiles = openFiles.filter(f => f.path !== path);
        setOpenFiles(newOpenFiles);
        if (activeTab === path) {
            setActiveTab(newOpenFiles.length > 0 ? newOpenFiles[newOpenFiles.length - 1].path : null);
        }
    };
    const formatFileSize = (size) => {
        if (size < 1024) return `${size} B`;
        if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
        return `${(size / (1024 * 1024)).toFixed(1)} MB`;
    };
    const isLikelyBinaryFile = (fileName) => {
        const binaryExtensions = ['.pdf', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.db', '.sqlite', '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.wav', '.ogg', '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'];
        const ext = '.' + fileName.split('.').pop().toLowerCase();
        return binaryExtensions.includes(ext);
    };
    const handleSearchChange = (e) => {
        setSearchTerm(e.target.value);
    };
    useEffect(() => {
        const handleKeyDown = (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
                e.preventDefault();
                searchInputRef.current?.focus();
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, []);
    const filterTree = (node, term) => {
        if (!term) return true;
        const searchLower = term.toLowerCase();
        if (node.name.toLowerCase().includes(searchLower)) return true;
        if (node.type === 'directory' && node.children) {
            for (const childName in node.children) {
                if (filterTree(node.children[childName], term)) return true;
            }
        }
        return false;
    };
    const renderFileTree = (node, level = 0) => {
        if (searchTerm && !filterTree(node, searchTerm)) return null;
        if (node.type === 'directory') {
            const isExpanded = expandedFolders[node.path] || false;
            return (
                <div key={node.path} className="file-tree-node">
                    <div className={`flex items-center cursor-pointer py-1 hover:bg-gray-100 dark:hover:bg-gray-700 pl-2 ${searchTerm && node.name.toLowerCase().includes(searchTerm.toLowerCase()) ? 'bg-yellow-100 dark:bg-yellow-900/30' : ''}`} style={{ paddingLeft: `${level * 12 + 4}px` }} onClick={() => toggleFolder(node.path)}>
                        {isExpanded ? <ChevronDown className="w-4 h-4 text-gray-500 dark:text-gray-400 mr-1" /> : <ChevronRight className="w-4 h-4 text-gray-500 dark:text-gray-400 mr-1" />}
                        <Folder className={`w-4 h-4 mr-2 ${isExpanded ? 'text-blue-500' : 'text-gray-500 dark:text-gray-400'}`} />
                        <span className="text-sm truncate text-gray-900 dark:text-gray-200">{node.name}</span>
                    </div>
                    {isExpanded && node.children && Object.keys(node.children).length > 0 && (
                        <div className="directory-contents">
                            {Object.values(node.children).sort((a, b) => {
                                if (a.type === 'directory' && b.type !== 'directory') return -1;
                                if (a.type !== 'directory' && b.type === 'directory') return 1;
                                return a.name.localeCompare(b.name);
                            }).map(child => renderFileTree(child, level + 1))}
                        </div>
                    )}
                </div>
            );
        } else {
            return (
                <div key={node.path} className={`flex items-center cursor-pointer py-1 hover:bg-gray-100 dark:hover:bg-gray-700 pl-2 ${activeTab === node.path ? 'bg-blue-100 dark:bg-blue-900/50' : searchTerm && node.name.toLowerCase().includes(searchTerm.toLowerCase()) ? 'bg-yellow-100 dark:bg-yellow-900/30' : ''}`} style={{ paddingLeft: `${level * 12 + 8}px` }} onClick={() => openFile(node)}>
                    <FileText className="w-4 h-4 text-gray-500 dark:text-gray-400 mr-2" />
                    <span className="text-sm truncate text-gray-900 dark:text-gray-200">{node.name}</span>
                    <span className="text-xs text-gray-500 dark:text-gray-400 ml-2">{formatFileSize(node.size)}</span>
                </div>
            );
        }
    };


    if (loading) {
        return (
            <div className="flex justify-center items-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center">
                <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 mr-2" />
                <p className="text-red-600 dark:text-red-400">{error}</p>
            </div>
        );
    }

    return (
        <div className="flex flex-col h-full border dark:border-gray-700 rounded-lg overflow-hidden">
            <div className="text-sm font-medium px-4 py-2 bg-gray-100 dark:bg-gray-800 border-b dark:border-gray-700 flex justify-between items-center text-gray-900 dark:text-gray-200">
                <span>ZIP Explorer: {fileName}</span>
                <div className="relative">
                    <Search className="w-4 h-4 absolute left-2 top-1/2 transform -translate-y-1/2 text-gray-400" />
                    <input
                        ref={searchInputRef}
                        type="text"
                        placeholder="Search for files..."
                        value={searchTerm}
                        onChange={handleSearchChange}
                        className="pl-8 pr-4 py-1 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-200 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>
            </div>

            <div className="flex flex-1 overflow-hidden">
                {/* File Explorer Sidebar */}
                {/* MODIFIED: Replaced w-64 with inline style for dynamic width. Added flex-shrink-0 */}
                <div
                    ref={fileExplorerRef}
                    style={{ width: `${sidebarWidth}px` }}
                    className="flex-shrink-0 bg-white dark:bg-gray-900 overflow-y-auto"
                >
                    {zipStructure && (
                        <div className="py-2">
                            {Object.values(zipStructure.children)
                                .sort((a, b) => {
                                    if (a.type === 'directory' && b.type !== 'directory') return -1;
                                    if (a.type !== 'directory' && b.type === 'directory') return 1;
                                    return a.name.localeCompare(b.name);
                                })
                                .map(node => renderFileTree(node))
                            }
                        </div>
                    )}
                </div>

                {/* NEW: Resizer Handle */}
                <div
                    onMouseDown={startResizing}
                    className="w-1.5 cursor-col-resize flex-shrink-0 bg-gray-200 dark:bg-gray-700 hover:bg-blue-500 transition-colors"
                />

                {/* Content Area */}
                {/* MODIFIED: Removed border-r as the resizer now provides the visual separation */}
                <div className="flex-1 flex flex-col overflow-hidden">
                    {/* Tabs */}
                    {openFiles.length > 0 ? (
                        <>
                            <div className="flex overflow-x-auto bg-white dark:bg-gray-800 border-b dark:border-gray-700">
                                {openFiles.map(file => (
                                    <div
                                        key={file.path}
                                        className={`flex items-center px-3 py-2 text-sm cursor-pointer border-r dark:border-gray-700 max-w-xs ${activeTab === file.path
                                                ? 'bg-white dark:bg-gray-900 text-blue-600 dark:text-blue-400 border-b-2 border-b-blue-500'
                                                : 'bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-gray-200'
                                            }`}
                                        onClick={() => setActiveTab(file.path)}
                                    >
                                        <span className="truncate">{file.name}</span>
                                        <X
                                            className="w-4 h-4 ml-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 flex-shrink-0"
                                            onClick={(e) => closeTab(file.path, e)}
                                        />
                                    </div>
                                ))}
                            </div>

                            {/* File Content */}
                            <div className="flex-1 overflow-hidden">
                                {extracting ? (
                                    <div className="flex items-center justify-center h-full bg-gray-50 dark:bg-gray-900">
                                        <div className="flex flex-col items-center">
                                            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400 mb-2"></div>
                                            <p className="text-gray-600 dark:text-gray-400">Extracting file...</p>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="h-full">
                                        {openFiles.map(file => (
                                            <div
                                                key={file.path}
                                                style={{
                                                    height: '100%',
                                                    display: activeTab === file.path ? 'block' : 'none'
                                                }}
                                            >
                                                <MonacoContentViewer
                                                    content={fileContents[file.path] || 'Loading file content...'}
                                                    language={getMonacoLanguage(file.name || '')}
                                                    onLanguageChange={() => { }}
                                                    showLanguageSelect={false}
                                                    key={`${file.path}-${!!fileContents[file.path]}`}
                                                />
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </>
                    ) : (
                        <div className="flex items-center justify-center h-full bg-gray-50 dark:bg-gray-900 text-gray-500 dark:text-gray-400">
                            <p>Select a file from the explorer to view its contents</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ZipFileViewer;
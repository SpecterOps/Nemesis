import { useTheme } from '@/components/ThemeProvider';
import Editor from "@monaco-editor/react";
import { AlertCircle, ChevronDown, ChevronRight, Database, Download, ExternalLink, FileWarning, Info, Play, RefreshCw, Table } from 'lucide-react';
import React, { useEffect, useRef, useState } from 'react';
import initSQLJS from 'sql.js';

// Maximum number of rows to display at once
const MAX_ROWS = 1000;

const SQLiteViewer = ({ fileBuffer, fileName }) => {
    const { isDark } = useTheme();
    const [db, setDb] = useState(null);
    const [tables, setTables] = useState([]);
    const [views, setViews] = useState([]);
    const [selectedTable, setSelectedTable] = useState(null);
    const [tableData, setTableData] = useState(null);
    const [tableStructure, setTableStructure] = useState(null);
    const [sqlQuery, setSqlQuery] = useState('');
    const [queryResult, setQueryResult] = useState(null);
    const [loading, setLoading] = useState(true);
    const [queryLoading, setQueryLoading] = useState(false);
    const [error, setError] = useState(null);
    const [activeTab, setActiveTab] = useState('tables');
    const [rowCount, setRowCount] = useState(0);
    const [hasMoreRows, setHasMoreRows] = useState(false);
    const [sqlJsInitialized, setSqlJsInitialized] = useState(false);
    const sqlJsRef = useRef(null);
    // Add a state for file header preview
    const [fileHeaderHex, setFileHeaderHex] = useState('');
    // Add state for table structure collapse
    const [isStructureCollapsed, setIsStructureCollapsed] = useState(true);

    const editorRef = useRef(null);
    const setEditorRef = (editor) => {
        editorRef.current = editor;
    };

    // Initialize SQL.js once when component loads
    useEffect(() => {
        const loadSqlJs = async () => {
            try {
                // Use CDN directly for sql.js WASM file
                const SQL = await initSQLJS({
                    locateFile: file => `https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.13.0/${file}`,
                });

                console.log('Successfully loaded SQL.js WASM from CDN');
                sqlJsRef.current = SQL;
                setSqlJsInitialized(true);
            } catch (err) {
                console.error('Failed to initialize SQL.js:', err);
                setError(`Failed to initialize SQL.js: ${err.message}`);
            }
        };

        loadSqlJs();
    }, []);

    // Extract file header to help diagnose file issues
    useEffect(() => {
        if (fileBuffer && fileBuffer.byteLength > 0) {
            // Get first 16 bytes for header inspection
            const headerBytes = new Uint8Array(fileBuffer.slice(0, Math.min(32, fileBuffer.byteLength)));
            const headerHex = Array.from(headerBytes)
                .map(byte => byte.toString(16).padStart(2, '0'))
                .join(' ');
            setFileHeaderHex(headerHex);
        }
    }, [fileBuffer]);

    // Then try to open the database with enhanced error handling
    useEffect(() => {
        if (!sqlJsInitialized || !fileBuffer) return;

        try {
            // Before passing to SQL.js, validate that the file looks like a SQLite file
            // SQLite files start with "SQLite format 3\0" (magic number)
            const header = new Uint8Array(fileBuffer.slice(0, 16));
            const isSQLiteHeader = header[0] === 0x53 && // 'S'
                header[1] === 0x51 && // 'Q'
                header[2] === 0x4C && // 'L'
                header[3] === 0x69;   // 'i'

            if (!isSQLiteHeader) {
                throw new Error(`File doesn't appear to be a valid SQLite database. File header: ${fileHeaderHex}`);
            }

            // New approach - wrap this in a try/catch and convert any errors
            try {
                const sqlDb = new sqlJsRef.current.Database(new Uint8Array(fileBuffer));
                setDb(sqlDb);

                // Get table list
                const tableResult = sqlDb.exec("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
                if (tableResult && tableResult.length > 0) {
                    const tableNames = tableResult[0].values.flat();
                    setTables(tableNames);

                    // Select first table by default
                    if (tableNames.length > 0) {
                        setSelectedTable(tableNames[0]);
                    }
                }

                // Get view list
                const viewResult = sqlDb.exec("SELECT name FROM sqlite_master WHERE type='view' ORDER BY name");
                if (viewResult && viewResult.length > 0) {
                    const viewNames = viewResult[0].values.flat();
                    setViews(viewNames);
                }

                setLoading(false);
            } catch (dbError) {
                console.error('Error creating database:', dbError);
                throw new Error(`Failed to read SQLite database: ${dbError.message}`);
            }
        } catch (err) {
            console.error('Error initializing SQLite database:', err);
            setError(`${err.message}`);
            setLoading(false);
        }
    }, [sqlJsInitialized, fileBuffer, fileHeaderHex]);

    // The rest of your component remains the same...

    // Render file analysis section when there's an error
    const renderFileAnalysis = () => {
        if (!fileBuffer) return null;

        return (
            <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border dark:border-gray-700">
                <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-3 flex items-center">
                    <FileWarning className="w-5 h-5 mr-2 text-yellow-500" />
                    File Analysis
                </h3>

                <div className="space-y-3">
                    <div>
                        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">File Header (Hex)</h4>
                        <pre className="bg-gray-100 dark:bg-gray-700 p-2 rounded text-xs font-mono overflow-x-auto">
                            {fileHeaderHex}
                        </pre>
                    </div>

                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        <Info className="inline w-4 h-4 mr-1 text-blue-500" />
                        A valid SQLite database should start with "SQLite format 3" (hex: 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00).
                    </p>

                    <div className="flex flex-col space-y-2">
                        <p className="text-sm text-gray-700 dark:text-gray-300">This file may be:</p>
                        <ul className="list-disc list-inside text-sm text-gray-600 dark:text-gray-400 pl-4">
                            <li>Not a SQLite database</li>
                            <li>Corrupted or incomplete</li>
                            <li>A newer SQLite format not supported by SQL.js</li>
                            <li>Encrypted</li>
                        </ul>
                    </div>

                    <div className="mt-4 flex space-x-3">
                        <a
                            href="https://www.sqlite.org/fileformat.html"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center text-sm text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                        >
                            <ExternalLink className="w-4 h-4 mr-1" />
                            SQLite File Format Documentation
                        </a>
                    </div>
                </div>
            </div>
        );
    };

    // Load table data when selected table changes
    useEffect(() => {
        if (!db || !selectedTable) return;

        const loadTableData = async () => {
            try {
                // Get table structure
                const structureQuery = `PRAGMA table_info(${escapeSQLIdentifier(selectedTable)})`;
                const structureResult = db.exec(structureQuery);
                if (structureResult && structureResult.length > 0) {
                    setTableStructure({
                        columns: structureResult[0].columns,
                        values: structureResult[0].values
                    });
                }

                // Get row count
                const countQuery = `SELECT COUNT(*) FROM ${escapeSQLIdentifier(selectedTable)}`;
                const countResult = db.exec(countQuery);
                if (countResult && countResult.length > 0) {
                    const count = countResult[0].values[0][0];
                    setRowCount(count);
                    setHasMoreRows(count > MAX_ROWS);
                }

                // Get table data (limited to prevent browser freeze with large tables)
                const dataQuery = `SELECT * FROM ${escapeSQLIdentifier(selectedTable)} LIMIT ${MAX_ROWS}`;
                const dataResult = db.exec(dataQuery);
                if (dataResult && dataResult.length > 0) {
                    setTableData({
                        columns: dataResult[0].columns,
                        values: dataResult[0].values
                    });
                } else {
                    setTableData({ columns: [], values: [] });
                }

                // Set default SQL query
                setSqlQuery(`SELECT * FROM ${selectedTable} LIMIT 100;`);
            } catch (err) {
                console.error('Error loading table data:', err);
                setError(`Failed to load table data: ${err.message}`);
            }
        };

        loadTableData();
    }, [db, selectedTable]);

    // Execute custom SQL query
    const executeQuery = () => {
        if (!db || !sqlQuery.trim()) return;

        setQueryLoading(true);
        setError(null);

        try {
            const result = db.exec(sqlQuery);
            if (result && result.length > 0) {
                setQueryResult({
                    columns: result[0].columns,
                    values: result[0].values
                });
            } else {
                // Handle empty result or statements like INSERT, UPDATE, DELETE
                setQueryResult({ columns: [], values: [] });
            }
        } catch (err) {
            console.error('Error executing SQL query:', err);
            setError(`SQL error: ${err.message}`);
            setQueryResult(null);
        } finally {
            setQueryLoading(false);
        }
    };

    // Helper function to escape SQL identifiers
    const escapeSQLIdentifier = (identifier) => {
        // SQLite identifiers should be wrapped in double quotes if they contain special characters
        return `"${identifier.replace(/"/g, '""')}"`;
    };

    // Format cell values for display
    const formatCellValue = (value) => {
        if (value === null) return <span className="text-gray-400 italic">NULL</span>;
        if (typeof value === 'object') return JSON.stringify(value);
        if (typeof value === 'string' && value.length > 100) {
            return `${value.substring(0, 100)}...`;
        }
        return String(value);
    };

    // Handle keyboard shortcuts
    useEffect(() => {
        const handleKeyDown = (e) => {
            // Execute query on Ctrl+Enter or Cmd+Enter when in the SQL editor
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                if (activeTab === 'query' && document.activeElement.closest('.monaco-editor')) {
                    e.preventDefault();
                    executeQuery();
                }
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [activeTab, sqlQuery]);

    if (loading) {
        return (
            <div className="flex justify-center items-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
            </div>
        );
    }

    if (error && !db) {
        return (
            <div className="flex flex-col space-y-4">
                <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center">
                    <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 mr-2" />
                    <p className="text-red-600 dark:text-red-400">{error}</p>
                </div>

                {/* Show file analysis to help with debugging */}
                {renderFileAnalysis()}

                {/* Add options to download and try another tool */}
                <div className="flex space-x-4 mt-4">
                    <button
                        onClick={() => {
                            const a = document.createElement('a');
                            const blob = new Blob([fileBuffer], { type: 'application/octet-stream' });
                            a.href = URL.createObjectURL(blob);
                            a.download = fileName;
                            document.body.appendChild(a);
                            a.click();
                            document.body.removeChild(a);
                        }}
                        className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                    >
                        <Download className="w-4 h-4 mr-2" />
                        Download Raw File
                    </button>
                </div>
            </div>
        );
    }

    // Toggle table structure visibility
    const toggleStructure = () => {
        setIsStructureCollapsed(!isStructureCollapsed);
    };

    // Rest of your component (UI rendering for tabs, tables, etc.)
    return (
        <div className="flex flex-col h-full border dark:border-gray-700 rounded-lg overflow-hidden">
            <div className="text-sm font-medium text-gray-800 dark:text-gray-200 px-4 py-2 bg-gray-100 dark:bg-gray-800 border-b dark:border-gray-700 flex justify-between items-center">
                <span>SQLite Explorer: {fileName}</span>
                <div className="flex gap-2">
                    <button
                        onClick={() => setActiveTab('tables')}
                        className={`px-3 py-1 rounded-md text-sm flex items-center gap-1 ${activeTab === 'tables'
                            ? 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300'
                            : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
                            }`}
                    >
                        <Table className="w-4 h-4" />
                        Tables
                    </button>
                    <button
                        onClick={() => setActiveTab('query')}
                        className={`px-3 py-1 rounded-md text-sm flex items-center gap-1 ${activeTab === 'query'
                            ? 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300'
                            : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
                            }`}
                    >
                        <Play className="w-4 h-4" />
                        Custom Query
                    </button>
                </div>
            </div>

            <div className="flex flex-1 overflow-hidden">
                {/* Left sidebar: Table list */}
                <div className="w-64 border-r dark:border-gray-700 bg-white dark:bg-gray-800 overflow-y-auto">
                    <div className="p-3 border-b dark:border-gray-700">
                        <div className="flex items-center space-x-2 text-sm font-medium text-gray-600 dark:text-gray-300">
                            <Database className="w-4 h-4" />
                            <span>{tables.length} Tables, {views.length} Views</span>
                        </div>
                    </div>

                    {/* Tables */}
                    <div className="py-1">
                        <div className="px-3 py-1 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                            Tables
                        </div>
                    {tables.map(table => (
                        <div
                        key={table}
                        className={`flex items-center px-3 py-2 text-sm cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 ${
                            selectedTable === table
                            ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                            : 'text-gray-700 dark:text-gray-300'
                        }`}
                        onClick={() => setSelectedTable(table)}
                        >
                        <Table className="w-4 h-4 mr-2 text-gray-500 dark:text-gray-400" />
                        <span className="truncate">{table}</span>
                        </div>
                    ))}
                    </div>

                    {/* Views */}
                    {views.length > 0 && (
                    <div className="py-1">
                        <div className="px-3 py-1 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Views
                        </div>
                        {views.map(view => (
                        <div
                            key={view}
                            className={`flex items-center px-3 py-2 text-sm cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 ${
                            selectedTable === view
                                ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                                : 'text-gray-700 dark:text-gray-300'
                            }`}
                            onClick={() => setSelectedTable(view)}
                        >
                            <Table className="w-4 h-4 mr-2 text-gray-500 dark:text-gray-400" />
                            <span className="truncate">{view}</span>
                        </div>
                        ))}
                    </div>
                    )}
                </div>

                {/* Content area */}
                <div className="flex-1 overflow-hidden">
                    {activeTab === 'tables' ? (
                        // Table data view
                        <div className="h-full flex flex-col">
                            {selectedTable ? (
                                <>
                                    <div className="p-4 border-b dark:border-gray-700 bg-white dark:bg-gray-800 flex justify-between items-center">
                                        <div>
                                            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">{selectedTable}</h3>
                                            <p className="text-sm text-gray-500 dark:text-gray-400">
                                                {rowCount} rows {hasMoreRows && `(showing first ${MAX_ROWS})`}
                                            </p>
                                        </div>
                                    </div>

                                    {/* Collapsible Table Structure */}
                                    {tableStructure && (
                                        <div className="border-b dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
                                            {/* Clickable header for collapsing/expanding */}
                                            <div
                                                className="px-4 py-3 flex items-center cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700"
                                                onClick={toggleStructure}
                                            >
                                                {isStructureCollapsed ?
                                                    <ChevronRight className="w-4 h-4 mr-2 text-gray-500 dark:text-gray-400" /> :
                                                    <ChevronDown className="w-4 h-4 mr-2 text-gray-500 dark:text-gray-400" />
                                                }
                                                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                                                    Table Structure
                                                </h4>
                                            </div>

                                            {/* Collapsible content */}
                                            {!isStructureCollapsed && (
                                                <div className="px-4 pb-3">
                                                    <div className="overflow-x-auto">
                                                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
                                                            <thead className="bg-gray-100 dark:bg-gray-700">
                                                                <tr>
                                                                    {tableStructure.columns.map(column => (
                                                                        <th key={column} className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                                                                            {column}
                                                                        </th>
                                                                    ))}
                                                                </tr>
                                                            </thead>
                                                            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                                                {tableStructure.values.map((row, rowIndex) => (
                                                                    <tr key={rowIndex} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                                                                        {row.map((cell, cellIndex) => (
                                                                            <td key={cellIndex} className="px-3 py-2 whitespace-nowrap text-gray-700 dark:text-gray-300">
                                                                                {formatCellValue(cell)}
                                                                            </td>
                                                                        ))}
                                                                    </tr>
                                                                ))}
                                                            </tbody>
                                                        </table>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Table data */}
                                    {tableData && (
                                        <div className="overflow-auto flex-1 bg-white dark:bg-gray-800">
                                            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
                                                <thead className="bg-gray-100 dark:bg-gray-700 sticky top-0">
                                                    <tr>
                                                        {tableData.columns.map(column => (
                                                            <th key={column} className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                                                                {column}
                                                            </th>
                                                        ))}
                                                    </tr>
                                                </thead>
                                                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                                                    {tableData.values.length > 0 ? (
                                                        tableData.values.map((row, rowIndex) => (
                                                            <tr key={rowIndex} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                                                                {row.map((cell, cellIndex) => (
                                                                    <td key={cellIndex} className="px-3 py-2 whitespace-nowrap text-gray-700 dark:text-gray-300">
                                                                        {formatCellValue(cell)}
                                                                    </td>
                                                                ))}
                                                            </tr>
                                                        ))
                                                    ) : (
                                                        <tr>
                                                            <td colSpan={tableData.columns.length} className="px-3 py-2 text-center text-gray-500 dark:text-gray-400">
                                                                No data available
                                                            </td>
                                                        </tr>
                                                    )}
                                                </tbody>
                                            </table>

                                            {hasMoreRows && (
                                                <div className="p-3 text-center text-gray-500 dark:text-gray-400 text-sm bg-gray-50 dark:bg-gray-700 border-t dark:border-gray-600">
                                                    Showing first {MAX_ROWS} rows of {rowCount}. Use a custom SQL query to filter or limit results.
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </>
                            ) : (
                                <div className="flex items-center justify-center h-full bg-gray-50 dark:bg-gray-900 text-gray-500 dark:text-gray-400">
                                    <p>Select a table from the sidebar to view its data</p>
                                </div>
                            )}
                        </div>
                    ) : (
                        // SQL query view
                        <div className="h-full flex flex-col">
                            <div className="border-b dark:border-gray-700 p-4 bg-white dark:bg-gray-800">
                                <div className="flex justify-between items-center mb-2">
                                    <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">SQL Query Editor</h3>
                                    <button
                                        onClick={executeQuery}
                                        disabled={queryLoading}
                                        className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm flex items-center gap-1 disabled:bg-blue-400 disabled:cursor-not-allowed"
                                    >
                                        {queryLoading ? (
                                            <RefreshCw className="w-4 h-4 animate-spin" />
                                        ) : (
                                            <Play className="w-4 h-4" />
                                        )}
                                        Run Query
                                    </button>
                                </div>
                                <p className="text-sm text-gray-500 dark:text-gray-400 mb-3">
                                    Press Ctrl+Enter (or Cmd+Enter on Mac) to execute the query
                                </p>
                                <div className="h-48 border dark:border-gray-700 rounded-md overflow-hidden">
                                    <EditableMonacoViewer
                                        content={sqlQuery}
                                        language="sql"
                                        readOnly={false}
                                        onChange={setSqlQuery}
                                        editorRef={setEditorRef}
                                    />
                                </div>
                            </div>

                            {error && (
                                <div className="m-4 p-3 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center">
                                    <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 mr-2 flex-shrink-0" />
                                    <p className="text-red-600 dark:text-red-400 text-sm">{error}</p>
                                </div>
                            )}

                            {/* Query results */}
                            {queryResult && (
                                <div className="flex-1 overflow-auto bg-white dark:bg-gray-800 p-4">
                                    <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                        Query Results {queryResult.values.length > 0 && `(${queryResult.values.length} rows)`}
                                    </h4>

                                    <div className="overflow-x-auto border dark:border-gray-700 rounded-md">
                                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
                                            <thead className="bg-gray-100 dark:bg-gray-700">
                                                <tr>
                                                    {queryResult.columns.map(column => (
                                                        <th key={column} className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                                                            {column}
                                                        </th>
                                                    ))}
                                                </tr>
                                            </thead>
                                            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                                {queryResult.values.length > 0 ? (
                                                    queryResult.values.map((row, rowIndex) => (
                                                        <tr key={rowIndex} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                                                            {row.map((cell, cellIndex) => (
                                                                <td key={cellIndex} className="px-3 py-2 whitespace-nowrap text-gray-700 dark:text-gray-300">
                                                                    {formatCellValue(cell)}
                                                                </td>
                                                            ))}
                                                        </tr>
                                                    ))
                                                ) : (
                                                    <tr>
                                                        <td colSpan={queryResult.columns.length || 1} className="px-3 py-2 text-center text-gray-500 dark:text-gray-400">
                                                            {queryResult.columns.length === 0 ? 'Query executed successfully. No results to display.' : 'No data available'}
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            )}

                            {!queryResult && !error && (
                                <div className="flex items-center justify-center flex-1 bg-gray-50 dark:bg-gray-900 text-gray-500 dark:text-gray-400">
                                    <p>Run a query to see results</p>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

const EditableMonacoViewer = ({ content, language, readOnly = true, onChange, editorRef }) => {
    const { isDark } = useTheme();
    const [value, setValue] = useState(content);

    useEffect(() => {
        setValue(content);
    }, [content]);

    const handleEditorChange = (newValue) => {
        setValue(newValue);
        if (onChange) {
            onChange(newValue);
        }
    };

    return (
        <div className="h-full">
            <Editor
                height="100%"
                language={language}
                value={value}
                theme={isDark ? "vs-dark" : "light"}
                onChange={handleEditorChange}
                options={{
                    readOnly: readOnly,
                    minimap: { enabled: true },
                    scrollBeyondLastLine: false,
                    wordWrap: 'on',
                    lineNumbers: 'on',
                    folding: true,
                    fontSize: 14,
                }}
                onMount={(editor) => {
                    if (editorRef) {
                        editorRef(editor);
                    }
                    // Initial layout
                    setTimeout(() => editor.layout(), 100);
                }}
            />
        </div>
    );
};

export default SQLiteViewer;
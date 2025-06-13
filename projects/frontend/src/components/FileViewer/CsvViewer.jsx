import React, { useState, useEffect } from 'react';
import Papa from 'papaparse';
import { ChevronDown, ChevronUp, ArrowUpDown } from 'lucide-react';

const CsvViewer = ({ content }) => {
    const [csvData, setCsvData] = useState([]);
    const [originalData, setOriginalData] = useState([]);
    const [error, setError] = useState(null);
    const [sortConfig, setSortConfig] = useState({
        key: null,
        direction: null // null for original order, 'ascending', or 'descending'
    });

    useEffect(() => {
        try {
            if (typeof content !== 'string' || content.trim() === '') {
                setCsvData([]);
                setOriginalData([]);
                return;
            }

            // Use PapaParse for robust CSV parsing
            const result = Papa.parse(content, {
                delimiter: ',',          // Auto-detect delimiter
                newline: undefined,      // Auto-detect newline
                quoteChar: '"',          // Set quote character
                escapeChar: '"',         // Set escape character
                header: false,           // We'll handle headers manually
                skipEmptyLines: true,    // Skip empty lines
                transformHeader: undefined // Don't transform header
            });

            if (result.errors && result.errors.length > 0) {
                console.warn('CSV parsing warnings:', result.errors);
            }

            // Store both the displayed and original data
            setCsvData(result.data);
            setOriginalData(result.data);
            
            // Reset sorting when content changes
            setSortConfig({ key: null, direction: null });
        } catch (e) {
            setError('Error parsing CSV content');
            console.error('CSV parsing error:', e);
        }
    }, [content]);

    // Helper function to determine if a value is numeric
    const isNumeric = (value) => {
        return !isNaN(parseFloat(value)) && isFinite(value);
    };

    // Function to handle column header click for sorting
    const handleSort = (columnIndex) => {
        let direction = 'ascending';
        
        if (sortConfig.key === columnIndex) {
            if (sortConfig.direction === 'ascending') {
                direction = 'descending';
            } else if (sortConfig.direction === 'descending') {
                direction = null;
            }
        }
        
        setSortConfig({ key: columnIndex, direction });
    };

    // Effect to sort data when sortConfig changes
    useEffect(() => {
        if (!originalData.length || originalData.length <= 1) return;
        
        if (sortConfig.direction === null || sortConfig.key === null) {
            // Reset to original order
            setCsvData(originalData);
            return;
        }
        
        const headers = originalData[0];
        const dataToSort = [...originalData.slice(1)]; // Create a copy of the data rows
        
        const sortedRows = dataToSort.sort((a, b) => {
            const columnIndex = sortConfig.key;
            
            // Handle cases where the cell might not exist
            const valueA = a[columnIndex] !== undefined ? a[columnIndex] : '';
            const valueB = b[columnIndex] !== undefined ? b[columnIndex] : '';
            
            // Try to sort numerically if both values are numbers
            if (isNumeric(valueA) && isNumeric(valueB)) {
                return sortConfig.direction === 'ascending' 
                    ? parseFloat(valueA) - parseFloat(valueB)
                    : parseFloat(valueB) - parseFloat(valueA);
            }
            
            // Otherwise sort alphabetically
            if (valueA < valueB) {
                return sortConfig.direction === 'ascending' ? -1 : 1;
            }
            if (valueA > valueB) {
                return sortConfig.direction === 'ascending' ? 1 : -1;
            }
            return 0;
        });
        
        // Combine headers with sorted rows
        setCsvData([headers, ...sortedRows]);
    }, [sortConfig, originalData]);

    // Render sort indicator for column headers
    const renderSortIcon = (columnIndex) => {
        if (sortConfig.key !== columnIndex) {
            return <ArrowUpDown className="w-4 h-4 ml-1 opacity-50" />;
        }
        
        if (sortConfig.direction === 'ascending') {
            return <ChevronUp className="w-4 h-4 ml-1" />;
        }
        
        return <ChevronDown className="w-4 h-4 ml-1" />;
    };

    if (error) {
        return (
            <div className="text-red-500 p-4">
                {error}
            </div>
        );
    }

    if (csvData.length === 0) {
        return (
            <div className="text-gray-500 p-4">
                No CSV data to display
            </div>
        );
    }

    const headers = csvData[0];
    const rows = csvData.slice(1);

    return (
        <div className="p-4 bg-white dark:bg-gray-900 rounded-lg overflow-auto max-h-[80vh]">
            <table className="w-full border-collapse">
                <thead className="bg-gray-100 dark:bg-gray-800 sticky top-0">
                    <tr>
                        {headers.map((header, index) => (
                            <th
                                key={`header-${index}`}
                                className="border dark:border-gray-700 px-4 py-2 text-left font-semibold text-gray-700 dark:text-gray-300 cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                                onClick={() => handleSort(index)}
                            >
                                <div className="flex items-center gap-1">
                                    {/* Replace newlines with <br /> for proper display */}
                                    <span>
                                        {typeof header === 'string' ? header.split('\n').map((line, i) => (
                                            <React.Fragment key={i}>
                                                {i > 0 && <br />}
                                                {line}
                                            </React.Fragment>
                                        )) : header}
                                    </span>
                                    {renderSortIcon(index)}
                                </div>
                            </th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {rows.map((row, rowIndex) => (
                        <tr
                            key={`row-${rowIndex}`}
                            className={rowIndex % 2 === 0 ? 'bg-white dark:bg-gray-900' : 'bg-gray-50 dark:bg-gray-800'}
                        >
                            {row.map((cell, cellIndex) => (
                                <td
                                    key={`cell-${rowIndex}-${cellIndex}`}
                                    className="border dark:border-gray-700 px-4 py-2 text-gray-700 dark:text-gray-300"
                                >
                                    {/* Handle newlines in cell content too */}
                                    {typeof cell === 'string' ? cell.split('\n').map((line, i) => (
                                        <React.Fragment key={i}>
                                            {i > 0 && <br />}
                                            {line}
                                        </React.Fragment>
                                    )) : cell}
                                </td>
                            ))}
                            {/* Fill empty cells if row has fewer columns than headers */}
                            {row.length < headers.length && Array(headers.length - row.length).fill().map((_, i) => (
                                <td
                                    key={`empty-${rowIndex}-${i}`}
                                    className="border dark:border-gray-700 px-4 py-2"
                                ></td>
                            ))}
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default CsvViewer;
import { ChevronDown, ChevronRight } from 'lucide-react';
import React, { useState, useEffect } from 'react';

const JsonViewer = ({ content }) => {
    const [expandedPaths, setExpandedPaths] = useState(new Set([]));
    
    // Initialize with all paths expanded
    useEffect(() => {
        const expandAllPaths = (obj, basePath = 'root') => {
            const paths = new Set([basePath]);
            
            const traverse = (value, path) => {
                if (value === null || typeof value !== 'object') return;
                
                if (Array.isArray(value)) {
                    value.forEach((item, index) => {
                        const newPath = `${path}.${index}`;
                        paths.add(newPath);
                        traverse(item, newPath);
                    });
                } else {
                    Object.keys(value).forEach(key => {
                        const newPath = `${path}.${key}`;
                        paths.add(newPath);
                        traverse(value[key], newPath);
                    });
                }
            };
            
            traverse(obj, basePath);
            return paths;
        };
        
        try {
            const parsedContent = typeof content === 'string' ? JSON.parse(content) : content;
            setExpandedPaths(expandAllPaths(parsedContent));
        } catch (e) {
            // If JSON is invalid, do nothing
        }
    }, [content]);

    const togglePath = (path) => {
        const newPaths = new Set(expandedPaths);
        if (newPaths.has(path)) {
            newPaths.delete(path);
        } else {
            newPaths.add(path);
        }
        setExpandedPaths(newPaths);
    };

    const renderValue = (value, path, depth = 0) => {
        if (value === null) return <span className="text-gray-500">null</span>;
        if (typeof value === 'boolean') return <span className="text-purple-500">{value.toString()}</span>;
        if (typeof value === 'number') return <span className="text-blue-500">{value}</span>;
        if (typeof value === 'string') return <span className="text-green-500">"{value}"</span>;

        if (Array.isArray(value)) {
            if (value.length === 0) return <span className="text-gray-500">[]</span>;

            const isExpanded = expandedPaths.has(path);
            return (
                <div>
                    <div
                        className="inline-flex items-center cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 rounded px-1"
                        onClick={() => togglePath(path)}
                    >
                        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                        <span className="text-gray-500">[{value.length}]</span>
                    </div>
                    {isExpanded && (
                        <div className="ml-4 border-l dark:border-gray-700 pl-2">
                            {value.map((item, index) => (
                                <div key={`${path}.${index}`}>
                                    {renderValue(item, `${path}.${index}`, depth + 1)}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            );
        }

        if (typeof value === 'object') {
            const keys = Object.keys(value);
            if (keys.length === 0) return <span className="text-gray-500">{"{}"}</span>;

            const isExpanded = expandedPaths.has(path);
            return (
                <div>
                    <div
                        className="inline-flex items-center cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 rounded px-1"
                        onClick={() => togglePath(path)}
                    >
                        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                        <span className="text-gray-500">{"{...}"}</span>
                    </div>
                    {isExpanded && (
                        <div className="ml-4 border-l dark:border-gray-700 pl-2">
                            {keys.map(key => (
                                <div key={`${path}.${key}`} className="flex">
                                    <span className="text-gray-700 dark:text-gray-300 mr-2">"{key}":</span>
                                    {renderValue(value[key], `${path}.${key}`, depth + 1)}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            );
        }

        return <span>{String(value)}</span>;
    };

    let parsedContent;
    try {
        parsedContent = typeof content === 'string' ? JSON.parse(content) : content;
    } catch (e) {
        return (
            <div className="text-red-500 p-4">
                Invalid JSON content
            </div>
        );
    }

    return (
        <div className="font-mono text-sm p-4 bg-white dark:bg-gray-900 rounded-lg">
            {renderValue(parsedContent, 'root')}
        </div>
    );
};

export default JsonViewer;
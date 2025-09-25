import { AlertTriangle, Bot, Filter, Search, ThumbsUp, ChevronDown } from 'lucide-react';
import React, { useEffect, useMemo, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useSearchParams } from 'react-router-dom';

const FindingsFilters = ({
    findings,
    onFilteredDataChange,
    sortColumn,
    sortDirection
}) => {
    const [searchParams, setSearchParams] = useSearchParams();

    // Helper functions for URL parameter handling
    const getFilterFromUrl = (key, defaultValue) => {
        const value = searchParams.get(key);
        return value !== null ? value : defaultValue;
    };

    const convertSeverityFromUrl = (urlSeverity) => {
        const severityMap = {
            'high': '7',
            'medium': '4',
            'low': '0'
        };
        return urlSeverity ? (severityMap[urlSeverity] || 'all') : 'all';
    };

    // Initialize state from URL parameters
    const [categoryFilter, setCategoryFilter] = React.useState(() =>
        getFilterFromUrl('category', 'all')
    );

    const [severityFilter, setSeverityFilter] = React.useState(() => {
        const urlSeverity = convertSeverityFromUrl(getFilterFromUrl('severity', 'all'));
        if (urlSeverity === 'all') {
            return ['high', 'medium', 'low'];
        } else {
            const severityMap = { '7': 'high', '4': 'medium', '0': 'low' };
            return [severityMap[urlSeverity]];
        }
    });
    const [severityDropdownOpen, setSeverityDropdownOpen] = React.useState(false);
    const severityDropdownRef = useRef(null);
    const severityButtonRef = useRef(null);
    const [dropdownPosition, setDropdownPosition] = React.useState({ top: 0, left: 0 });

    const [originFilter, setOriginFilter] = React.useState(() =>
        getFilterFromUrl('origin', '')
    );

    const [triageFilter, setTriageFilter] = React.useState(() =>
        getFilterFromUrl('triage_state', 'untriaged_and_actionable')
    );

    const [triageSourceFilter, setTriageSourceFilter] = React.useState(() =>
        getFilterFromUrl('triage_source', 'all')
    );

    // Add object_id filter
    const [objectIdFilter, setObjectIdFilter] = React.useState(() =>
        getFilterFromUrl('object_id', '')
    );


    // Check if any filters are active
    const hasActiveFilters = useMemo(() => {
        return categoryFilter !== 'all' ||
            severityFilter.length !== 3 ||
            originFilter !== '' ||
            triageFilter !== 'untriaged_and_actionable' ||
            triageSourceFilter !== 'all' ||
            objectIdFilter !== '';
    }, [categoryFilter, severityFilter, originFilter, triageFilter, triageSourceFilter, objectIdFilter]);

    // Handle clearing all filters
    const handleClearFilters = () => {
        setCategoryFilter('all');
        setSeverityFilter(['high', 'medium', 'low']);
        setOriginFilter('');
        setTriageFilter('untriaged_and_actionable');
        setTriageSourceFilter('all');
        setObjectIdFilter('');
    };

    // Update URL when filters change
    useEffect(() => {
        const newParams = new URLSearchParams();

        // Only set parameters that aren't default values
        if (categoryFilter !== 'all') {
            newParams.set('category', categoryFilter);
        }

        if (severityFilter.length === 1) {
            const severityMap = { 'high': 'high', 'medium': 'medium', 'low': 'low' };
            newParams.set('severity', severityMap[severityFilter[0]]);
        } else if (severityFilter.length !== 3) {
            // If not all severities are selected, we need to handle this differently
            // For now, we'll only handle single selection in URL
        }

        if (originFilter) {
            newParams.set('origin', originFilter);
        }

        newParams.set('triage_state', triageFilter);

        if (triageSourceFilter !== 'all') {
            newParams.set('triage_source', triageSourceFilter);
        }

        if (objectIdFilter) {
            newParams.set('object_id', objectIdFilter);
        }

        // Preserve other existing parameters that we don't manage
        for (const [key, value] of searchParams.entries()) {
            if (!['category', 'severity', 'origin', 'triage_state', 'triage_source', 'object_id'].includes(key)) {
                newParams.set(key, value);
            }
        }

        // Only update if parameters have actually changed
        if (newParams.toString() !== searchParams.toString()) {
            setSearchParams(newParams, { replace: false });
        }
    }, [categoryFilter, severityFilter, originFilter, triageFilter, triageSourceFilter, objectIdFilter, setSearchParams, searchParams]);

    // Memoized filtered and sorted findings calculation
    const filteredFindings = useMemo(() => {
        const filtered = findings.filter(finding => {
            // Category filter
            if (categoryFilter !== 'all' && finding.category !== categoryFilter) return false;

            // Severity filter
            if (severityFilter.length < 3) {
                let severityMatch = false;
                for (const selected of severityFilter) {
                    if (selected === 'high' && finding.severity >= 7) {
                        severityMatch = true;
                        break;
                    }
                    if (selected === 'medium' && finding.severity >= 4 && finding.severity < 7) {
                        severityMatch = true;
                        break;
                    }
                    if (selected === 'low' && finding.severity < 4) {
                        severityMatch = true;
                        break;
                    }
                }
                if (!severityMatch) return false;
            }

            // Origin filter
            if (originFilter && !finding.origin_name.toLowerCase().includes(originFilter.toLowerCase())) return false;

            // Object ID filter
            if (objectIdFilter && finding.object_id.toString() !== objectIdFilter) return false;

            // Triage state filter
            if (triageFilter && triageFilter !== 'all') {
                const hasTriage = finding.finding_triage_histories.length > 0;
                const latestTriage = hasTriage ? finding.finding_triage_histories[0].value : null;

                switch (triageFilter) {
                    case 'untriaged':
                        if (hasTriage) return false;
                        break;
                    case 'untriaged_and_actionable':
                        // Show untriaged files OR files triaged as true_positive or needs_review from automated sources
                        if (hasTriage) {
                            const isAutomated = finding.finding_triage_histories[0].automated;
                            if (!isAutomated || (latestTriage !== 'true_positive' && latestTriage !== 'needs_review')) {
                                return false;
                            }
                        }
                        break;
                    case 'triaged':
                        if (!hasTriage) return false;
                        break;
                    case 'true_positive':
                    case 'false_positive':
                    case 'needs_review':
                        if (latestTriage !== triageFilter) return false;
                        break;
                }
            }

            // Triage source filter
            if (triageSourceFilter !== 'all') {
                const hasTriage = finding.finding_triage_histories.length > 0;
                if (!hasTriage) return false;

                const isAutomated = finding.finding_triage_histories[0].automated;
                if (triageSourceFilter === 'automated' && !isAutomated) return false;
                if (triageSourceFilter === 'human' && isAutomated) return false;
            }

            return true;
        });

        // Apply sorting
        return filtered.sort((a, b) => {
            let comparison = 0;

            switch (sortColumn) {
                case 'severity':
                    comparison = a.severity - b.severity;
                    break;
                case 'created_at':
                    comparison = new Date(a.created_at) - new Date(b.created_at);
                    break;
                case 'finding_name':
                    comparison = a.finding_name.localeCompare(b.finding_name);
                    break;
                case 'category':
                    comparison = a.category.localeCompare(b.category);
                    break;
                case 'origin_name':
                    comparison = a.origin_name.localeCompare(b.origin_name);
                    break;
                case 'file_path':
                    const pathA = a.files_enriched?.path || '';
                    const pathB = b.files_enriched?.path || '';
                    comparison = pathA.localeCompare(pathB);
                    break;
                case 'triage_value':
                    const triageA = a.finding_triage_histories.length > 0 ? a.finding_triage_histories[0].value : '';
                    const triageB = b.finding_triage_histories.length > 0 ? b.finding_triage_histories[0].value : '';
                    comparison = triageA.localeCompare(triageB);
                    break;
                default:
                    comparison = new Date(a.created_at) - new Date(b.created_at);
            }

            return sortDirection === 'asc' ? comparison : -comparison;
        });
    }, [findings, categoryFilter, severityFilter, originFilter, triageFilter, triageSourceFilter, objectIdFilter, sortColumn, sortDirection]);

    // Notify parent component of filtered data changes
    useEffect(() => {
        onFilteredDataChange(filteredFindings);
    }, [filteredFindings, onFilteredDataChange]);

    // Filter change handlers
    const handleCategoryChange = (e) => {
        setCategoryFilter(e.target.value);
    };

    const handleSeverityToggle = (severity) => {
        setSeverityFilter(prev => {
            if (prev.includes(severity)) {
                const newSelection = prev.filter(s => s !== severity);
                return newSelection.length === 0 ? ['high', 'medium', 'low'] : newSelection;
            } else {
                return [...prev, severity];
            }
        });
    };

    // Close dropdown when clicking outside
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (severityDropdownRef.current && !severityDropdownRef.current.contains(event.target)) {
                setSeverityDropdownOpen(false);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, []);

    const getSeverityButtonText = () => {
        if (severityFilter.length === 3) return 'All Severities';
        if (severityFilter.length === 0) return 'No Severities';
        const labels = { high: 'High', medium: 'Medium', low: 'Low' };
        return severityFilter.map(s => labels[s]).join(', ');
    };

    const updateDropdownPosition = () => {
        if (severityButtonRef.current) {
            const rect = severityButtonRef.current.getBoundingClientRect();
            setDropdownPosition({
                top: rect.bottom + window.scrollY,
                left: rect.left + window.scrollX
            });
        }
    };

    const handleSeverityDropdownToggle = () => {
        if (!severityDropdownOpen) {
            updateDropdownPosition();
        }
        setSeverityDropdownOpen(!severityDropdownOpen);
    };

    const handleOriginChange = (e) => {
        setOriginFilter(e.target.value);
    };

    const handleTriageStateChange = (e) => {
        setTriageFilter(e.target.value);
    };

    const handleTriageSourceChange = (e) => {
        setTriageSourceFilter(e.target.value);
    };

    return (
        <div className="p-2 border-b dark:border-gray-700 overflow-x-auto">
            <div className="flex items-center space-x-4 min-w-max">
                <div className="flex items-center space-x-2">
                    <ThumbsUp className="w-5 h-5 text-gray-500 dark:text-gray-400 flex-shrink-0" />
                    <select
                        className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
                        value={triageFilter}
                        onChange={handleTriageStateChange}
                    >
                        <option value="untriaged_and_actionable">Untriaged + Actionable</option>
                        <option value="all">All Triage States</option>
                        <option value="untriaged">Untriaged Only</option>
                        <option value="triaged">Triaged Only</option>
                        <option value="true_positive">True Positive</option>
                        <option value="false_positive">False Positive</option>
                        <option value="needs_review">Needs Review</option>
                    </select>
                </div>

                <div className="flex items-center space-x-2">
                    <Filter className="w-5 h-5 text-gray-500 dark:text-gray-400 flex-shrink-0" />
                    <select
                        className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
                        value={categoryFilter}
                        onChange={handleCategoryChange}
                    >
                        <option value="all">All Categories</option>
                        <option value="credential">Credentials</option>
                        <option value="vulnerability">Vulnerabilities</option>
                        <option value="yara_match">Yara</option>
                        <option value="extracted_hash">Extracted Hashes</option>
                        <option value="extracted_data">Extracted Data</option>
                        <option value="pii">PII</option>
                    </select>
                </div>

                <div className="flex items-center space-x-2">
                    <AlertTriangle className="w-5 h-5 text-gray-500 dark:text-gray-400 flex-shrink-0" />
                    <button
                        ref={severityButtonRef}
                        className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2 flex items-center space-x-2 hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors"
                        onClick={handleSeverityDropdownToggle}
                    >
                        <span>{getSeverityButtonText()}</span>
                        <ChevronDown className={`w-4 h-4 transition-transform ${severityDropdownOpen ? 'rotate-180' : ''}`} />
                    </button>
                </div>
                {severityDropdownOpen && createPortal(
                    <div
                        ref={severityDropdownRef}
                        className="fixed bg-white dark:bg-dark-secondary border dark:border-gray-700 rounded shadow-lg z-50 min-w-48"
                        style={{
                            top: `${dropdownPosition.top}px`,
                            left: `${dropdownPosition.left}px`
                        }}
                    >
                        <div className="p-2">
                            {[
                                { key: 'high', label: 'High (7-10)', color: 'text-red-600 dark:text-red-400' },
                                { key: 'medium', label: 'Medium (4-6)', color: 'text-orange-600 dark:text-orange-400' },
                                { key: 'low', label: 'Low (0-3)', color: 'text-yellow-600 dark:text-yellow-400' }
                            ].map(({ key, label, color }) => (
                                <label key={key} className="flex items-center space-x-2 p-1 hover:bg-gray-100 dark:hover:bg-gray-600 rounded cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={severityFilter.includes(key)}
                                        onChange={() => handleSeverityToggle(key)}
                                        className="rounded"
                                    />
                                    <span className={`${color} font-medium`}>{label}</span>
                                </label>
                            ))}
                        </div>
                    </div>,
                    document.body
                )}

                <div className="flex items-center space-x-2">
                    <Search className="w-5 h-5 text-gray-500 dark:text-gray-400 flex-shrink-0" />
                    <input
                        type="text"
                        placeholder="Filter by origin"
                        className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2 w-40"
                        value={originFilter}
                        onChange={handleOriginChange}
                    />
                </div>

                <div className="flex items-center space-x-2">
                    <Bot className="w-5 h-5 text-gray-500 dark:text-gray-400 flex-shrink-0" />
                    <select
                        className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
                        value={triageSourceFilter}
                        onChange={handleTriageSourceChange}
                    >
                        <option value="all">All Triage Sources</option>
                        <option value="automated">Automated Triage Sources</option>
                        <option value="human">Human Triage Sources</option>
                    </select>
                </div>

                <button
                    onClick={handleClearFilters}
                    disabled={!hasActiveFilters}
                    className={`ml-4 px-4 py-2 rounded ${hasActiveFilters
                        ? 'bg-blue-600 text-white hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600'
                        : 'bg-gray-100 text-gray-400 cursor-not-allowed dark:bg-gray-700 dark:text-gray-500'
                        } transition-colors duration-200`}
                >
                    Clear Filters
                </button>
            </div>
        </div>
    );
};

export default FindingsFilters;
import { AlertTriangle, Bot, Filter, Search, ThumbsUp } from 'lucide-react';
import React, { useEffect, useMemo } from 'react';
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

    const [severityFilter, setSeverityFilter] = React.useState(() =>
        convertSeverityFromUrl(getFilterFromUrl('severity', 'all'))
    );

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

    // Helper function for severity conversion
    const convertSeverityToUrl = (severityValue) => {
        const severityMap = {
            '7': 'high',
            '4': 'medium',
            '0': 'low',
            'all': null
        };
        return severityMap[severityValue];
    };

    // Check if any filters are active
    const hasActiveFilters = useMemo(() => {
        return categoryFilter !== 'all' ||
            severityFilter !== 'all' ||
            originFilter !== '' ||
            triageFilter !== 'untriaged_and_actionable' ||
            triageSourceFilter !== 'all' ||
            objectIdFilter !== '';
    }, [categoryFilter, severityFilter, originFilter, triageFilter, triageSourceFilter, objectIdFilter]);

    // Handle clearing all filters
    const handleClearFilters = () => {
        setCategoryFilter('all');
        setSeverityFilter('all');
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

        const severityParam = convertSeverityToUrl(severityFilter);
        if (severityParam) {
            newParams.set('severity', severityParam);
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
            if (severityFilter !== 'all') {
                const severity = parseInt(severityFilter);
                if (severity === 7 && finding.severity < 7) return false;
                if (severity === 4 && (finding.severity >= 7 || finding.severity < 4)) return false;
                if (severity === 0 && finding.severity >= 4) return false;
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

    const handleSeverityChange = (e) => {
        setSeverityFilter(e.target.value);
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
                    <select
                        className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2"
                        value={severityFilter}
                        onChange={handleSeverityChange}
                    >
                        <option value="all">All Severities</option>
                        <option value="7">High (7-10)</option>
                        <option value="4">Medium (4-6)</option>
                        <option value="0">Low (0-3)</option>
                    </select>
                </div>

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
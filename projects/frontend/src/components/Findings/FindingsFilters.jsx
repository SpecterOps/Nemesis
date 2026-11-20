import { AlertTriangle, Bot, ChevronDown, Filter, Search, ThumbsUp } from 'lucide-react';
import React, { useEffect, useMemo, useRef } from 'react';
import { createPortal } from 'react-dom';
import { ALL_CATEGORIES, ALL_SEVERITIES, DEFAULT_TRIAGE_STATE } from './findingsQuery';

const CATEGORY_LABELS = {
    credential: 'Credentials',
    extracted_hash: 'Extracted Hashes',
    extracted_data: 'Extracted Data',
    vulnerability: 'Vulnerabilities',
    yara_match: 'Yara',
    pii: 'PII',
    misc: 'Misc',
    informational: 'Informational'
};

// Filter bar for the Findings list. Controlled: the filter values live in the URL (owned by
// FindingsList) and are applied server-side; this component only renders and reports changes.
const FindingsFilters = ({
    filters,
    onChange,
    totalCount
}) => {
    const { categories: categoryFilter, severities: severityFilter, triageState: triageFilter, triageSource: triageSourceFilter } = filters;

    const [severityDropdownOpen, setSeverityDropdownOpen] = React.useState(false);
    const severityDropdownRef = useRef(null);
    const severityButtonRef = useRef(null);
    const [severityDropdownPosition, setSeverityDropdownPosition] = React.useState({ top: 0, left: 0 });

    const [categoryDropdownOpen, setCategoryDropdownOpen] = React.useState(false);
    const categoryDropdownRef = useRef(null);
    const categoryButtonRef = useRef(null);
    const [categoryDropdownPosition, setCategoryDropdownPosition] = React.useState({ top: 0, left: 0 });

    // The search box updates the (server-side) filter after a short pause in typing
    const [searchFilter, setSearchFilter] = React.useState(filters.search);
    const searchTimer = useRef(null);
    useEffect(() => {
        setSearchFilter(filters.search);
    }, [filters.search]);
    useEffect(() => () => clearTimeout(searchTimer.current), []);

    // Check if any filters are active
    const hasActiveFilters = useMemo(() => {
        return categoryFilter.length !== ALL_CATEGORIES.length ||
            severityFilter.length !== ALL_SEVERITIES.length ||
            filters.search !== '' ||
            triageFilter !== DEFAULT_TRIAGE_STATE ||
            triageSourceFilter !== 'all' ||
            filters.objectId !== '';
    }, [categoryFilter, severityFilter, filters.search, triageFilter, triageSourceFilter, filters.objectId]);

    // Handle clearing all filters
    const handleClearFilters = () => {
        clearTimeout(searchTimer.current);
        setSearchFilter('');
        onChange({
            categories: ALL_CATEGORIES,
            severities: ALL_SEVERITIES,
            search: '',
            triageState: DEFAULT_TRIAGE_STATE,
            triageSource: 'all',
            objectId: '',
        });
    };

    // Filter change handlers

    const handleSeverityToggle = (severity) => {
        const prev = severityFilter;
        let next;
        if (prev.includes(severity)) {
            next = prev.filter(s => s !== severity);
            if (next.length === 0) next = ALL_SEVERITIES;
        } else {
            next = ALL_SEVERITIES.filter(s => s === severity || prev.includes(s));
        }
        onChange({ severities: next });
    };

    // Close dropdowns when clicking outside
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (severityDropdownRef.current && !severityDropdownRef.current.contains(event.target) && !severityButtonRef.current.contains(event.target)) {
                setSeverityDropdownOpen(false);
            }
            if (categoryDropdownRef.current && !categoryDropdownRef.current.contains(event.target) && !categoryButtonRef.current.contains(event.target)) {
                setCategoryDropdownOpen(false);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, []);

    const getSeverityButtonText = () => {
        if (severityFilter.length === ALL_SEVERITIES.length) return 'All Severities';
        if (severityFilter.length === 0) return 'No Severities';
        const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' };
        return severityFilter.map(s => labels[s]).join(', ');
    };

    const updateSeverityDropdownPosition = () => {
        if (severityButtonRef.current) {
            const rect = severityButtonRef.current.getBoundingClientRect();
            setSeverityDropdownPosition({
                top: rect.bottom + window.scrollY,
                left: rect.left + window.scrollX
            });
        }
    };

    const handleSeverityDropdownToggle = () => {
        if (!severityDropdownOpen) {
            updateSeverityDropdownPosition();
        }
        setSeverityDropdownOpen(!severityDropdownOpen);
    };

    const updateCategoryDropdownPosition = () => {
        if (categoryButtonRef.current) {
            const rect = categoryButtonRef.current.getBoundingClientRect();
            setCategoryDropdownPosition({
                top: rect.bottom + window.scrollY,
                left: rect.left + window.scrollX
            });
        }
    };

    const handleCategoryDropdownToggle = () => {
        if (!categoryDropdownOpen) {
            updateCategoryDropdownPosition();
        }
        setCategoryDropdownOpen(!categoryDropdownOpen);
    };

    const getCategoryButtonText = () => {
        if (categoryFilter.length === ALL_CATEGORIES.length) return 'All Categories';
        if (categoryFilter.length === 0) return 'No Categories';
        return categoryFilter.map(c => CATEGORY_LABELS[c]).join(', ');
    };

    const handleCategoryToggle = (category) => {
        const prev = categoryFilter;
        let next;
        if (prev.includes(category)) {
            next = prev.filter(c => c !== category);
            if (next.length === 0) next = ALL_CATEGORIES;
        } else {
            next = ALL_CATEGORIES.filter(c => c === category || prev.includes(c));
        }
        onChange({ categories: next });
    };

    const handleSearchChange = (e) => {
        const value = e.target.value;
        setSearchFilter(value);
        clearTimeout(searchTimer.current);
        searchTimer.current = setTimeout(() => onChange({ search: value }), 300);
    };

    const handleTriageStateChange = (e) => {
        onChange({ triageState: e.target.value });
    };

    const handleTriageSourceChange = (e) => {
        onChange({ triageSource: e.target.value });
    };

    return (
        <div className="p-2 border-b dark:border-gray-700 overflow-x-auto">
            <div className="flex items-center flex-wrap gap-4">
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
                    <button
                        ref={categoryButtonRef}
                        className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2 flex items-center space-x-2 hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors w-34"
                        onClick={handleCategoryDropdownToggle}
                    >
                        <span className="truncate flex-1 text-left">{getCategoryButtonText()}</span>
                        <ChevronDown className={`w-4 h-4 transition-transform flex-shrink-0 ${categoryDropdownOpen ? 'rotate-180' : ''}`} />
                    </button>
                </div>
                {categoryDropdownOpen && createPortal(
                    <div
                        ref={categoryDropdownRef}
                        className="fixed bg-white dark:bg-dark-secondary border dark:border-gray-700 rounded shadow-lg z-50 min-w-64"
                        style={{
                            top: `${categoryDropdownPosition.top}px`,
                            left: `${categoryDropdownPosition.left}px`
                        }}
                    >
                        <div className="p-2">
                            {[
                                { key: 'credential', label: 'Credentials' },
                                { key: 'extracted_hash', label: 'Extracted Hashes' },
                                { key: 'extracted_data', label: 'Extracted Data' },
                                { key: 'vulnerability', label: 'Vulnerabilities' },
                                { key: 'yara_match', label: 'Yara' },
                                { key: 'pii', label: 'PII' },
                                { key: 'misc', label: 'Misc' },
                                { key: 'informational', label: 'Informational' }
                            ].map(({ key, label }) => (
                                <label key={key} className="flex items-center space-x-2 p-1 hover:bg-gray-100 dark:hover:bg-gray-600 rounded cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={categoryFilter.includes(key)}
                                        onChange={() => handleCategoryToggle(key)}
                                        className="rounded"
                                    />
                                    <span className="font-medium dark:text-gray-300">{label}</span>
                                </label>
                            ))}
                        </div>
                    </div>,
                    document.body
                )}

                <div className="flex items-center space-x-2">
                    <AlertTriangle className="w-5 h-5 text-gray-500 dark:text-gray-400 flex-shrink-0" />
                    <button
                        ref={severityButtonRef}
                        className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2 flex items-center space-x-2 hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors w-34"
                        onClick={handleSeverityDropdownToggle}
                    >
                        <span className="truncate flex-1 text-left">{getSeverityButtonText()}</span>
                        <ChevronDown className={`w-4 h-4 transition-transform flex-shrink-0 ${severityDropdownOpen ? 'rotate-180' : ''}`} />
                    </button>
                </div>
                {severityDropdownOpen && createPortal(
                    <div
                        ref={severityDropdownRef}
                        className="fixed bg-white dark:bg-dark-secondary border dark:border-gray-700 rounded shadow-lg z-50 min-w-48"
                        style={{
                            top: `${severityDropdownPosition.top}px`,
                            left: `${severityDropdownPosition.left}px`
                        }}
                    >
                        <div className="p-2">
                            {[
                                { key: 'critical', label: 'Critical (9-10)', color: 'text-purple-600 dark:text-purple-400' },
                                { key: 'high', label: 'High (7-8)', color: 'text-red-600 dark:text-red-400' },
                                { key: 'medium', label: 'Medium (4-6)', color: 'text-orange-600 dark:text-orange-400' },
                                { key: 'low', label: 'Low (2-3)', color: 'text-yellow-600 dark:text-yellow-400' },
                                { key: 'informational', label: 'Informational (0-1)', color: 'text-gray-600 dark:text-gray-400' }
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
                        placeholder="Search name/category/origin/path"
                        className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2 w-64"
                        value={searchFilter}
                        onChange={handleSearchChange}
                    />
                </div>

                <div className="flex items-center space-x-2">
                    <Bot className="w-5 h-5 text-gray-500 dark:text-gray-400 flex-shrink-0" />
                    <select
                        className="border dark:border-gray-700 dark:bg-dark-secondary dark:text-gray-300 rounded p-2 w-44"
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
                    className={`px-2 py-2 rounded ${hasActiveFilters
                        ? 'bg-blue-600 text-white hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600'
                        : 'bg-gray-100 text-gray-400 cursor-not-allowed dark:bg-gray-700 dark:text-gray-500'
                        } transition-colors duration-200`}
                >
                    Clear Filters
                </button>

                <span className="text-sm text-gray-600 dark:text-gray-400 whitespace-nowrap">
                    {typeof totalCount === 'number'
                        ? `${totalCount.toLocaleString()} finding${totalCount !== 1 ? 's' : ''} found`
                        : 'Counting findings...'}
                </span>
            </div>
        </div>
    );
};

export default FindingsFilters;
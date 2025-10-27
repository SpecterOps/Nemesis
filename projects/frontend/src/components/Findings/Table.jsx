import Tooltip from '@/components/shared/Tooltip2';
import { Bot, ChevronDown, ChevronUp, HelpCircle, ThumbsDown, ThumbsUp } from 'lucide-react';
import React from 'react';
import { useFileNavigation } from './navigation';

// Sortable header component
const SortableHeader = ({ children, column, currentSort, currentDirection, onSort, className = "" }) => {
  const isActive = currentSort === column;
  const nextDirection = isActive && currentDirection === 'asc' ? 'desc' : 'asc';

  return (
    <div
      className={`flex items-center cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 px-2 py-2 ${className}`}
      onClick={() => onSort(column, nextDirection)}
    >
      <span className="text-sm font-medium text-gray-500 dark:text-gray-400">{children}</span>
      <div className="ml-1 flex flex-col">
        {isActive ? (
          currentDirection === 'asc' ? (
            <ChevronUp className="w-3 h-3 text-gray-600 dark:text-gray-300" />
          ) : (
            <ChevronDown className="w-3 h-3 text-gray-600 dark:text-gray-300" />
          )
        ) : (
          <div className="w-3 h-3" />
        )}
      </div>
    </div>
  );
};


export const TableHeaders = ({ isTriageMode, sortColumn, sortDirection, onSort }) => (
    <div className="min-w-full">
        <div className="flex bg-gray-50 dark:bg-gray-800 border-b dark:border-gray-700">
            {isTriageMode && (
                <div className="flex-shrink-0 w-8 text-sm font-medium text-gray-500 dark:text-gray-400 text-center" />
            )}
            <SortableHeader
                column="severity"
                currentSort={sortColumn}
                currentDirection={sortDirection}
                onSort={onSort}
                className="flex-shrink-0 w-16 justify-center"
            >
                Severity
            </SortableHeader>
            <SortableHeader
                column="created_at"
                currentSort={sortColumn}
                currentDirection={sortDirection}
                onSort={onSort}
                className="flex-shrink-0 w-40"
            >
                Timestamp
            </SortableHeader>
            <SortableHeader
                column="finding_name"
                currentSort={sortColumn}
                currentDirection={sortDirection}
                onSort={onSort}
                className="flex-shrink-0 w-48"
            >
                Name
            </SortableHeader>
            <SortableHeader
                column="category"
                currentSort={sortColumn}
                currentDirection={sortDirection}
                onSort={onSort}
                className="flex-shrink-0 w-40"
            >
                Category
            </SortableHeader>
            <SortableHeader
                column="origin_name"
                currentSort={sortColumn}
                currentDirection={sortDirection}
                onSort={onSort}
                className="flex-shrink-0 w-40"
            >
                Origin
            </SortableHeader>
            <SortableHeader
                column="file_path"
                currentSort={sortColumn}
                currentDirection={sortDirection}
                onSort={onSort}
                className="flex-shrink-0 w-96"
            >
                File Path
            </SortableHeader>
            <SortableHeader
                column="triage_value"
                currentSort={sortColumn}
                currentDirection={sortDirection}
                onSort={onSort}
                className="flex-shrink-0 w-[140px] justify-center"
            >
                Actions
            </SortableHeader>
        </div>
    </div>
);

export const TableRow = React.memo(({ index, style, data }) => {
    const {
        findings,
        isTriageMode,
        selectedIndex,
        selectedFindings,
        handleTriage,
        triageStates,
        setSelectedFinding,
        setIsModalOpen,
        setSelectedIndex
    } = data;

    const finding = findings[index];
    const navigateToFile = useFileNavigation();

    const renderSeverityBadge = (severity) => {
        let classes = 'px-2.5 py-0.5 rounded-full text-xs font-medium ';
        if (severity >= 9) {
            classes += 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-400';
        } else if (severity >= 7) {
            classes += 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
        } else if (severity >= 4) {
            classes += 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400';
        } else if (severity >= 2) {
            classes += 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
        } else {
            classes += 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400';
        }
        return <span className={classes}>{severity}</span>;
    };

    const handleFileNavigation = (e) => {
        e.stopPropagation();
        navigateToFile(finding);
    };

    return (
        <div
            style={style}
            className={`
        flex items-center border-b dark:border-gray-700 cursor-pointer transition-colors
        dark:bg-dark-secondary hover:bg-gray-100 dark:hover:bg-gray-700
        ${selectedFindings.has(finding.finding_id) ? '!bg-blue-100 dark:!bg-blue-900/30' : ''}
        ${isTriageMode && index === selectedIndex ? '!bg-blue-50 dark:!bg-blue-900/20' : ''}
      `}
            onClick={() => {
                setSelectedFinding(finding);
                setIsModalOpen(true);
                if (isTriageMode) {
                    setSelectedIndex(findings.findIndex(f => f.finding_id === finding.finding_id));
                }
            }}
        >
            {isTriageMode && (
                <div className="flex-shrink-0 w-8 text-sm font-medium text-gray-500 dark:text-gray-400 text-center">
                    {index === selectedIndex ? '✓' : ''}
                </div>
            )}
            <div className="flex-shrink-0 w-16 text-center">
                {renderSeverityBadge(finding.severity)}
            </div>
            <div className="flex-shrink-0 w-40 text-sm text-gray-500 dark:text-gray-400 text-left">
                {new Date(finding.created_at).toLocaleString()}
            </div>
            <div className="flex-shrink-0 w-48 text-sm text-gray-500 dark:text-gray-400 text-left">
                <Tooltip
                    content={finding.finding_name}
                    side="top"
                    sideOffset={10}
                    align="left"
                    alignOffset={-35}
                    avoidCollisions={true}
                    maxWidth="full"
                    onClick={(e) => e.stopPropagation()}
                >
                    <div className="overflow-hidden text-ellipsis whitespace-nowrap">
                        {finding.finding_name}
                    </div>
                </Tooltip>
            </div>
            <div className="flex-shrink-0 w-40 text-sm text-gray-500 dark:text-gray-400 text-left">
                <Tooltip
                    content={finding.category}
                    side="top"
                    sideOffset={10}
                    align="left"
                    alignOffset={-35}
                    avoidCollisions={true}
                    maxWidth="full"
                    onClick={(e) => e.stopPropagation()}
                >
                    <div className="overflow-hidden text-ellipsis whitespace-nowrap">
                        {finding.category}
                    </div>
                </Tooltip>
            </div>
            <div className="flex-shrink-0 w-40 text-sm text-gray-500 dark:text-gray-400 text-left">
                <Tooltip
                    content={finding.origin_name}
                    side="top"
                    sideOffset={10}
                    align="left"
                    alignOffset={-35}
                    avoidCollisions={true}
                    maxWidth="full"
                    onClick={(e) => e.stopPropagation()}
                >
                    <div className="overflow-hidden text-ellipsis whitespace-nowrap">
                        {finding.origin_name}
                    </div>
                </Tooltip>
            </div>
            <div className="flex-shrink-0 w-96 text-sm text-gray-500 dark:text-gray-400 text-left relative truncate">
                <Tooltip
                    content={finding.files_enriched?.path || 'Unknown path'}
                    side="top"
                    sideOffset={10}
                    align="left"
                    alignOffset={-35}
                    avoidCollisions={true}
                    maxWidth="full"
                    onClick={(e) => e.stopPropagation()}
                >
                    <button
                        className="text-blue-600 dark:text-blue-400 hover:underline text-left block max-w-full"
                        onClick={handleFileNavigation}
                    >
                        <div className="overflow-hidden text-ellipsis whitespace-nowrap">
                            {finding.files_enriched?.path || 'Unknown path'}
                        </div>
                    </button>
                </Tooltip>
            </div>
            <div className="flex-shrink-0 w-[140px] flex justify-center items-center space-x-2">
                <TriageActions
                    finding={finding}
                    handleTriage={handleTriage}
                    triageStates={triageStates}
                />
            </div>
        </div>
    );
});

const TriageActions = ({ finding, handleTriage, triageStates }) => (
    <div className="flex items-center justify-center w-full">
        <div className="grid grid-cols-4 gap-1">
            <Tooltip content="Mark as true positive" side="top">
                <button
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                    onClick={(e) => {
                        e.stopPropagation();
                        handleTriage(finding.finding_id, 'true_positive');
                    }}
                >
                    <ThumbsUp className={`w-4 h-4 ${triageStates[finding.finding_id] === 'true_positive'
                        ? 'text-green-500 dark:text-green-400'
                        : 'text-gray-300 dark:text-gray-600'
                        }`} />
                </button>
            </Tooltip>

            <Tooltip content="Mark as false positive" side="top">
                <button
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                    onClick={(e) => {
                        e.stopPropagation();
                        handleTriage(finding.finding_id, 'false_positive');
                    }}
                >
                    <ThumbsDown className={`w-4 h-4 ${triageStates[finding.finding_id] === 'false_positive'
                        ? 'text-red-500 dark:text-red-400'
                        : 'text-gray-300 dark:text-gray-600'
                        }`} />
                </button>
            </Tooltip>

            <Tooltip content="Mark as needs additional review" side="top">
                <button
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                    onClick={(e) => {
                        e.stopPropagation();
                        handleTriage(finding.finding_id, 'needs_review');
                    }}
                >
                    <HelpCircle className={`w-4 h-4 ${triageStates[finding.finding_id] === 'needs_review'
                        ? 'text-gray-500 dark:text-gray-400'
                        : 'text-gray-300 dark:text-gray-600'
                        }`} />
                </button>
            </Tooltip>

            <div className="flex items-center justify-center">
                {finding.finding_triage_histories.length > 0 &&
                    finding.finding_triage_histories[0].automated ? (
                    <Tooltip
                        content={
                            <>
                                {finding.finding_triage_histories[0].explanation || "No explanation provided"}
                                {finding.finding_triage_histories[0].confidence && finding.finding_triage_histories[0].confidence > 0 && (
                                    <span> (confidence: <strong>{finding.finding_triage_histories[0].confidence}</strong>)</span>
                                )}
                            </>
                        }
                        side="top"
                    >
                        <span>
                            <Bot className="w-4 h-4 text-blue-500 dark:text-blue-400" />
                        </span>
                    </Tooltip>
                ) : (
                    <div className="w-4 h-4"></div> /* Empty placeholder to maintain alignment */
                )}
            </div>
        </div>
    </div>
);

export default TableRow;
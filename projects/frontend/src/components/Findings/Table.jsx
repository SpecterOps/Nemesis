import { CheckCell, CheckHeaderCell, SortableHeader, listRowClassName } from '@/components/shared/ListTable';
import Tooltip from '@/components/shared/Tooltip2';
import { Bot, HelpCircle, ThumbsDown, ThumbsUp } from 'lucide-react';
import React from 'react';
import { useFileNavigation } from './navigation';

// Sortable header component

export const TableHeaders = ({ isTriageMode, sortColumn, sortDirection, onSort }) => (
    <div className="min-w-full">
        <div className="flex bg-gray-50 dark:bg-gray-800 border-b dark:border-gray-700">
            {isTriageMode && <CheckHeaderCell />}
            <SortableHeader
                column="severity"
                currentSort={sortColumn}
                currentDirection={sortDirection}
                onSort={onSort}
                className="flex-shrink-0 w-24 justify-center"
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

// One finding row. Props are per-row values and stable callbacks so React.memo skips rows whose
// selection/triage state didn't change (keyboard navigation re-renders only two rows).
/**
 * @param {{
 *   finding: any, index: number, height: number, isTriageMode: boolean, isSelected: boolean,
 *   isChecked: boolean, onRowClick: (finding: any, index: number, e?: React.MouseEvent) => void,
 *   onTriage: (...args: any[]) => any,
 * }} props
 */
const FindingRow = ({
    finding,
    index,
    height,
    isTriageMode,
    isSelected,
    isChecked,
    onRowClick,
    onTriage,
}) => {
    const navigateToFile = useFileNavigation();
    const latestTriage = finding.finding_triage_histories?.[0];

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
        // Keyboard access to rows is the page-level handler (t, arrows, ArrowRight opens), not per-row focus
        // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
        <div
            style={{ height }}
            data-row-index={index}
            data-finding-id={finding.finding_id}
            data-active={isTriageMode && isSelected ? 'true' : undefined}
            className={listRowClassName(isTriageMode, isChecked, isTriageMode && isSelected)}
            onClick={(e) => onRowClick(finding, index, e)}
        >
            {isTriageMode && <CheckCell checked={isChecked} />}
            <div className="flex-shrink-0 w-24 text-center">
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
                    align="start"
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
                    align="start"
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
                    align="start"
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
                    align="start"
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
                    latestTriage={latestTriage}
                    onTriage={onTriage}
                />
            </div>
        </div>
    );
};
export const TableRow = React.memo(FindingRow);

const TriageActions = ({ finding, latestTriage, onTriage }) => (
    <div className="flex items-center justify-center w-full">
        <div className="grid grid-cols-4 gap-1">
            <Tooltip content="Mark as true positive" side="top">
                <button
                    className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                    onClick={(e) => {
                        e.stopPropagation();
                        onTriage(finding.finding_id, 'true_positive');
                    }}
                >
                    <ThumbsUp className={`w-4 h-4 ${latestTriage?.value === 'true_positive'
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
                        onTriage(finding.finding_id, 'false_positive');
                    }}
                >
                    <ThumbsDown className={`w-4 h-4 ${latestTriage?.value === 'false_positive'
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
                        onTriage(finding.finding_id, 'needs_review');
                    }}
                >
                    <HelpCircle className={`w-4 h-4 ${latestTriage?.value === 'needs_review'
                        ? 'text-gray-500 dark:text-gray-400'
                        : 'text-gray-300 dark:text-gray-600'
                        }`} />
                </button>
            </Tooltip>

            <div className="flex items-center justify-center">
                {latestTriage?.automated ? (
                    <Tooltip
                        content={
                            <>
                                {latestTriage.explanation || "No explanation provided"}
                                {latestTriage.confidence && latestTriage.confidence > 0 && (
                                    <span> (confidence: <strong>{latestTriage.confidence}</strong>)</span>
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
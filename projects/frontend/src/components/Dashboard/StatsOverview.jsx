import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle,
  Clock,
  Eye,
  FileArchive,
  FileText,
  Layers,
  Search,
  Server,
  X
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  XAxis,
  YAxis
} from 'recharts';

// Custom tooltip component that can be reused
// Custom tooltip component with dynamic positioning
const CustomTooltip = ({ children, content }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [position, setPosition] = useState('right');
  const tooltipRef = useRef(null);
  const containerRef = useRef(null);

  const updatePosition = useCallback(() => {
    if (containerRef.current && tooltipRef.current) {
      const containerRect = containerRef.current.getBoundingClientRect();
      const viewportWidth = window.innerWidth;

      // Check if there's enough space on the right side
      const spaceOnRight = viewportWidth - containerRect.right;
      const tooltipWidth = 384; // max-w-md is 28rem (448px), but we use 384 for better fit

      if (spaceOnRight < tooltipWidth) {
        setPosition('left');
      } else {
        setPosition('right');
      }
    }
  }, []);

  const handleMouseEnter = useCallback(() => {
    setIsVisible(true);
    // Small delay to ensure the tooltip is rendered before positioning
    setTimeout(updatePosition, 0);
  }, [updatePosition]);

  const handleMouseLeave = useCallback(() => {
    setIsVisible(false);
  }, []);

  return (
    <div
      ref={containerRef}
      className="relative"
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      {children}
      {isVisible && (
        <div
          ref={tooltipRef}
          className={`absolute z-10 p-3 text-sm bg-gray-900 text-white rounded shadow-xl whitespace-normal -mt-2 border-2 border-blue-600 ${position === 'right'
            ? 'left-4'
            : 'right-4'
            }`}
          style={{ minWidth: '200px', maxWidth: '300px' }}
        >
          {content}
        </div>
      )}
    </div>
  );
};

// Enhanced stat card with icon and value
// Enhanced stat card with icon and value - modified for consistent number alignment
const StatCard = ({ title, value, icon: Icon, isLoading, onClick, tooltip }) => {
  const content = (
    <div
      className={`group relative bg-white dark:bg-dark-secondary p-4 rounded-lg shadow-md transition-colors h-full ${onClick ? 'cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800' : ''}`}
      onClick={onClick}
    >
      {/* Use flex column with justify-between to push content to top and bottom */}
      <div className="flex flex-col justify-between h-full">
        {/* Top content area */}
        <div>
          <div className="flex items-start justify-between mb-2">
            <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400 transition-colors">{title}</h3>
            {Icon && <Icon className="h-5 w-5 text-blue-500 dark:text-blue-400" />}
          </div>
        </div>

        {/* Bottom content area - always at the bottom */}
        <div className="mt-auto">
          {isLoading ? (
            <div className="animate-spin h-6 w-6 border-2 border-blue-500 dark:border-blue-400 rounded-full border-t-transparent transition-colors" />
          ) : (
            <p className="text-2xl font-bold text-blue-600 dark:text-blue-400 transition-colors">
              {typeof value === 'number' ? value.toLocaleString() : value}
            </p>
          )}
        </div>
      </div>

      {onClick && (
        <div className="absolute bottom-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
          <ArrowUpRight className="h-4 w-4 text-blue-500" />
        </div>
      )}
    </div>
  );

  return tooltip ? (
    <CustomTooltip content={tooltip}>
      {content}
    </CustomTooltip>
  ) : content;
};

// Section with title and optional action
const DashboardSection = ({ title, children, action }) => (
  <div className="bg-gray-50 dark:bg-gray-900 p-4 rounded-lg shadow border border-gray-200 dark:border-gray-800">
    <div className="flex justify-between items-center mb-4">
      <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200 transition-colors">{title}</h2>
      {action}
    </div>
    {children}
  </div>
);

const POLL_INTERVAL = 5000; // Poll every 5 seconds

const StatsOverview = () => {
  const [stats, setStats] = useState(null);
  const [enrichmentStats, setEnrichmentStats] = useState(null);
  const [failedWorkflows, setFailedWorkflows] = useState(null);
  const [filesOverTime, setFilesOverTime] = useState(null);
  const [findingsOverTime, setFindingsOverTime] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isEnrichmentLoading, setIsEnrichmentLoading] = useState(true);
  const [isFailedWorkflowsLoading, setIsFailedWorkflowsLoading] = useState(true);
  const [isTimeSeriesLoading, setIsTimeSeriesLoading] = useState(true);
  const [error, setError] = useState(null);
  const [enrichmentError, setEnrichmentError] = useState(null);
  const [failedWorkflowsError, setFailedWorkflowsError] = useState(null);
  const [timeSeriesError, setTimeSeriesError] = useState(null);
  const [queueStats, setQueueStats] = useState(null);
  const [isQueueLoading, setIsQueueLoading] = useState(true);
  const [queueError, setQueueError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);




  const fetchStats = useCallback(async () => {
    try {
      const query = {
        query: `
          query GetStats {
            files_enriched_aggregate {
              aggregate {
                count
              }
            }
            processed_files: files_enriched_aggregate(
              where: { originating_object_id: { _is_null: true } }
            ) {
              aggregate {
                count
              }
            }
            containers_processed: files_enriched_aggregate(
              where: { is_container: { _eq: true } }
            ) {
              aggregate {
                count
              }
            }
            unviewed_files: files_enriched_aggregate(
              where: {
                _and: [
                  {
                    _or: [
                      { originating_object_id: { _is_null: true } },
                      {
                        _and: [
                          { originating_object_id: { _is_null: false } },
                          { nesting_level: { _is_null: false } },
                          { nesting_level: { _gt: 0 } }
                        ]
                      }
                    ]
                  },
                  {
                    _not: {
                      files_view_histories: {}
                    }
                  }
                ]
              }
            ) {
              aggregate {
                count
              }
            }
            noseyparker_findings: findings_aggregate(
              where: { origin_name: { _eq: "noseyparker" } }
            ) {
              aggregate {
                count
              }
            }
            yara_findings: findings_aggregate(
              where: { origin_name: { _eq: "yara_scanner" } }
            ) {
              aggregate {
                count
              }
            }
            findings_aggregate {
              aggregate {
                count
              }
            }
            yara_rules_aggregate(
              where: { enabled: { _eq: true } }
            ) {
              aggregate {
                count
              }
            }
            untriaged_findings: findings_aggregate(
              where: {
                _not: {
                  finding_triage_histories: {}
                }
              }
            ) {
              aggregate {
                count
              }
            }
            latest_triage_entries: findings_triage_history(
              distinct_on: finding_id
              order_by: [{ finding_id: asc }, { timestamp: desc }]
            ) {
              finding_id
              value
            }
          }
        `,
        variables: {}
      };

      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(query)
      });

      if (!response.ok) {
        throw new Error(`Network response error: ${response.status}`);
      }

      const result = await response.json();

      if (result.errors) {
        throw new Error(result.errors[0].message);
      }

      const noseyParkerCount = result.data.noseyparker_findings.aggregate.count;
      const yaraCount = result.data.yara_findings.aggregate.count;

      // Process latest triage entries to get counts by value
      const latestTriageEntries = result.data.latest_triage_entries || [];
      const triageCounts = latestTriageEntries.reduce((acc, entry) => {
        acc[entry.value] = (acc[entry.value] || 0) + 1;
        return acc;
      }, {});

      setStats({
        totalFiles: result.data.files_enriched_aggregate.aggregate.count,
        processedFiles: result.data.processed_files.aggregate.count,
        containersProcessed: result.data.containers_processed.aggregate.count,
        unviewedFiles: result.data.unviewed_files.aggregate.count,
        totalFindings: result.data.findings_aggregate.aggregate.count,
        noseyParkerMatches: noseyParkerCount,
        yaraMatches: yaraCount,
        enabledYaraRules: result.data.yara_rules_aggregate.aggregate.count,
        untriagedFindings: result.data.untriaged_findings.aggregate.count,
        truePositiveFindings: triageCounts.true_positive || 0,
        falsePositiveFindings: triageCounts.false_positive || 0,
        needsReviewFindings: triageCounts.needs_review || 0
      });



      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      console.error('Error fetching stats:', err);
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const fetchEnrichmentStatus = useCallback(async () => {
    try {
      const response = await fetch('/api/workflows/status');

      if (!response.ok) {
        throw new Error(`Network response error: ${response.status}`);
      }

      const data = await response.json();
      setEnrichmentStats(data);
      setEnrichmentError(null);
    } catch (err) {
      console.error('Error fetching enrichment status:', err);
      setEnrichmentError(err.message);
    } finally {
      setIsEnrichmentLoading(false);
    }
  }, []);

  const fetchFailedWorkflows = useCallback(async () => {
    try {
      const response = await fetch('/api/workflows/failed');

      if (!response.ok) {
        throw new Error(`Network response error: ${response.status}`);
      }

      const data = await response.json();
      setFailedWorkflows(data);
      setFailedWorkflowsError(null);
    } catch (err) {
      console.error('Error fetching failed workflows:', err);
      setFailedWorkflowsError(err.message);
    } finally {
      setIsFailedWorkflowsLoading(false);
    }
  }, []);

  const fetchTimeSeriesData = useCallback(async () => {
    try {
      // First, get the timestamp of the first uploaded file
      const firstFileQuery = {
        query: `
          query GetFirstFile {
            files_enriched(
              where: { originating_object_id: { _is_null: true } }
              order_by: { created_at: asc }
              limit: 1
            ) {
              created_at
            }
          }
        `,
        variables: {}
      };

      const firstFileResponse = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(firstFileQuery)
      });

      if (!firstFileResponse.ok) {
        throw new Error(`Network response error: ${firstFileResponse.status}`);
      }

      const firstFileResult = await firstFileResponse.json();

      if (firstFileResult.errors) {
        throw new Error(firstFileResult.errors[0].message);
      }

      // Get current date and calculate start date
      const endDate = new Date();
      const startDate = new Date();

      // Default to 5 days ago
      startDate.setDate(startDate.getDate() - 5);

      // If we have a first file, use its date if it's more recent than 5 days ago
      if (firstFileResult.data.files_enriched && firstFileResult.data.files_enriched.length > 0) {
        const firstFileDate = new Date(firstFileResult.data.files_enriched[0].created_at);
        if (firstFileDate > startDate) {
          // Use the first file's date
          startDate.setTime(firstFileDate.getTime());
        }
      }

      // Calculate time difference in milliseconds
      const timeDiffMs = endDate - startDate;
      const timeDiffHours = timeDiffMs / (1000 * 60 * 60);

      // Determine granularity based on time range
      let granularity, intervalMs, minIntervals;

      if (timeDiffHours < 2) {
        // Less than 2 hours: use minutes (5-minute intervals)
        granularity = 'minute';
        intervalMs = 5 * 60 * 1000; // 5 minutes
        minIntervals = 6; // At least 30 minutes
      } else if (timeDiffHours < 48) {
        // Less than 2 days: use hours
        granularity = 'hour';
        intervalMs = 60 * 60 * 1000; // 1 hour
        minIntervals = 6; // At least 6 hours
      } else {
        // 2+ days: use days
        granularity = 'day';
        intervalMs = 24 * 60 * 60 * 1000; // 1 day
        minIntervals = 2; // At least 2 days
      }

      // Ensure minimum number of intervals for visualization
      const actualIntervals = Math.ceil(timeDiffMs / intervalMs);
      if (actualIntervals < minIntervals) {
        startDate.setTime(endDate.getTime() - (minIntervals * intervalMs));
      }

      // Round start date to interval boundary
      if (granularity === 'day') {
        startDate.setHours(0, 0, 0, 0);
      } else if (granularity === 'hour') {
        startDate.setMinutes(0, 0, 0);
      } else if (granularity === 'minute') {
        const minutes = startDate.getMinutes();
        startDate.setMinutes(Math.floor(minutes / 5) * 5, 0, 0);
      }

      // Format dates using local timezone to avoid timezone shift issues
      const formatLocalDate = (date) => {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
      };

      const startDateStr = formatLocalDate(startDate);
      const endDateStr = formatLocalDate(endDate);

      console.log('Time series date range:', { startDateStr, endDateStr, startDate, endDate, granularity });

      // Generate time intervals based on granularity
      const getIntervalsArray = () => {
        const intervals = [];
        const currentTime = new Date(startDate);
        const end = new Date(endDate);

        while (currentTime <= end) {
          intervals.push(new Date(currentTime));

          if (granularity === 'minute') {
            currentTime.setMinutes(currentTime.getMinutes() + 5);
          } else if (granularity === 'hour') {
            currentTime.setHours(currentTime.getHours() + 1);
          } else {
            currentTime.setDate(currentTime.getDate() + 1);
          }
        }

        return intervals;
      };

      const intervals = getIntervalsArray();

      // Create a batch query for all intervals
      let filesQueryParts = '';
      let findingsQueryParts = '';

      intervals.forEach((intervalStart, index) => {
        // Calculate end of this interval
        const intervalEnd = new Date(intervalStart);

        if (granularity === 'minute') {
          intervalEnd.setMinutes(intervalEnd.getMinutes() + 5);
        } else if (granularity === 'hour') {
          intervalEnd.setHours(intervalEnd.getHours() + 1);
        } else {
          intervalEnd.setDate(intervalEnd.getDate() + 1);
        }

        // Convert to ISO strings (which include timezone offset)
        const startTimestamp = intervalStart.toISOString();
        const endTimestamp = intervalEnd.toISOString();

        console.log(`Query for interval ${index}:`, { intervalStart, startTimestamp, endTimestamp });

        filesQueryParts += `
          files_day_${index}: files_enriched_aggregate(
            where: {
              created_at: { _gte: "${startTimestamp}", _lt: "${endTimestamp}" },
              originating_object_id: { _is_null: true }
            }
          ) {
            aggregate {
              count
            }
          }
        `;

        findingsQueryParts += `
          findings_day_${index}: findings_aggregate(
            where: {
              created_at: { _gte: "${startTimestamp}", _lt: "${endTimestamp}" }
            }
          ) {
            aggregate {
              count
            }
          }
        `;
      });

      const query = {
        query: `
          query GetTimeSeriesData {
            ${filesQueryParts}
            ${findingsQueryParts}
          }
        `,
        variables: {}
      };

      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(query)
      });

      if (!response.ok) {
        throw new Error(`Network response error: ${response.status}`);
      }

      const result = await response.json();

      if (result.errors) {
        throw new Error(result.errors[0].message);
      }

      console.log('Time series GraphQL result:', result);

      // Process the response data into time series format
      const filesData = [];
      const findingsData = [];
      let cumulativeFileCount = 0;
      let cumulativeFindingsCount = 0;

      intervals.forEach((intervalStart, index) => {
        // Format the label based on granularity
        let formattedLabel;
        if (granularity === 'minute') {
          formattedLabel = intervalStart.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
        } else if (granularity === 'hour') {
          formattedLabel = intervalStart.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
        } else {
          formattedLabel = intervalStart.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        }

        // Get file count for this interval and add to cumulative total
        const fileCount = result.data[`files_day_${index}`]?.aggregate?.count || 0;
        cumulativeFileCount += fileCount;
        filesData.push({
          date: formattedLabel,
          count: cumulativeFileCount
        });

        // Get findings count for this interval and add to cumulative total
        const findingsCount = result.data[`findings_day_${index}`]?.aggregate?.count || 0;
        cumulativeFindingsCount += findingsCount;
        findingsData.push({
          date: formattedLabel,
          count: cumulativeFindingsCount
        });
      });

      setFilesOverTime(filesData);
      setFindingsOverTime(findingsData);
      setTimeSeriesError(null);
    } catch (err) {
      console.error('Error fetching time series data:', err);
      setTimeSeriesError(err.message);
    } finally {
      setIsTimeSeriesLoading(false);
    }
  }, []);

  const fetchQueueStats = useCallback(async () => {
    try {
      const response = await fetch('/api/queues');

      if (!response.ok) {
        throw new Error(`Network response error: ${response.status}`);
      }

      const data = await response.json();
      setQueueStats(data);
      setQueueError(null);
    } catch (err) {
      console.error('Error fetching queue stats:', err);;
      setQueueError(err.message);
    } finally {
      setIsQueueLoading(false);
    }
  }, []);

  useEffect(() => {
    // Initial fetch for all data sources
    fetchStats();
    fetchEnrichmentStatus();
    fetchFailedWorkflows();
    fetchTimeSeriesData();
    fetchQueueStats();

    // Set up polling interval for all
    const statsIntervalId = setInterval(fetchStats, POLL_INTERVAL);
    const enrichmentIntervalId = setInterval(fetchEnrichmentStatus, POLL_INTERVAL);
    const failedWorkflowsIntervalId = setInterval(fetchFailedWorkflows, POLL_INTERVAL);
    const timeSeriesIntervalId = setInterval(fetchTimeSeriesData, POLL_INTERVAL);
    const queueStatsIntervalId = setInterval(fetchQueueStats, POLL_INTERVAL);

    // Cleanup intervals on component unmount
    return () => {
      clearInterval(statsIntervalId);
      clearInterval(enrichmentIntervalId);
      clearInterval(failedWorkflowsIntervalId);
      clearInterval(timeSeriesIntervalId);
      clearInterval(queueStatsIntervalId);
    };
  }, [fetchStats, fetchEnrichmentStatus, fetchFailedWorkflows, fetchTimeSeriesData, fetchQueueStats]);

  // Add visibility change handler to pause/resume polling when tab is hidden
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (!document.hidden) {
        // Immediately fetch when tab becomes visible again
        fetchStats();
        fetchEnrichmentStatus();
        fetchFailedWorkflows();
        fetchTimeSeriesData();
        fetchQueueStats();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [fetchStats, fetchEnrichmentStatus, fetchFailedWorkflows, fetchTimeSeriesData, fetchQueueStats]);



  // Processing time breakdown data
  const processingTimeData = enrichmentStats?.metrics?.processing_times && [
    { name: 'Average', value: enrichmentStats.metrics.processing_times.avg_seconds },
    { name: 'Median (P50)', value: enrichmentStats.metrics.processing_times.p50_seconds },
    { name: '90th Percentile', value: enrichmentStats.metrics.processing_times.p90_seconds },
    { name: 'Maximum', value: enrichmentStats.metrics.processing_times.max_seconds }
  ];

  if (error) {
    return (
      <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2 transition-colors">
        <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
        <div className="flex flex-col">
          <span className="text-red-600 dark:text-red-400">Error loading statistics: {error}</span>
          <span className="text-sm text-red-500 dark:text-red-400">Check browser console for details</span>
        </div>
      </div>
    );
  }

  // Function to handle navigation
  const handleNavigation = (path) => {
    window.location.href = path;
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-800 dark:text-white mt-2 ml-2">Nemesis Dashboard</h1>
        <div className="text-sm text-gray-500 dark:text-gray-400 flex items-center space-x-1">
          <Clock className="w-4 h-4" />
          <span>{lastUpdated ? `Last updated: ${lastUpdated.toLocaleTimeString()}` : 'Updating...'}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Files Overview Section */}
        <DashboardSection
          title="Files Overview"
          action={
            <button
              className="text-sm text-blue-500 hover:text-blue-700 flex items-center"
              onClick={() => handleNavigation('/files')}
            >
              View all <ArrowUpRight className="w-4 h-4 ml-1" />
            </button>
          }
        >
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <StatCard
              title="Total Submitted Files"
              value={stats?.processedFiles ?? 0}
              icon={FileText}
              isLoading={isLoading}
              onClick={() => handleNavigation('/files')}
              tooltip="Total files submitted from the queue for processing."
            />
            <StatCard
              title="Total Derived Files"
              value={stats ? (stats.totalFiles - stats.processedFiles) : 0}
              icon={Layers}
              isLoading={isLoading}
              tooltip="Files derived from processing submitted files."
            />
            <StatCard
              title="Unviewed Files"
              value={stats?.unviewedFiles ?? 0}
              icon={Eye}
              isLoading={isLoading}
              onClick={() => handleNavigation('/files?view_state=unviewed')}
              tooltip="Files that have not been viewed by anyone"
            />
            <StatCard
              title="Containers Processed"
              value={stats?.containersProcessed ?? 0}
              icon={FileArchive}
              isLoading={isLoading}
              tooltip="Archive files (.zip, .7z, etc.) processed"
            />
          </div>

          {!isTimeSeriesLoading && filesOverTime && filesOverTime.length > 0 && (
            <div className="mt-4">
              <p className="text-sm text-gray-500 mb-2">Files over time</p>
              <div className="h-24">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={filesOverTime}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
                    <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="#6B7280" />
                    <YAxis tick={{ fontSize: 10 }} stroke="#6B7280" />
                    <RechartsTooltip
                      formatter={(value) => [`${value} files`, 'Count']}
                      labelFormatter={(label) => `Date: ${label}`}
                    />
                    <Line type="monotone" dataKey="count" stroke="#3B82F6" strokeWidth={2} dot={{ r: 3 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}


        </DashboardSection>

        {/* Findings Overview Section */}
        <DashboardSection
          title="Findings Overview"
          action={
            <button
              className="text-sm text-blue-500 hover:text-blue-700 flex items-center"
              onClick={() => handleNavigation('/findings')}
            >
              View all <ArrowUpRight className="w-4 h-4 ml-1" />
            </button>
          }
        >
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <StatCard
              title="Total Findings"
              value={stats?.totalFindings ?? 0}
              icon={Search}
              isLoading={isLoading}
              onClick={() => handleNavigation('/findings')}
              tooltip="Total findings across all categories"
            />
            <StatCard
              title="NoseyParker Matches"
              value={stats?.noseyParkerMatches ?? 0}
              icon={Search}
              isLoading={isLoading}
              onClick={() => handleNavigation('/findings')}
              tooltip="Credentials and sensitive data found"
            />
            <StatCard
              title="Yara Matches"
              value={stats?.yaraMatches ?? 0}
              icon={Search}
              isLoading={isLoading}
              onClick={() => handleNavigation('/findings?category=yara_match')}
              tooltip="Files matching enabled Yara rules"
            />
            <StatCard
              title="Enabled Yara Rules"
              value={stats?.enabledYaraRules ?? 0}
              icon={Server}
              isLoading={isLoading}
              onClick={() => handleNavigation('/yara-rules')}
              tooltip="Currently enabled Yara rules"
            />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
            <StatCard
              title="Untriaged Findings"
              value={stats?.untriagedFindings ?? 0}
              icon={AlertTriangle}
              isLoading={isLoading}
              onClick={() => handleNavigation('/findings?triage_state=untriaged')}
              tooltip="Findings that have not been triaged yet"
            />
            <StatCard
              title="True Positives"
              value={stats?.truePositiveFindings ?? 0}
              icon={CheckCircle}
              isLoading={isLoading}
              onClick={() => handleNavigation('/findings?triage_state=true_positive')}
              tooltip="Findings marked as true positives"
            />
            <StatCard
              title="False Positives"
              value={stats?.falsePositiveFindings ?? 0}
              icon={X}
              isLoading={isLoading}
              onClick={() => handleNavigation('/findings?triage_state=false_positive')}
              tooltip="Findings marked as false positives"
            />
            <StatCard
              title="Needs Review"
              value={stats?.needsReviewFindings ?? 0}
              icon={Clock}
              isLoading={isLoading}
              onClick={() => handleNavigation('/findings?triage_state=needs_review')}
              tooltip="Findings that need further review"
            />
          </div>


        </DashboardSection>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Enrichment Overview Section */}
        <DashboardSection title="Enrichment Overview">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-4">
            <StatCard
              title="Active Workflows"
              value={enrichmentStats?.active_workflows ?? 0}
              icon={Activity}
              isLoading={isEnrichmentLoading}
              tooltip="File enrichment workflows currently running."
            />
            <StatCard
              title="Completed Workflows"
              value={enrichmentStats?.metrics?.completed_count ?? 0}
              icon={FileText}
              isLoading={isEnrichmentLoading}
              tooltip="Enrichment workflows successfully processed by all enrichment services."
            />
            <StatCard
              title="Failed Workflows"
              value={failedWorkflows?.failed_count ?? 0}
              icon={X}
              isLoading={isFailedWorkflowsLoading}
              tooltip="Workflows that failed, errored, or timed out"
            />
          </div>

          {/* Queued Files Breakdown */}
          <div className="mt-4">
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Enrichment Queues</h3>
            <div className="space-y-1">
              {isQueueLoading ? (
                <div className="flex justify-center py-4">
                  <div className="animate-spin h-6 w-6 border-2 border-blue-500 rounded-full border-t-transparent" />
                </div>
              ) : queueStats?.queue_details ? (() => {
                // Define the queues we want to display and their friendly names (in display order)
                const queueDisplayConfig = [
                  { topic: 'new_file', displayName: 'Files Queued for Processing' },
                  { topic: 'document_conversion_input', displayName: 'Document Conversion' },
                  { topic: 'noseyparker_input', displayName: 'NoseyParker' },
                  { topic: 'dotnet_input', displayName: 'Dotnet Analysis' },
                  { topic: 'bulk_enrichment_task', displayName: 'Bulk Enrichment Tasks' },
                ];

                // Filter and map the queue details in the specified order
                const filteredQueues = queueDisplayConfig
                  .filter(({ topic }) => queueStats.queue_details[topic])
                  .map(({ topic, displayName }) => ({
                    topic,
                    displayName,
                    metrics: queueStats.queue_details[topic]
                  }));

                if (filteredQueues.length === 0) {
                  return (
                    <div className="text-center py-4 text-gray-500 dark:text-gray-400 text-sm">
                      No queue data available
                    </div>
                  );
                }

                return filteredQueues.map(({ topic, displayName, metrics }) => (
                  <div key={topic} className="flex items-center justify-between px-3 py-1 bg-white dark:bg-gray-700 rounded shadow-sm">
                    <span className="text-base font-medium text-gray-700 dark:text-gray-300">{displayName}</span>
                    <span className="text-base font-bold text-blue-600 dark:text-blue-400">
                      {metrics.total_messages.toLocaleString()}
                    </span>
                  </div>
                ));
              })() : (
                <div className="text-center py-4 text-gray-500 dark:text-gray-400 text-sm">
                  No queue data available
                </div>
              )}
            </div>
          </div>

          {!isEnrichmentLoading && processingTimeData && (
            <div className="h-48 mt-4">
              <p className="text-sm text-gray-500 mb-2">Processing times (seconds)</p>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={processingTimeData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="#6B7280" />
                  <YAxis tick={{ fontSize: 10 }} stroke="#6B7280" />
                  <RechartsTooltip />
                  <Bar dataKey="value" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </DashboardSection>

        {/* Running Enrichment Workflows */}
        <DashboardSection title="Running Enrichment Workflows">
          {/* Remove the nested container div and put content directly in section */}
          <div className="space-y-1">
            {enrichmentStats?.active_details?.slice(0, 10).map((detail) => (
              <div key={detail.id} className="p-2 bg-white dark:bg-gray-700 rounded shadow-sm flex justify-between items-center">
                <div>
                  <div className="text-sm font-medium text-gray-800 dark:text-gray-200">
                    {detail.id.substring(0, 18)}
                    {detail.filename && <span className="ml-2 font-normal text-gray-600 dark:text-gray-400">({detail.filename} / {detail.object_id})</span>}
                  </div>
                </div>
                <div className="text-sm font-medium text-blue-500">
                  {detail.runtime_seconds ? detail.runtime_seconds.toFixed(2) : '0.00'}s
                </div>
              </div>
            ))}

            {/* Show count of additional workflows if there are more than 10 */}
            {enrichmentStats?.active_details?.length > 10 && (
              <div className="text-center py-2 text-gray-500 dark:text-gray-400 text-sm">
                +{enrichmentStats.active_details.length - 10} more running workflows
              </div>
            )}

            {/* Show a message when there are no current workflows activities */}
            {(!enrichmentStats?.active_details || enrichmentStats.active_details.length === 0) && (
              <div className="text-center py-10 text-gray-500 dark:text-gray-400">
                No current enrichment workflows running
              </div>
            )}
          </div>
        </DashboardSection>
      </div>

      {/* Failed Workflows Section */}
      <DashboardSection title="Failed Workflows">
        <div className="space-y-3">
          {failedWorkflows?.workflows?.slice(0, 5).map((workflow) => (
            <div key={workflow.id} className="p-3 bg-white dark:bg-gray-700 rounded shadow-sm flex justify-between items-center">
              <div className="flex-1">
                <div className="text-sm font-medium text-gray-800 dark:text-gray-200 flex items-center">
                  <AlertCircle className="h-4 w-4 text-red-500 mr-2" />
                  Workflow {workflow.id.substring(0, 8)}
                  {workflow.filename && <span className="ml-2 font-normal text-gray-600 dark:text-gray-400">({workflow.filename} / {workflow.object_id})</span>}
                </div>
                {workflow.error && (
                  <div className="text-xs text-red-500 dark:text-red-400 mt-1 line-clamp-2">
                    Error: {workflow.error}
                  </div>
                )}
              </div>
              <div className="text-right">
                <div className="text-sm font-medium text-red-500">
                  {workflow.runtime_seconds ? workflow.runtime_seconds.toFixed(2) : '0.00'}s
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400">
                  {new Date(workflow.timestamp).toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))}

          {/* Show count of additional failures if there are more than 5 */}
          {failedWorkflows?.workflows?.length > 5 && (
            <div className="text-center py-2 text-gray-500 dark:text-gray-400 text-sm">
              +{failedWorkflows.workflows.length - 5} more failed workflows
            </div>
          )}

          {/* Show a message when there are no failed workflows */}
          {(!failedWorkflows?.workflows || failedWorkflows.workflows.length === 0) && (
            <div className="text-center py-10 text-gray-500 dark:text-gray-400">
              No failed workflows
            </div>
          )}
        </div>
      </DashboardSection>

      {enrichmentError && (
        <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg flex items-center space-x-2 transition-colors">
          <AlertTriangle className="w-5 h-5 text-yellow-500 dark:text-yellow-400" />
          <div className="flex flex-col">
            <span className="text-yellow-600 dark:text-yellow-400">
              Warning: Enrichment metrics unavailable: {enrichmentError}
            </span>
          </div>
        </div>
      )}

      {failedWorkflowsError && (
        <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg flex items-center space-x-2 transition-colors mt-4">
          <AlertTriangle className="w-5 h-5 text-yellow-500 dark:text-yellow-400" />
          <div className="flex flex-col">
            <span className="text-yellow-600 dark:text-yellow-400">
              Warning: Failed workflows information unavailable: {failedWorkflowsError}
            </span>
          </div>
        </div>
      )}

      {timeSeriesError && (
        <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg flex items-center space-x-2 transition-colors mt-4">
          <AlertTriangle className="w-5 h-5 text-yellow-500 dark:text-yellow-400" />
          <div className="flex flex-col">
            <span className="text-yellow-600 dark:text-yellow-400">
              Warning: Time series data unavailable: {timeSeriesError}
            </span>
          </div>
        </div>
      )}

      {queueError && (
        <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg flex items-center space-x-2 transition-colors mt-4">
          <AlertTriangle className="w-5 h-5 text-yellow-500 dark:text-yellow-400" />
          <div className="flex flex-col">
            <span className="text-yellow-600 dark:text-yellow-400">
              Warning: Queue metrics unavailable: {queueError}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

export default StatsOverview;
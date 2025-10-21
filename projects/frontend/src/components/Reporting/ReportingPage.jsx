import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { BarChart2, FileText, Search, TrendingUp, AlertCircle, ArrowUpRight, Clock } from 'lucide-react';
import LoadingSpinner from '@/components/shared/LoadingSpinner';

const ReportingPage = () => {
  const [sources, setSources] = useState([]);
  const [systemStats, setSystemStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState('last_activity');
  const [sortDirection, setSortDirection] = useState('desc');
  const navigate = useNavigate();

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setError(null);

      // Fetch sources list and system stats in parallel
      const [sourcesRes, systemRes] = await Promise.all([
        fetch('/api/reports/sources'),
        fetch('/api/reports/system')
      ]);

      if (!sourcesRes.ok || !systemRes.ok) {
        throw new Error('Failed to fetch reporting data');
      }

      const sourcesData = await sourcesRes.json();
      const systemData = await systemRes.json();

      setSources(sourcesData);
      setSystemStats(systemData);
    } catch (err) {
      console.error('Error fetching reporting data:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const filteredSources = sources.filter(source =>
    source.source.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const sortedSources = [...filteredSources].sort((a, b) => {
    let aVal = a[sortField];
    let bVal = b[sortField];

    // Handle null values
    if (aVal === null) return 1;
    if (bVal === null) return -1;

    // Handle dates
    if (sortField === 'last_activity') {
      aVal = new Date(aVal);
      bVal = new Date(bVal);
    }

    if (sortDirection === 'asc') {
      return aVal > bVal ? 1 : -1;
    } else {
      return aVal < bVal ? 1 : -1;
    }
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <LoadingSpinner size="large" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2">
        <AlertCircle className="w-5 h-5 text-red-500 dark:text-red-400" />
        <span className="text-red-600 dark:text-red-400">Error loading reporting data: {error}</span>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-800 dark:text-white">Reporting & Risk Assessment</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Generate comprehensive reports and AI-powered risk assessments
          </p>
        </div>
        <button
          onClick={() => navigate('/reporting/system')}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center space-x-2 transition-colors"
        >
          <BarChart2 className="w-5 h-5" />
          <span>System-Wide Report</span>
          <ArrowUpRight className="w-4 h-4" />
        </button>
      </div>

      {/* System Overview Stats */}
      {systemStats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-dark-secondary p-4 rounded-lg shadow">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Sources</p>
                <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                  {systemStats.summary.total_sources.toLocaleString()}
                </p>
              </div>
              <TrendingUp className="w-8 h-8 text-blue-500 dark:text-blue-400" />
            </div>
          </div>

          <div className="bg-white dark:bg-dark-secondary p-4 rounded-lg shadow">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Files</p>
                <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                  {systemStats.summary.total_files.toLocaleString()}
                </p>
              </div>
              <FileText className="w-8 h-8 text-blue-500 dark:text-blue-400" />
            </div>
          </div>

          <div className="bg-white dark:bg-dark-secondary p-4 rounded-lg shadow">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Total Findings</p>
                <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                  {systemStats.summary.total_findings.toLocaleString()}
                </p>
              </div>
              <AlertCircle className="w-8 h-8 text-blue-500 dark:text-blue-400" />
            </div>
          </div>

          <div className="bg-white dark:bg-dark-secondary p-4 rounded-lg shadow">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Verified Findings</p>
                <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                  {systemStats.summary.verified_true_positives.toLocaleString()}
                </p>
              </div>
              <BarChart2 className="w-8 h-8 text-blue-500 dark:text-blue-400" />
            </div>
          </div>
        </div>
      )}

      {/* Sources Table */}
      <div className="bg-white dark:bg-dark-secondary rounded-lg shadow">
        <div className="p-4 border-b dark:border-gray-700">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-gray-800 dark:text-gray-200">Sources</h2>
            <div className="flex items-center space-x-2">
              <Search className="w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search sources..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="px-3 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-dark-primary text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-800 border-b dark:border-gray-700">
              <tr>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700"
                  onClick={() => handleSort('source')}
                >
                  Source {sortField === 'source' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700"
                  onClick={() => handleSort('file_count')}
                >
                  Files {sortField === 'file_count' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700"
                  onClick={() => handleSort('finding_count')}
                >
                  Findings {sortField === 'finding_count' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700"
                  onClick={() => handleSort('verified_findings')}
                >
                  Verified {sortField === 'verified_findings' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700"
                  onClick={() => handleSort('last_activity')}
                >
                  Last Activity {sortField === 'last_activity' && (sortDirection === 'asc' ? '↑' : '↓')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-gray-700">
              {sortedSources.map((source) => (
                <tr
                  key={source.source}
                  className="hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                >
                  <td className="px-4 py-3 text-sm font-medium text-gray-800 dark:text-gray-200">
                    {source.source}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                    {source.file_count.toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                    {source.finding_count.toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <span className={`font-medium ${source.verified_findings > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-600 dark:text-gray-400'}`}>
                      {source.verified_findings.toLocaleString()}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                    {source.last_activity ? (
                      <div className="flex items-center space-x-1">
                        <Clock className="w-4 h-4" />
                        <span>{new Date(source.last_activity).toLocaleString()}</span>
                      </div>
                    ) : (
                      'N/A'
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <button
                      onClick={() => navigate(`/reporting/source/${encodeURIComponent(source.source)}`)}
                      className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 flex items-center space-x-1"
                    >
                      <span>View Report</span>
                      <ArrowUpRight className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {sortedSources.length === 0 && (
            <div className="text-center py-12 text-gray-500 dark:text-gray-400">
              {searchTerm ? 'No sources match your search' : 'No sources available'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ReportingPage;

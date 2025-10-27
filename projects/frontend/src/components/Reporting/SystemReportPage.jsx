import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertCircle,
  ArrowLeft,
  Download,
  Sparkles,
  ArrowUpRight
} from 'lucide-react';
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer
} from 'recharts';
import LoadingSpinner from '@/components/shared/LoadingSpinner';
import MarkdownRenderer from '@/components/shared/MarkdownRenderer';

const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899'];

const DashboardSection = ({ title, children, action }) => (
  <div className="bg-gray-50 dark:bg-gray-900 p-4 rounded-lg shadow border border-gray-200 dark:border-gray-800">
    <div className="flex justify-between items-center mb-4">
      <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">{title}</h2>
      {action}
    </div>
    {children}
  </div>
);

const SystemReportPage = () => {
  const navigate = useNavigate();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [llmReport, setLlmReport] = useState(null);
  const [llmLoading, setLlmLoading] = useState(false);
  const [llmError, setLlmError] = useState(null);

  useEffect(() => {
    fetchReport();
  }, []);

  const fetchReport = async () => {
    try {
      setError(null);
      setLoading(true);

      const response = await fetch('/api/reports/system');

      if (!response.ok) {
        throw new Error(`Failed to fetch report: ${response.status}`);
      }

      const data = await response.json();
      setReport(data);
    } catch (err) {
      console.error('Error fetching report:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateAIReport = async () => {
    try {
      setLlmError(null);
      setLlmLoading(true);

      const response = await fetch('/api/reports/system/synthesize', {
        method: 'POST'
      });

      if (!response.ok) {
        throw new Error(`Failed to generate AI report: ${response.status}`);
      }

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'AI synthesis failed');
      }

      setLlmReport(data);
    } catch (err) {
      console.error('Error generating AI report:', err);
      setLlmError(err.message);
    } finally {
      setLlmLoading(false);
    }
  };

  const handleDownloadPDF = async () => {
    try {
      const response = await fetch('/api/reports/system/pdf');

      if (!response.ok) {
        throw new Error(`Failed to generate PDF: ${response.status}`);
      }

      // Get filename from Content-Disposition header or use default
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = 'nemesis_system_report.pdf';
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="([^"]+)"/i) || contentDisposition.match(/filename=([^;]+)/i);
        if (filenameMatch) {
          filename = filenameMatch[1].trim();
        }
      }

      // Download the PDF
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Error downloading PDF:', err);
      alert(`Failed to download PDF: ${err.message}`);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <LoadingSpinner size="large" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2">
          <AlertCircle className="w-5 h-5 text-red-500 dark:text-red-400" />
          <span className="text-red-600 dark:text-red-400">Error loading report: {error}</span>
        </div>
      </div>
    );
  }

  if (!report) {
    return null;
  }

  // Prepare chart data
  const findingsByCategoryData = Object.entries(report.findings_by_category || {}).map(([name, value]) => ({
    name,
    value
  }));

  const findingsBySeverityData = Object.entries(report.findings_by_severity || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value
  }));

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <button
            onClick={() => navigate('/reporting')}
            className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
          >
            <ArrowLeft className="w-5 h-5 text-gray-600 dark:text-gray-400" />
          </button>
          <div>
            <h1 className="text-3xl font-bold text-gray-800 dark:text-white">System-Wide Report</h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">Comprehensive analysis across all sources</p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={handleGenerateAIReport}
            disabled={llmLoading}
            className="px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 text-white rounded-lg flex items-center space-x-2 transition-colors"
          >
            {llmLoading ? (
              <>
                <LoadingSpinner size="small" />
                <span>Generating...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-5 h-5" />
                <span>Generate AI Risk Assessment</span>
              </>
            )}
          </button>
          <button
            onClick={handleDownloadPDF}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center space-x-2 transition-colors"
          >
            <Download className="w-5 h-5" />
            <span>Download PDF</span>
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-dark-secondary p-6 rounded-lg shadow">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Total Sources</h3>
          <p className="text-3xl font-bold text-blue-600 dark:text-blue-400">
            {report.summary.total_sources.toLocaleString()}
          </p>
        </div>
        <div className="bg-white dark:bg-dark-secondary p-6 rounded-lg shadow">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Total Files</h3>
          <p className="text-3xl font-bold text-blue-600 dark:text-blue-400">
            {report.summary.total_files.toLocaleString()}
          </p>
        </div>
        <div className="bg-white dark:bg-dark-secondary p-6 rounded-lg shadow">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Total Findings</h3>
          <p className="text-3xl font-bold text-blue-600 dark:text-blue-400">
            {report.summary.total_findings.toLocaleString()}
          </p>
        </div>
        <div className="bg-white dark:bg-dark-secondary p-6 rounded-lg shadow border-2 border-red-500">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Verified True Positives</h3>
          <p className="text-3xl font-bold text-red-600 dark:text-red-400">
            {report.summary.verified_true_positives.toLocaleString()}
          </p>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {findingsByCategoryData.length > 0 && (
          <DashboardSection title="Findings by Category">
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={findingsByCategoryData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {findingsByCategoryData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </DashboardSection>
        )}

        {findingsBySeverityData.length > 0 && (
          <DashboardSection title="Findings by Severity">
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={findingsBySeverityData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="name" tick={{ fontSize: 12 }} stroke="#6B7280" />
                  <YAxis tick={{ fontSize: 12 }} stroke="#6B7280" />
                  <RechartsTooltip />
                  <Bar dataKey="value" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </DashboardSection>
        )}
      </div>

      {/* Top Sources */}
      {report.sources && report.sources.length > 0 && (
        <DashboardSection title="Top Sources by Activity">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-100 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Source</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Files</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Findings</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Verified</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y dark:divide-gray-700">
                {report.sources.slice(0, 20).map((source) => (
                  <tr key={source.source} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                    <td className="px-4 py-2 text-sm font-medium text-gray-800 dark:text-gray-200">{source.source}</td>
                    <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400">{source.file_count.toLocaleString()}</td>
                    <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400">{source.finding_count.toLocaleString()}</td>
                    <td className="px-4 py-2 text-sm">
                      <span className={source.verified_findings > 0 ? 'font-medium text-red-600 dark:text-red-400' : 'text-gray-600 dark:text-gray-400'}>
                        {source.verified_findings.toLocaleString()}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-sm">
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
          </div>
        </DashboardSection>
      )}

      {/* AI Risk Assessment Section */}
      {llmError && (
        <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2">
          <AlertCircle className="w-5 h-5 text-red-500 dark:text-red-400" />
          <span className="text-red-600 dark:text-red-400">AI synthesis error: {llmError}</span>
        </div>
      )}

      {llmReport && (
        <DashboardSection
          title="AI-Generated System Risk Assessment"
          action={
            <div className="flex items-center space-x-2">
              <span className="text-xs text-gray-500 dark:text-gray-400">
                Tokens: {llmReport.token_usage?.toLocaleString()}
              </span>
              <span className={`px-2 py-1 rounded text-xs font-medium ${
                llmReport.risk_level === 'high' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400' :
                llmReport.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' :
                'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
              }`}>
                Risk: {llmReport.risk_level?.toUpperCase()}
              </span>
            </div>
          }
        >
          <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3 mb-4">
            <div className="flex items-start space-x-2">
              <AlertCircle className="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
              <div className="text-sm text-yellow-800 dark:text-yellow-200">
                <strong>Note:</strong> AI reports are regenerated each time (not cached). Token limit: 150k tokens.
              </div>
            </div>
          </div>

          <div className="prose dark:prose-invert max-w-none">
            <MarkdownRenderer content={llmReport.report_markdown} />
          </div>
        </DashboardSection>
      )}
    </div>
  );
};

export default SystemReportPage;

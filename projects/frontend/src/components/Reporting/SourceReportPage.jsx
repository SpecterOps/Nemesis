import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  AlertCircle,
  ArrowLeft,
  BarChart2,
  CheckCircle,
  Clock,
  Download,
  Eye,
  FileText,
  Layers,
  Search,
  Sparkles,
  X,
  AlertTriangle,
  FileArchive,
  Server
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
  ResponsiveContainer,
  Legend
} from 'recharts';
import LoadingSpinner from '@/components/shared/LoadingSpinner';
import MarkdownRenderer from '@/components/shared/MarkdownRenderer';

const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899'];

const StatCard = ({ title, value, icon: Icon, onClick, className = '' }) => {
  return (
    <div
      className={`bg-white dark:bg-dark-secondary p-4 rounded-lg shadow-md transition-colors ${onClick ? 'cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800' : ''} ${className}`}
      onClick={onClick}
    >
      <div className="flex flex-col justify-between h-full">
        <div className="flex items-start justify-between mb-2">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400">{title}</h3>
          {Icon && <Icon className="h-5 w-5 text-blue-500 dark:text-blue-400" />}
        </div>
        <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
          {typeof value === 'number' ? value.toLocaleString() : value}
        </p>
      </div>
    </div>
  );
};

const DashboardSection = ({ title, children, action }) => (
  <div className="bg-gray-50 dark:bg-gray-900 p-4 rounded-lg shadow border border-gray-200 dark:border-gray-800">
    <div className="flex justify-between items-center mb-4">
      <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">{title}</h2>
      {action}
    </div>
    {children}
  </div>
);

const SourceReportPage = () => {
  const { sourceName } = useParams();
  const navigate = useNavigate();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [llmReport, setLlmReport] = useState(null);
  const [llmLoading, setLlmLoading] = useState(false);
  const [llmError, setLlmError] = useState(null);

  useEffect(() => {
    fetchReport();
  }, [sourceName]);

  const fetchReport = async () => {
    try {
      setError(null);
      setLoading(true);

      const response = await fetch(`/api/reports/source?source=${encodeURIComponent(sourceName)}`);

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

      const response = await fetch(`/api/reports/source/synthesize?source=${encodeURIComponent(sourceName)}`, {
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
      // Prepare AI synthesis data if it exists
      const requestBody = llmReport ? {
        ai_synthesis: {
          risk_level: llmReport.risk_level,
          report_markdown: llmReport.report_markdown,
        }
      } : null;

      const response = await fetch(`/api/reports/source/pdf?source=${encodeURIComponent(sourceName)}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: requestBody ? JSON.stringify(requestBody) : JSON.stringify({}),
      });

      if (!response.ok) {
        throw new Error(`Failed to generate PDF: ${response.status}`);
      }

      // Get filename from Content-Disposition header or use default
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = `nemesis_source_report_${sourceName}.pdf`;
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
  const findingsByCategoryData = Object.entries(report.findings_detail.by_category || {}).map(([name, value]) => ({
    name,
    value
  }));

  const findingsBySeverityData = Object.entries(report.findings_detail.by_severity || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value
  }));

  const triageBreakdownData = Object.entries(report.findings_detail.triage_breakdown || {}).map(([name, value]) => ({
    name: name.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
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
            <h1 className="text-3xl font-bold text-gray-800 dark:text-white">Source Report</h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">{sourceName}</p>
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
      <DashboardSection title="Summary Statistics">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            title="Total Files"
            value={report.summary.total_files}
            icon={FileText}
          />
          <StatCard
            title="Unique Extensions"
            value={report.summary.unique_extensions}
            icon={Layers}
          />
          <StatCard
            title="Total Findings"
            value={report.summary.total_findings}
            icon={Search}
          />
          <StatCard
            title="Verified True Positives"
            value={report.summary.verified_true_positives}
            icon={CheckCircle}
            className={report.summary.verified_true_positives > 0 ? 'border-2 border-red-500' : ''}
          />
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
          <StatCard
            title="False Positives"
            value={report.summary.verified_false_positives}
            icon={X}
          />
          <StatCard
            title="Needs Review"
            value={report.summary.needs_review_findings}
            icon={Clock}
          />
          <StatCard
            title="Untriaged"
            value={report.summary.untriaged_findings}
            icon={AlertTriangle}
          />
          <StatCard
            title="Size (MB)"
            value={((report.summary.total_size_bytes || 0) / 1024 / 1024).toFixed(2)}
            icon={FileArchive}
          />
        </div>
      </DashboardSection>

      {/* Risk Indicators */}
      <DashboardSection title="Risk Indicators">
        <div className="space-y-4">
          <div>
            <h3 className="text-md font-semibold text-gray-700 dark:text-gray-300 mb-2">Credentials</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard
                title="Chromium Logins"
                value={report.risk_indicators.credentials.chromium_logins}
                icon={Server}
              />
              <StatCard
                title="Logins Decrypted"
                value={report.risk_indicators.credentials.chromium_logins_decrypted}
                icon={CheckCircle}
                className={report.risk_indicators.credentials.chromium_logins_decrypted > 0 ? 'border-2 border-orange-500' : ''}
              />
              <StatCard
                title="Chromium Cookies"
                value={report.risk_indicators.credentials.chromium_cookies}
                icon={Server}
              />
              <StatCard
                title="Cookies Decrypted"
                value={report.risk_indicators.credentials.chromium_cookies_decrypted}
                icon={CheckCircle}
                className={report.risk_indicators.credentials.chromium_cookies_decrypted > 0 ? 'border-2 border-orange-500' : ''}
              />
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
              <StatCard
                title="DPAPI Masterkeys"
                value={report.risk_indicators.credentials.dpapi_masterkeys}
                icon={Server}
              />
              <StatCard
                title="Masterkeys Decrypted"
                value={report.risk_indicators.credentials.dpapi_masterkeys_decrypted}
                icon={CheckCircle}
                className={report.risk_indicators.credentials.dpapi_masterkeys_decrypted > 0 ? 'border-2 border-orange-500' : ''}
              />
              <StatCard
                title="NoseyParker Findings"
                value={report.risk_indicators.credentials.noseyparker_findings}
                icon={Search}
                className={report.risk_indicators.credentials.noseyparker_findings > 0 ? 'border-2 border-red-500' : ''}
              />
              <StatCard
                title="YARA Matches"
                value={report.risk_indicators.sensitive_data.yara_matches}
                icon={FileText}
              />
            </div>
          </div>
        </div>
      </DashboardSection>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Findings by Category */}
        {findingsByCategoryData.length > 0 && (
          <DashboardSection title="Findings by Category">
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={findingsByCategoryData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                    outerRadius={80}
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

        {/* Findings by Severity */}
        {findingsBySeverityData.length > 0 && (
          <DashboardSection title="Findings by Severity">
            <div className="h-64">
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

      {/* Triage Breakdown */}
      {triageBreakdownData.length > 0 && (
        <DashboardSection title="Triage Status">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={triageBreakdownData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="name" tick={{ fontSize: 12 }} stroke="#6B7280" />
                <YAxis tick={{ fontSize: 12 }} stroke="#6B7280" />
                <RechartsTooltip />
                <Bar dataKey="value" fill="#10B981" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </DashboardSection>
      )}

      {/* Top Findings */}
      {report.top_findings && report.top_findings.length > 0 && (
        <DashboardSection title="Top Findings">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-100 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Finding</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Category</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Severity</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Triage</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">File Path</th>
                </tr>
              </thead>
              <tbody className="divide-y dark:divide-gray-700">
                {report.top_findings.slice(0, 10).map((finding) => (
                  <tr key={finding.finding_id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                    <td className="px-4 py-2 text-sm text-gray-800 dark:text-gray-200">{finding.finding_name}</td>
                    <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400">{finding.category}</td>
                    <td className="px-4 py-2 text-sm">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        finding.severity >= 3 ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400' :
                        finding.severity === 2 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' :
                        'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-400'
                      }`}>
                        {finding.severity >= 3 ? 'High' : finding.severity === 2 ? 'Medium' : 'Low'}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-sm">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        finding.triage_state === 'true_positive' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400' :
                        finding.triage_state === 'false_positive' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' :
                        finding.triage_state === 'needs_review' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' :
                        'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-400'
                      }`}>
                        {finding.triage_state || 'Untriaged'}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400 truncate max-w-md" title={finding.file_path}>
                      {finding.file_path}
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
          title="AI-Generated Risk Assessment"
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

export default SourceReportPage;

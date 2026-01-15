import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CheckCircle, XCircle, Clock, AlertCircle, SkipForward } from 'lucide-react';
import Tooltip from '@/components/shared/Tooltip';

const EnrichmentStatusSection = ({ objectId }) => {
  const [workflowData, setWorkflowData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchWorkflowData = async () => {
      try {
        const query = {
          query: `
            query GetWorkflowData($objectId: uuid!) {
              workflows(where: {object_id: {_eq: $objectId}}, order_by: {start_time: desc}) {
                wf_id
                workflow_type
                enrichments_success
                enrichments_failure
                enrichments_skipped
                status
                runtime_seconds
                start_time
              }
            }
          `,
          variables: { objectId }
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
          throw new Error('Network response was not ok');
        }

        const result = await response.json();
        if (result.errors) {
          throw new Error(result.errors[0].message);
        }

        setWorkflowData(result.data.workflows);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    if (objectId) {
      fetchWorkflowData();
    }
  }, [objectId]);

  // Format the enrichment name to be more readable
  const formatEnrichmentName = (name) => {
    return name
      .replace(/_/g, ' ')
      .split(' ')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  // Format workflow type for display
  const formatWorkflowType = (type) => {
    if (!type) return 'Unknown';
    return type
      .replace(/_/g, ' ')
      .split(' ')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  // Get workflow type badge color
  const getWorkflowTypeStyle = (type) => {
    switch (type) {
      case 'file_enrichment':
        return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200';
      case 'document_conversion':
        return 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200';
      default:
        return 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200';
    }
  };

  // Get status color based on workflow status
  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'text-green-600 dark:text-green-400';
      case 'failed':
        return 'text-red-600 dark:text-red-400';
      case 'running':
        return 'text-blue-600 dark:text-blue-400';
      default:
        return 'text-gray-600 dark:text-gray-400';
    }
  };

  // Get status icon based on workflow status
  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />;
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-600 dark:text-red-400" />;
      case 'running':
        return <Clock className="w-5 h-5 text-blue-600 dark:text-blue-400" />;
      default:
        return <AlertCircle className="w-5 h-5 text-gray-600 dark:text-gray-400" />;
    }
  };

  // Format runtime duration
  const formatRuntime = (seconds) => {
    if (!seconds && seconds !== 0) return 'N/A';

    if (seconds < 60) {
      return `${seconds.toFixed(1)}s`;
    } else {
      const minutes = Math.floor(seconds / 60);
      const remainingSeconds = (seconds % 60).toFixed(1);
      return `${minutes}m ${remainingSeconds}s`;
    }
  };

  // Format date
  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  // Truncate long error messages for display in badges
  const truncateErrorName = (errorMsg, maxLength = 20) => {
    if (!errorMsg) return '';
    if (errorMsg.length <= maxLength) return errorMsg;
    return `${errorMsg.substring(0, maxLength)}...`;
  };

  // Extract error details for tooltips with improved formatting
  const parseErrorMessage = (errorString) => {
    // Split the string at the first colon
    const parts = errorString.split(':', 2);
    const moduleName = parts[0].trim();
    const errorMessage = parts.length > 1 ? parts[1].trim() : '';

    return {
      moduleName,
      errorMessage
    };
  };

  if (loading) {
    return (
      <Card className="bg-white dark:bg-dark-secondary shadow-lg mb-1 transition-colors">
        <CardHeader className="border-b border-gray-200 dark:border-gray-700 py-4">
          <CardTitle className="text-gray-900 dark:text-gray-100">Enrichment Status</CardTitle>
        </CardHeader>
        <CardContent className="p-4">
          <div className="flex justify-center items-center h-12">
            <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600 dark:border-blue-400"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="bg-white dark:bg-dark-secondary shadow-lg mb-1 transition-colors">
        <CardHeader className="border-b border-gray-200 dark:border-gray-700 py-4">
          <CardTitle className="text-gray-900 dark:text-gray-100">Enrichment Status</CardTitle>
        </CardHeader>
        <CardContent className="p-4">
          <p className="text-red-600 dark:text-red-400">Error loading enrichment data: {error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!workflowData || workflowData.length === 0) {
    return (
      <Card className="bg-white dark:bg-dark-secondary shadow-lg mb-1 transition-colors">
        <CardHeader className="border-b border-gray-200 dark:border-gray-700 py-4">
          <CardTitle className="text-gray-900 dark:text-gray-100">Enrichment Status</CardTitle>
        </CardHeader>
        <CardContent className="p-4">
          <p className="text-gray-500 dark:text-gray-400">No enrichment data available for this file.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-white dark:bg-dark-secondary shadow-lg mb-1 transition-colors">
      <CardHeader className="border-b border-gray-200 dark:border-gray-700 py-4">
        <div className="flex justify-between items-center">
          <CardTitle className="text-gray-900 dark:text-gray-100">Enrichment Status</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-800">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Workflow Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Runtime</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Start Time</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Successful Enrichments</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Skipped Enrichments</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Failed Enrichments</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {workflowData.map((workflow) => (
                <tr key={workflow.wf_id} className="bg-white dark:bg-gray-900">
                  <td className="px-4 py-4 text-sm">
                    <div className="flex items-center">
                      {getStatusIcon(workflow.status)}
                      <span className={`ml-2 ${getStatusColor(workflow.status)}`}>
                        {workflow.status.charAt(0).toUpperCase() + workflow.status.slice(1)}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getWorkflowTypeStyle(workflow.workflow_type)}`}>
                      {formatWorkflowType(workflow.workflow_type)}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-900 dark:text-gray-100">{formatRuntime(workflow.runtime_seconds)}</td>
                  <td className="px-4 py-4 text-sm text-gray-900 dark:text-gray-100">{formatDate(workflow.start_time)}</td>
                  <td className="px-4 py-4">
                    <div className="flex flex-wrap gap-1">
                      {workflow.enrichments_success && workflow.enrichments_success.length > 0 ? (
                        workflow.enrichments_success.map((enrichment) => (
                          <Tooltip key={enrichment} content={enrichment}>
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200">
                              <CheckCircle className="w-3 h-3 mr-1" />
                              {formatEnrichmentName(enrichment)}
                            </span>
                          </Tooltip>
                        ))
                      ) : (
                        <span className="text-gray-500 dark:text-gray-400 text-sm">None</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex flex-wrap gap-1">
                      {workflow.enrichments_skipped && workflow.enrichments_skipped.length > 0 ? (
                        workflow.enrichments_skipped.map((enrichment) => (
                          <Tooltip key={enrichment} content={`Skipped: ${enrichment}`}>
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200">
                              <SkipForward className="w-3 h-3 mr-1" />
                              {formatEnrichmentName(enrichment)}
                            </span>
                          </Tooltip>
                        ))
                      ) : (
                        <span className="text-gray-500 dark:text-gray-400 text-sm">None</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex flex-wrap gap-1">
                      {workflow.enrichments_failure && workflow.enrichments_failure.length > 0 ? (
                        workflow.enrichments_failure.map((enrichment) => {
                          const { moduleName, errorMessage } = parseErrorMessage(enrichment);

                          return (
                            <Tooltip
                              key={enrichment}
                              content={
                                <div className="max-w-md break-words">
                                  <p className="font-semibold">Error:</p>
                                  <p>{errorMessage || moduleName}</p>
                                </div>
                              }
                              className="max-w-sm"
                            >
                              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200">
                                <XCircle className="w-3 h-3 mr-1" />
                                {formatEnrichmentName(moduleName)}
                              </span>
                            </Tooltip>
                          );
                        })
                      ) : (
                        <span className="text-gray-500 dark:text-gray-400 text-sm">None</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
};

export default EnrichmentStatusSection;
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import React, { useState, useEffect } from 'react';
import { useTheme } from '../ThemeProvider';
import LoadingSpinner from '../shared/LoadingSpinner';

const allServices = [
  {
    path: '/api/',
    link: '/api/',
    title: 'Nemesis API',
    description: 'The core API interface for Nemesis services',
    alwaysShow: true,  // Core service, always available
    subpages: [
      {
        path: '/api/docs',
        link: '/api/docs',
        title: 'Swagger UI',
        description: 'Interactive Swagger API documentation'
      },
      {
        path: '/api/redoc',
        link: '/api/redoc',
        title: 'ReDoc',
        description: 'Interactive ReDoc API documentation viewer'
      }
    ]
  },
  {
    path: '/grafana/',
    link: '/grafana/',
    title: 'Grafana Dashboard',
    description: 'Monitor and visualize Nemesis metrics and logs',
    credential: 'GRAFANA_ADMIN_USER:GRAFANA_ADMIN_PASSWORD',
    conditional: true,  // Part of monitoring profile
    subpages: [
      {
        path: '/grafana/explore/metrics',
        link: '/grafana/explore/metrics/trail?from=now-1h&to=now&timezone=browser',
        title: 'Metrics',
        description: 'Metrics being collected by Prometheus'
      },
      {
        path: '/grafana/a/grafana-lokiexplore-app/explore',
        link: '/grafana/a/grafana-lokiexplore-app/explore',
        title: 'Logs',
        description: 'View container logs collected by Loki'
      }
    ]
  },
  {
    path: '/hasura/console/',
    link: '/hasura/console/',
    title: 'Hasura Interface',
    description: 'Explore and query Nemesis data through the Hasura GraphQL interface',
    credential: 'HASURA_ADMIN_SECRET',
    alwaysShow: true  // Core service, always available
  },
  {
    path: '/jupyter/',
    link: '/jupyter/',
    title: 'Jupyter Notebooks',
    description: 'Jupyter notebooks for interacting with Nemesis data.',
    credential: 'JUPYTER_PASSWORD',
    conditional: true  // Part of jupyter profile
  },
  {
    path: '/jaeger/',
    link: '/jaeger/search?limit=200&lookback=24h&maxDuration&minDuration&operation=%2FTaskHubSidecarService%2FStartInstance&service=file-enrichment',
    title: 'Jaeger Tracing',
    description: 'Distributed tracing viewer for Dapr components and service interactions',
    conditional: true  // Part of monitoring profile
  },
  {
    path: '/prometheus/',
    link: '/prometheus/',
    title: 'Prometheus Dashboard',
    description: 'Raw Nemesis metrics and performance data',
    conditional: true  // Part of monitoring profile
  },
  {
    path: '/phoenix/',
    link: '/phoenix/',
    title: 'Arize Phoenix',
    description: 'LLM observability and tracing for AI agents',
    conditional: true  // Part of monitoring profile
  },
  {
    path: '/rabbitmq/',
    link: '/rabbitmq/#/queues',
    title: 'RabbitMQ Dashboard',
    description: 'Monitor and manage message queues and exchanges',
    credential: 'RABBITMQ_USER:RABBITMQ_PASSWORD',
    alwaysShow: true  // Core service, always available
  },
  {
    path: '/llm/',
    link: 'llm/sso/key/generate',
    title: 'LiteLLM',
    description: 'LiteLLM proxy interface',
    credential: 'admin:sk-LITELLM_ADMIN_PASSWORD',
    conditional: true  // Part of llm profile
  }
];

const HelpPage = () => {
  const { isDark, toggleTheme } = useTheme();
  const [services, setServices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchAvailableServices = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Fetch available services from the API
        const response = await fetch('/api/system/available-services');
        
        if (!response.ok) {
          throw new Error('Failed to fetch available services');
        }
        
        const data = await response.json();
        const availableServicePaths = data.services || [];
        
        // Filter services based on what's available
        const filteredServices = allServices.filter(service => {
          // Always show core services
          if (service.alwaysShow) {
            return true;
          }
          
          // For conditional services, check if they're in the available list
          if (service.conditional) {
            return availableServicePaths.includes(service.path.replace(/\/$/, ''));
          }
          
          return true;
        });
        
        setServices(filteredServices);
        
      } catch (err) {
        console.error('Error fetching available services:', err);
        setError(err.message);
        // On error, show all services to avoid breaking the UI
        setServices(allServices);
      } finally {
        setLoading(false);
      }
    };
    
    fetchAvailableServices();
  }, []);

  if (loading) {
    return (
      <div className="max-w-2xl mx-auto flex justify-center items-center min-h-[400px]">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto">
      <div className="grid gap-6">
        <Card className="bg-white dark:bg-dark-secondary">
          <CardHeader className="pt-2 pb-2">
            <CardTitle className="text-gray-900 dark:text-white">Available Services</CardTitle>
            <CardDescription className="text-gray-500 dark:text-gray-400 pb-0 mb-0">
              Access points for various Nemesis components and tools
              {error && (
                <span className="text-yellow-600 dark:text-yellow-400 text-xs block mt-1">
                  (Service detection unavailable - showing all services)
                </span>
              )}
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-1">
            {services.map((service) => (
              <div key={service.path}>
                <a
                  href={service.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block cursor-pointer"
                >
                  <div className="p-2 pt-1 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <h3 className="font-semibold text-gray-900 dark:text-white">
                          {service.title}
                        </h3>
                        <code className="px-2 py-1 bg-gray-100 dark:bg-gray-800 rounded text-sm text-gray-900 dark:text-gray-300">
                          {service.path}
                        </code>
                      </div>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {service.description}
                      </p>
                      {service.credential && (
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          <span className="font-medium">Credential: </span>
                          <code className="px-1 py-0.5 bg-gray-100 dark:bg-gray-800 rounded text-xs font-mono text-gray-900 dark:text-gray-300">
                            {service.credential}
                          </code>
                        </p>
                      )}
                      {service.subpages && (
                        <div className="mt-3 pl-4 border-l-2 border-gray-200 dark:border-gray-700">
                          {service.subpages.map((doc) => (
                            <a
                              key={doc.path}
                              href={doc.link}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="block mt-2 group"
                            >
                              <div className="flex items-center justify-between">
                                <div>
                                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 group-hover:text-gray-900 dark:group-hover:text-white">
                                    {doc.title}
                                  </h4>
                                  <p className="text-xs text-gray-500 dark:text-gray-400">
                                    {doc.description}
                                  </p>
                                </div>
                                <code className="px-2 py-1 bg-gray-100 dark:bg-gray-800 rounded text-sm text-gray-900 dark:text-gray-300">
                                  {doc.path}
                                </code>
                              </div>
                            </a>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </a>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-2 bg-white dark:bg-dark-secondary">
        <CardContent className="pt-6">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <h3 className="font-semibold text-gray-900 dark:text-white">Found an Issue?</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Help us improve Nemesis by reporting bugs and suggesting features
              </p>
            </div>
            <a
              href="https://github.com/SpecterOps/Nemesis/issues/new?template=Blank+issue"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center px-4 py-2 text-sm font-medium text-white bg-gray-900 hover:bg-gray-800 dark:bg-gray-100 dark:text-gray-900 dark:hover:bg-gray-200 rounded-md transition-colors"
            >
              Report an Issue
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default HelpPage;
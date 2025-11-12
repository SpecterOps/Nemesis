// src/App.jsx
import { createClient } from 'graphql-ws';
import {
  BarChart2,
  Bot,
  ChevronLeft,
  ChevronRight,
  FileArchive,
  FileSearch,
  FileText,
  FolderTree,
  Globe,
  HelpCircle,
  LayoutDashboard,
  Search,
  Settings,
  Siren,
  Upload
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { Route, BrowserRouter as Router, Routes, useLocation, useNavigate } from 'react-router-dom';

// Providers
import { TriageModeProvider } from '@/contexts/TriageModeContext';
import { UserProvider } from '@/contexts/UserContext';
import { ThemeProvider } from './components/ThemeProvider';

// Components
import Tooltip from '@/components/shared/Tooltip2';
import UserPromptOverlay from '@/components/User/UserPromptOverlay';
import ChatbotPage from './components/Chatbot/ChatbotPage';
import ChromiumDpapi from './components/ChromiumDpapi/ChromiumDpapi';
import Containers from './components/Containers/Containers';
import StatsOverview from './components/Dashboard/StatsOverview';
import FileBrowser from './components/FileBrowser/FileBrowser';
import FileList from './components/FileList/FileList';
import FileUpload from './components/FileUpload/FileUpload';
import FileViewer from './components/FileViewer/FileViewer';
import FindingsListContainer from './components/Findings/FindingsList';
import HelpPage from './components/Help/HelpPage';
import ReportingPage from './components/Reporting/ReportingPage';
import SourceReportPage from './components/Reporting/SourceReportPage';
import SystemReportPage from './components/Reporting/SystemReportPage';
import DocumentSearch from './components/Search/DocumentSearch';
import SettingsPage from './components/Settings/SettingsPage';
import ThemeToggle from './components/ThemeToggle';
import YaraRulesManager from './components/Yara/YaraManager';

// Assets
import logoDark from './img/nemesis_logo_dark.png';
import logoLight from './img/nemesis_logo_light.png';

const Sidebar = ({ onCollapse }) => {
  const [isCollapsed, setIsCollapsed] = useState(() => {
    const savedState = localStorage.getItem('sidebarCollapsed');
    return savedState ? JSON.parse(savedState) : false;
  });
  const [findingsCount, setFindingsCount] = useState(0);
  const [litellmAvailable, setLitellmAvailable] = useState(false);

  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    document.documentElement.style.setProperty('--navbar-width', `${isCollapsed ? 64 : 256}px`);
  }, [isCollapsed]);

  useEffect(() => {
    // Check LiteLLM availability
    const checkLitellmAvailability = async () => {
      try {
        const response = await fetch('/api/system/available-services');
        if (response.ok) {
          const data = await response.json();
          const availableServices = data.services || [];
          setLitellmAvailable(availableServices.includes('/llm'));
        }
      } catch (err) {
        console.error('Error checking LiteLLM availability:', err);
      }
    };

    checkLitellmAvailability();

    // Initial count fetch
    const fetchFindingsCount = async () => {
      const query = {
        query: `
          query GetCountOfFindingsWithNoTriageHistories {
            findings_aggregate(
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
          }
        `
      };

      try {
        const response = await fetch('/hasura/v1/graphql', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
          },
          body: JSON.stringify(query)
        });

        if (!response.ok) throw new Error('Network response error');
        const result = await response.json();
        if (result.errors) throw new Error(result.errors[0].message);

        setFindingsCount(result.data.findings_aggregate.aggregate.count);
      } catch (err) {
        console.error('Error fetching findings count:', err);
      }
    };

    fetchFindingsCount();

    // Set up subscription
    const wsClient = createClient({
      url: `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/hasura/v1/graphql`,
      connectionParams: {
        headers: {
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
      },
    });

    const subscription = wsClient.subscribe(
      {
        query: `
          subscription WatchCountOfFindingsWithNoTriageHistories {
            findings_aggregate(
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
          }
        `
      },
      {
        next(result) {
          if (result?.data?.findings_aggregate?.aggregate?.count !== undefined) {
            setFindingsCount(result.data.findings_aggregate.aggregate.count);
          }
        },
        error(error) {
          console.error('Subscription error:', error);
        },
        complete() {
          // console.log('Subscription completed');
        }
      }
    );

    return () => {
      if (subscription) {
        subscription();
      }
    };
  }, []);

  const toggleCollapse = () => {
    const newState = !isCollapsed;
    setIsCollapsed(newState);
    localStorage.setItem('sidebarCollapsed', JSON.stringify(newState));
    onCollapse?.(newState);
  };

  const baseNavigationItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, path: '/' },
    { id: 'upload', label: 'File Upload', icon: Upload, path: '/upload' },
    { id: 'files', label: 'Files', icon: FileText, path: '/files' },
    { id: 'findings', label: `Findings - ${findingsCount} Untriaged`, icon: Siren, path: '/findings', count: findingsCount },
    { id: 'search', label: 'Document Search', icon: Search, path: '/search' },
    { id: 'file-browser', label: 'File Browser', icon: FolderTree, path: '/file-browser' },
    { id: 'chromium-dpapi', label: 'Chrome/DPAPI', icon: Globe, path: '/chrome-dpapi' },
    { id: 'yara', label: 'Yara Rules', icon: FileSearch, path: '/yara-rules' },
    { id: 'containers', label: 'Containers', icon: FileArchive, path: '/containers' },
    { id: 'reporting', label: 'Reporting', icon: BarChart2, path: '/reporting' }
  ];

  // Add Chatbot tab if LiteLLM is available
  const navigationItems = litellmAvailable
    ? [
      ...baseNavigationItems,
      { id: 'chatbot', label: 'Chatbot', icon: Bot, path: '/chatbot' }
    ]
    : baseNavigationItems;

  const utilityItems = [
    { id: 'settings', label: 'Settings', icon: Settings, path: '/settings' },
    { id: 'help', label: 'Help', icon: HelpCircle, path: '/help' }
  ];

  const NavItem = ({ item }) => {
    const location = useLocation();
    const navigate = useNavigate();

    const isActive = location.pathname === item.path.split('?')[0];
    const isFindingsItem = item.id === 'findings';

    const baseClasses = `w-full flex ${isCollapsed ? 'justify-center' : ''} items-center px-3 py-3 text-left transition-colors group relative`;
    const activeClasses = isActive
      ? 'bg-blue-100 dark:bg-blue-600/30 text-blue-600 dark:text-blue-300'
      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600';

    const handleClick = (e) => {
      e.preventDefault();
      navigate(item.path);
    };

    const labelContent = isFindingsItem
      ? "Findings"
      : item.label;

    const tooltipContent = isFindingsItem
      ? `Findings - ${item.count} Untriaged`
      : item.label;

    const button = (
      <button
        onClick={handleClick}
        className={`${baseClasses} ${activeClasses}`}
        data-active={isActive}
      >
        <item.icon className="w-5 h-5 flex-shrink-0" />

        {!isCollapsed && (
          <div className="flex items-center flex-1 ml-3">
            <span className="text-sm font-medium min-w-0 truncate">{labelContent}</span>
            {item.count > 0 && (
              <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-full">
                {item.count >= 1000 ? '999+' : item.count}
              </span>
            )}
          </div>
        )}

        {isCollapsed && item.count > 0 && (
          <span className="absolute top-0.5 right-0.5 px-1.5 py-0.5 text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-full min-w-[1.25rem] text-center">
            {item.count >= 1000 ? '999+' : item.count}
          </span>
        )}
      </button>
    );

    // Show tooltip if sidebar is collapsed OR if it's the Findings item
    if (isCollapsed || isFindingsItem) {
      return (
        <div className="w-full flex justify-center">
          <Tooltip
            content={tooltipContent}
            side="right"
            align="start"
            sideOffset={12}
          >
            {button}
          </Tooltip>
        </div>
      );
    }

    // Return button without tooltip for other items when sidebar is expanded
    return button;
  };

  return (
    <div
      className={`${isCollapsed ? 'w-14' : 'w-48'} bg-white dark:bg-dark-secondary border-r dark:border-gray-700 h-full flex flex-col transition-all duration-300 ease-in-out z-[60] relative`}
    >
      {/* Logo Section */}
      <div className="p-4 border-b dark:border-gray-700 flex items-center justify-between">
        {!isCollapsed && (
          <div className="h-8 flex items-center flex-1">
            <img
              src={logoLight}
              alt="Nemesis Logo"
              className="h-full w-auto object-contain dark:hidden"
            />
            <img
              src={logoDark}
              alt="Nemesis Logo"
              className="h-full w-auto object-contain hidden dark:block"
            />
          </div>
        )}
        <button
          onClick={toggleCollapse}
          className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
          aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {isCollapsed ? (
            <ChevronRight className="w-5 h-5 text-gray-600 dark:text-gray-400" />
          ) : (
            <ChevronLeft className="w-5 h-5 text-gray-600 dark:text-gray-400" />
          )}
        </button>
      </div>

      {/* Main Navigation */}
      <nav className="flex-1 py-4">
        <div className="space-y-1">
          {navigationItems.map(item => (
            <NavItem key={item.id} item={item} />
          ))}
        </div>
      </nav>

      {/* Utility Navigation */}
      <div className="border-t dark:border-gray-700 py-4">
        <div className="space-y-1">
          {utilityItems.map(item => (
            <NavItem key={item.id} item={item} />
          ))}
          <div className="relative group">
            <ThemeToggle isCollapsed={isCollapsed} />
          </div>
        </div>
      </div>
    </div>
  );
};

const App = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    const savedState = localStorage.getItem('sidebarCollapsed');
    return savedState ? JSON.parse(savedState) : false;
  });

  return (
    <ThemeProvider>
      <UserProvider>
        <TriageModeProvider>
          <Router>
            <div className="min-h-screen bg-gray-100 dark:bg-dark-primary transition-colors">
              <UserPromptOverlay />
              <div className="flex">
                <div className={`fixed inset-y-0 transition-all duration-300 ease-in-out z-[60] ${sidebarCollapsed ? 'w-14' : 'w-48'
                  }`}>
                  <Sidebar onCollapse={setSidebarCollapsed} />
                </div>
                <div className={`flex-1 transition-all duration-300 ease-in-out ${sidebarCollapsed ? 'ml-14' : 'ml-48'
                  }`}>
                  <main className="p-2">
                    <Routes>
                      <Route path="/" element={<StatsOverview />} />
                      <Route path="/files" element={<FileList />} />
                      <Route path="/files/:objectId" element={<FileViewer />} />
                      <Route path="/file-browser" element={<FileBrowser />} />
                      <Route path="/upload" element={<FileUpload />} />
                      <Route path="/search" element={<DocumentSearch />} />
                      <Route path="/findings" element={<FindingsListContainer />} />
                      <Route path="/chrome-dpapi" element={<ChromiumDpapi />} />
                      <Route path="/yara-rules" element={<YaraRulesManager />} />
                      <Route path="/containers" element={<Containers />} />
                      <Route path="/chatbot" element={<ChatbotPage />} />
                      <Route path="/reporting" element={<ReportingPage />} />
                      <Route path="/reporting/source/:sourceName" element={<SourceReportPage />} />
                      <Route path="/reporting/system" element={<SystemReportPage />} />
                      <Route path="/settings" element={<SettingsPage />} />
                      <Route path="/help" element={<HelpPage />} />
                    </Routes>
                  </main>
                </div>
              </div>
            </div>
          </Router>
        </TriageModeProvider>
      </UserProvider>
    </ThemeProvider>
  );
};

export default App;
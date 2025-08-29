import { useTriageMode } from '@/contexts/TriageModeContext';
import { useUser } from '@/contexts/UserContext';
import { createClient } from 'graphql-ws';
import React, { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import AutoSizer from 'react-virtualized-auto-sizer';
import { FixedSizeList as List } from 'react-window';
import Alert from './Alert';
import FindingModal from './FindingModal';
import FindingsFilters from './FindingsFilters';
import { useFileNavigation } from './navigation';
import { TableHeaders, TableRow } from './Table';

// Create WebSocket client for GraphQL subscriptions
const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${wsProtocol}//${window.location.host}/hasura/v1/graphql`;

const wsClient = createClient({
  url: wsUrl,
  connectionParams: {
    headers: {
      'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
    },
  },
});

const ROW_HEIGHT = 42;

const FindingsList = () => {
  const [searchParams, setSearchParams] = useSearchParams();

  const [findings, setFindings] = useState([]);
  const [filteredFindings, setFilteredFindings] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const { isTriageMode, setIsTriageMode, selectedIndex, setSelectedIndex } = useTriageMode();
  const [triageStates, setTriageStates] = useState({});
  const [selectedFindings, setSelectedFindings] = useState(new Set());
  const { username } = useUser();
  const selectedRowRef = useRef(null);
  const lastDirection = useRef('down');
  const listRef = useRef();

  // Sorting state
  const [sortColumn, setSortColumn] = useState(() => searchParams.get('sort_column') || 'created_at');
  const [sortDirection, setSortDirection] = useState(() => searchParams.get('sort_direction') || 'desc');

  // Handle column sorting
  const handleSort = (column, direction) => {
    setSortColumn(column);
    setSortDirection(direction);
  };

  // Update URL parameters when sort changes
  useEffect(() => {
    const newParams = new URLSearchParams(searchParams);
    newParams.set('sort_column', sortColumn);
    newParams.set('sort_direction', sortDirection);
    
    if (newParams.toString() !== searchParams.toString()) {
      setSearchParams(newParams, { replace: true });
    }
  }, [sortColumn, sortDirection, searchParams, setSearchParams]);

  // Update sort state when URL parameters change
  useEffect(() => {
    const urlSortColumn = searchParams.get('sort_column');
    const urlSortDirection = searchParams.get('sort_direction');
    
    if (urlSortColumn && urlSortColumn !== sortColumn) {
      setSortColumn(urlSortColumn);
    }
    if (urlSortDirection && urlSortDirection !== sortDirection) {
      setSortDirection(urlSortDirection);
    }
  }, [searchParams]);

  // Function to handle multi-selection triage
  const handleBulkTriage = (value) => {
    selectedFindings.forEach(findingId => {
      handleTriage(findingId, value);
    });
    setSelectedFindings(new Set());
  };

  const handleTriage = async (findingId, value) => {
    // Update local state immediately for UI responsiveness
    setTriageStates(prev => ({
      ...prev,
      [findingId]: value
    }));

    const mutation = {
      query: `
        mutation InsertTriage($finding_id: bigint!, $username: String!, $value: String!) {
          insert_findings_triage_history_one(object: {
            finding_id: $finding_id,
            username: $username,
            value: $value,
            automated: false
          }) {
            id
            timestamp
          }
        }
      `,
      variables: {
        finding_id: findingId,
        username: username,
        value: value
      }
    };

    try {
      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(mutation)
      });

      if (!response.ok) throw new Error('Network error');

      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);

      console.log('Finding triage recorded successfully');
    } catch (err) {
      console.error('Failed to record finding triage:', err);
      // Revert the local state if the server update failed
      setTriageStates(prev => {
        const newState = { ...prev };
        delete newState[findingId];
        return newState;
      });
    }
  };

  useEffect(() => {
    if (listRef.current && isTriageMode && selectedIndex >= 0) {
      listRef.current.scrollToItem(selectedIndex, 'center');
    }
  }, [selectedIndex, isTriageMode]);

  // Handle initial selected finding and modal state from URL/navigation
  useEffect(() => {
    if (isLoading) return;

    const selected = searchParams.get('selected');
    const modalOpen = searchParams.get('modal');

    if (selected && filteredFindings.length > 0 && selectedIndex === -1) {
      const findingIndex = filteredFindings.findIndex(f => f.finding_id === parseInt(selected));
      if (findingIndex >= 0) {
        setSelectedIndex(findingIndex);
        setSelectedFinding(filteredFindings[findingIndex]);
        setIsTriageMode(true);
        selectedRowRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }

      if (modalOpen) {
        setIsModalOpen(true);
      }
    }
  }, [filteredFindings, searchParams, selectedIndex, isLoading]);

  // Initial data fetch
  useEffect(() => {
    const fetchFindings = async () => {
      const query = {
        query: `
          query GetFindings {
            findings(order_by: {created_at: desc}) {
              finding_name
              finding_id
              object_id
              origin_type
              origin_name
              category
              severity
              data
              created_at
              files_enriched {
                path
                agent_id
                magic_type
              }
              finding_triage_histories(order_by: {timestamp: desc}, limit: 1) {
                id
                automated
                username
                value
                explanation
                confidence
                true_positive_context
                timestamp
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

        if (!response.ok) {
          throw new Error(`Network response error: ${response.status}`);
        }

        const result = await response.json();
        if (result.errors) {
          throw new Error(result.errors[0].message);
        }

        // Initialize triageStates from the fetched data
        const initialTriageStates = {};
        result.data.findings.forEach(finding => {
          if (finding.finding_triage_histories && finding.finding_triage_histories.length > 0) {
            initialTriageStates[finding.finding_id] = finding.finding_triage_histories[0].value;
          }
        });

        setTriageStates(initialTriageStates);
        setFindings(result.data.findings);
      } catch (err) {
        console.error('Error fetching findings:', err);
        setError(err.message);
      } finally {
        setIsLoading(false);
      }
    };

    fetchFindings();
  }, []);

  // Set up subscription for real-time updates
  useEffect(() => {
    const subscription = {
      query: `
        subscription WatchFindings {
          findings(order_by: {created_at: desc}) {
            finding_name
            finding_id
            object_id
            origin_type
            origin_name
            category
            severity
            data
            created_at
            files_enriched {
              path
              agent_id
              magic_type
            }
            finding_triage_histories(order_by: {timestamp: desc}, limit: 1) {
              id
              automated
              username
              value
              explanation
              confidence
              true_positive_context
              timestamp
            }
          }
        }
      `
    };

    let unsubscribe;

    (async () => {
      unsubscribe = wsClient.subscribe(
        subscription,
        {
          next: ({ data }) => {
            if (data?.findings) {
              // Update triage states when new data comes in
              const newTriageStates = {};
              data.findings.forEach(finding => {
                if (finding.finding_triage_histories && finding.finding_triage_histories.length > 0) {
                  newTriageStates[finding.finding_id] = finding.finding_triage_histories[0].value;
                }
              });
              setTriageStates(newTriageStates);
              setFindings(data.findings);
            }
          },
          error: (err) => {
            console.error('Subscription error:', err);
            setError('Error in real-time updates. Please refresh the page.');
          },
          complete: () => {
            // console.log('Subscription completed');
          },
        },
      );
    })();

    return () => {
      if (unsubscribe) {
        unsubscribe();
      }
    };
  }, []);

  const navigateToFile = useFileNavigation();

  // If the modal is open, change its contents when up/down are used.
  useEffect(() => {
    if (isModalOpen && isTriageMode && selectedIndex >= 0 && filteredFindings[selectedIndex]) {
      setSelectedFinding(filteredFindings[selectedIndex]);
      setIsModalOpen(true);
    }
  }, [selectedIndex, filteredFindings, isTriageMode, isModalOpen]);

  // Update URL when selection or modal state changes
  useEffect(() => {
    if (isLoading) return;

    const newParams = new URLSearchParams(searchParams);

    // Handle selected parameter
    if (selectedIndex >= 0 && filteredFindings[selectedIndex]) {
      newParams.set('selected', filteredFindings[selectedIndex].finding_id);
    } else {
      newParams.delete('selected');
    }

    // Handle modal parameter
    if (isModalOpen) {
      newParams.set('modal', 'true');
    } else {
      newParams.delete('modal');
    }

    // Only update if the parameters have actually changed
    if (newParams.toString() !== searchParams.toString()) {
      setSearchParams(newParams, { replace: false });
    }

  }, [searchParams, selectedIndex, filteredFindings, isLoading, isModalOpen]);

  // Keyboard navigation logic
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Ignore keyboard shortcuts when focus is on an input or textarea element
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) {
        return;
      }

      // Handle global keyboard actions on the Findings page
      switch (e.key) {
        case 'ArrowLeft':
        case 'Escape':
          e.preventDefault();
          if (isModalOpen) {
            setIsModalOpen(false);
          }
          break;
        case 't':
          e.preventDefault();
          setIsTriageMode(value => {
            const isTriageMode = !value;
            if (isTriageMode && selectedIndex === -1) {
              setSelectedIndex(0);
            }
            return isTriageMode;
          });
          return;
      }

      // Handle keyboard shortcuts when in triage mode
      if (!isTriageMode) return;

      // Select all with Ctrl/Cmd + A
      if (!isModalOpen && (e.ctrlKey || e.metaKey) && e.key === 'a') {
        e.preventDefault();
        const newSelection = new Set(filteredFindings.map(f => f.finding_id));
        setSelectedFindings(newSelection);
        return;
      }

      const filteredFindingsLength = filteredFindings.length;

      switch (e.key) {
        case 'Escape':
          e.preventDefault();
          setSelectedFindings(new Set());
          break;

        case 'ArrowUp':
          e.preventDefault();
          lastDirection.current = 'up';
          setSelectedIndex(prev => Math.max(0, prev - 1));
          break;

        case 'ArrowDown':
          e.preventDefault();
          lastDirection.current = 'down';
          setSelectedIndex(prev => Math.min(filteredFindingsLength - 1, prev + 1));
          break;

        case 'ArrowRight':
          e.preventDefault();
          if (selectedIndex >= 0 && selectedIndex < filteredFindingsLength) {
            if (isModalOpen) {
              setIsModalOpen(true);
              navigateToFile(filteredFindings[selectedIndex]);
            } else {
              setSelectedFinding(filteredFindings[selectedIndex]);
              setIsModalOpen(true);
            }
          }
          break;

        case '1':
          e.preventDefault();
          if (selectedIndex >= 0 && selectedIndex < filteredFindingsLength) {
            handleTriage(filteredFindings[selectedIndex].finding_id, 'true_positive');
          }
          break;
        case '2':
          e.preventDefault();
          if (selectedIndex >= 0 && selectedIndex < filteredFindingsLength) {
            handleTriage(filteredFindings[selectedIndex].finding_id, 'false_positive');
          }
          break;
        case '3':
          e.preventDefault();
          if (selectedIndex >= 0 && selectedIndex < filteredFindingsLength) {
            handleTriage(filteredFindings[selectedIndex].finding_id, 'needs_review');
          }
          break;

        case ' ':
          e.preventDefault();
          if (selectedIndex >= 0 && selectedIndex < filteredFindingsLength) {
            const newSelection = new Set(selectedFindings);
            const findingId = filteredFindings[selectedIndex].finding_id;
            if (newSelection.has(findingId)) {
              newSelection.delete(findingId);
            } else {
              newSelection.add(findingId);
            }
            setSelectedFindings(newSelection);
          }
          break;
      }


      // Handle Shift + Arrow navigation to select multiple findings
      if (e.shiftKey && isTriageMode && selectedIndex >= 0) {
        switch (e.key) {
          case 'ArrowDown':
            e.preventDefault();
            const nextIndex = Math.min(filteredFindings.length - 1, selectedIndex + 1);
            const newSelection = new Set(selectedFindings);
            newSelection.add(filteredFindings[selectedIndex].finding_id);
            newSelection.add(filteredFindings[nextIndex].finding_id);
            setSelectedFindings(newSelection);
            setSelectedIndex(nextIndex);
            break;
          case 'ArrowUp':
            e.preventDefault();
            const prevIndex = Math.max(0, selectedIndex - 1);
            const newSelectionUp = new Set(selectedFindings);
            newSelectionUp.add(filteredFindings[selectedIndex].finding_id);
            newSelectionUp.add(filteredFindings[prevIndex].finding_id);
            setSelectedFindings(newSelectionUp);
            setSelectedIndex(prevIndex);
            break;
        }
      }

      // Bulk triage shortcuts
      if (selectedFindings.size > 0 && isTriageMode) {
        switch (e.key) {
          case '1':
            e.preventDefault();
            handleBulkTriage('true_positive');
            break;
          case '2':
            e.preventDefault();
            handleBulkTriage('false_positive');
            break;
          case '3':
            e.preventDefault();
            handleBulkTriage('needs_review');
            break;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isTriageMode, selectedIndex, filteredFindings, isModalOpen, selectedFindings]);

  if (error) {
    return <Alert title="Error" variant="error">Failed to load findings: {error}</Alert>;
  }


  return (
    <div className="bg-white dark:bg-dark-secondary rounded-lg shadow flex flex-col">
      {/* Triage mode indicator */}
      {isTriageMode ? (
        <div className="p-1 bg-blue-50 dark:bg-blue-900/20 border-b dark:border-gray-700">
          <p className="text-sm text-blue-600 dark:text-blue-400">
            Triage Mode Active: ↑↓ to navigate, → to view details. Select multiple with Shift + ↑↓, hitting space, or Ctrl+A. Clear selection with ESC. Triage selected results with 1, 2, or 3 keys.
          </p>
        </div>
      ) : (
        <div className="p-1 bg-blue-50 dark:bg-blue-900/20 border-b dark:border-gray-700">
          <p className="text-sm text-blue-600 dark:text-blue-400">
            Press 't' to enter triage mode
          </p>
        </div>
      )}

      {/* Filters section */}
      <FindingsFilters
        findings={findings}
        onFilteredDataChange={setFilteredFindings}
        sortColumn={sortColumn}
        sortDirection={sortDirection}
      />

      {/* Findings Table */}
      <div className="overflow-x-auto">
        {/* Headers - Keep these outside the virtualized area */}
        <TableHeaders 
          isTriageMode={isTriageMode} 
          sortColumn={sortColumn}
          sortDirection={sortDirection}
          onSort={handleSort}
        />

        {/* Virtualized List or No Findings Message */}
        {isLoading ? (
          <div className="flex justify-center py-4">
            <div className="animate-spin rounded-full h-10 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
          </div>
        ) : findings.length === 0 ? (
          <NoFindings />
        ) : filteredFindings.length === 0 ? (
          <NoFilteredFindings />
        ) : (
          <div className="h-[calc(100vh-150px)]">
            <AutoSizer>
              {({ height, width }) => (
                <List
                  ref={listRef}
                  height={height}
                  width={width}
                  itemCount={filteredFindings.length}
                  itemSize={ROW_HEIGHT}
                  itemData={{
                    findings: filteredFindings,
                    isTriageMode,
                    selectedIndex,
                    selectedFindings,
                    handleTriage,
                    triageStates,
                    setSelectedFinding,
                    setIsModalOpen,
                    setSelectedIndex
                  }}
                >
                  {TableRow}
                </List>
              )}
            </AutoSizer>
          </div>
        )}
      </div>

      <FindingModal
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setSelectedFinding(null);
        }}
        finding={selectedFinding}
      />
    </div>
  );
};

const NoFindings = () => {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4">
      <div className="text-center">
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
          No findings available
        </h3>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          No findings have been generated yet. Findings will appear here as Nemesis performs its analysis.
        </p>
      </div>
    </div>
  );
};

const NoFilteredFindings = () => {
  const [searchParams, setSearchParams] = useSearchParams();

  // Function to handle viewing all findings
  const handleViewAllFindings = () => {
    // Get the current search params
    const newParams = new URLSearchParams(searchParams);

    // Explicitly set triage_state to "untriaged_and_actionable" (the new default)
    newParams.set('triage_state', 'untriaged_and_actionable');

    // Clear other filter parameters that might be causing the filtering
    newParams.delete('category');
    newParams.delete('severity');
    newParams.delete('origin');
    newParams.delete('triage_source');
    newParams.delete('object_id');

    // Update the URL with the new parameters
    setSearchParams(newParams, { replace: false });

    // Force a page reload to ensure all components re-initialize with the new parameters
    // This bypasses any issues with state management in the FilterFindings component
    window.location.href = `/findings?${newParams.toString()}`;
  };

  return (
    <div className="flex flex-col items-center justify-center py-16 px-4">
      <div className="text-center">
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
          No findings match your current filters
        </h3>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          Adjust the filters or click below to view default findings.
        </p>
        <button
          onClick={handleViewAllFindings}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors inline-flex items-center"
        >
          View Default Findings
        </button>
      </div>
    </div>
  );
};



export default FindingsList;
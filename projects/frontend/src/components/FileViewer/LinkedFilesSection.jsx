import {
  Card,
  CardContent,
  CardHeader,
  CardTitle
} from "@/components/ui/card";
import Dialog from "@/components/ui/dialog";
import { ExternalLink, FileText, X } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

// A file can be linked to thousands of others; only load/render a bounded slice.
const MAX_LINKINGS = 1000;
const INITIAL_VISIBLE = 50;
const VISIBLE_STEP = 200;

const getLinkedFilePath = (linking, currentPath) => {
  return linking.file_path_1.toLowerCase() === currentPath.toLowerCase() ? linking.file_path_2 : linking.file_path_1;
};

const getRelationshipDirection = (linking, currentPath) => {
  return linking.file_path_1.toLowerCase() === currentPath.toLowerCase() ? 'outbound' : 'inbound';
};

const LinkedFilesSection = ({ filePath, source }) => {
  const [linkedFiles, setLinkedFiles] = useState([]);
  const [totalLinkings, setTotalLinkings] = useState(0);
  const [visibleCount, setVisibleCount] = useState(INITIAL_VISIBLE);
  const [fileStatusMap, setFileStatusMap] = useState(new Map());
  const statusRequestedRef = useRef(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [linkingToDelete, setLinkingToDelete] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!filePath || !source) return;

    const fetchLinkedFiles = async () => {
      try {
        const query = {
          query: `
            query GetLinkedFiles($where: file_linkings_bool_exp!, $limit: Int!) {
              file_linkings(where: $where, order_by: {linking_id: asc}, limit: $limit) {
                linking_id
                file_path_1
                file_path_2
                link_type
                created_at
              }
              file_linkings_aggregate(where: $where) {
                aggregate {
                  count
                }
              }
            }
          `,
          variables: {
            limit: MAX_LINKINGS,
            where: {
              _and: [
                { source: { _eq: source } },
                { _or: [
                  { file_path_1: { _eq: filePath } },
                  { file_path_2: { _eq: filePath } }
                ]}
              ]
            }
          }
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

        const linkedFilesResult = result.data.file_linkings || [];

        statusRequestedRef.current = new Set();
        setFileStatusMap(new Map());
        setVisibleCount(INITIAL_VISIBLE);
        setTotalLinkings(result.data.file_linkings_aggregate?.aggregate?.count ?? linkedFilesResult.length);
        setLinkedFiles(linkedFilesResult);
      } catch (err) {
        setError(err.message);
        console.error('Error fetching linked files:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchLinkedFiles();
  }, [filePath, source]);

  // Group linked files by path to merge entries with different directions (case-insensitive)
  const groupedFiles = useMemo(() => {
    const groups = new Map();
    if (!filePath) return [];
    linkedFiles.forEach((linking) => {
      const linkedPath = getLinkedFilePath(linking, filePath);
      const direction = getRelationshipDirection(linking, filePath);
      const pathKey = linkedPath.toLowerCase();

      if (groups.has(pathKey)) {
        const existing = groups.get(pathKey);
        existing.directions.add(direction);
        existing.linkTypes.add(linking.link_type);
      } else {
        groups.set(pathKey, {
          linkedPath,
          directions: new Set([direction]),
          linkTypes: new Set([linking.link_type].filter(Boolean)),
          linkingId: linking.linking_id
        });
      }
    });
    return Array.from(groups.values());
  }, [linkedFiles, filePath]);

  const visibleGroups = useMemo(() => groupedFiles.slice(0, visibleCount), [groupedFiles, visibleCount]);

  // Fetch collection status only for the linked files currently rendered
  useEffect(() => {
    if (!source) return;
    const paths = visibleGroups
      .map(g => g.linkedPath.toLowerCase())
      .filter(p => !statusRequestedRef.current.has(p));
    if (paths.length === 0) return;
    paths.forEach(p => statusRequestedRef.current.add(p));

    let cancelled = false;
    let done = false;
    (async () => {
      try {
        const statusResponse = await fetch('/hasura/v1/graphql', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
          },
          body: JSON.stringify({
            query: `
              query GetFileStatuses($paths: [String!]!, $source: String!) {
                file_listings(where: {
                  _and: [
                    { source: { _eq: $source } },
                    { path_lower: { _in: $paths } }
                  ]
                }) {
                  path
                  status
                  object_id
                }
              }
            `,
            variables: { paths, source }
          })
        });
        if (!statusResponse.ok || cancelled) return;
        const statusResult = await statusResponse.json();
        if (cancelled) return;
        done = true;
        if (statusResult.errors) return;
        const fileListingsResult = statusResult.data.file_listings || [];
        if (fileListingsResult.length === 0) return;
        setFileStatusMap(prev => {
          const next = new Map(prev);
          // Create status map with case-insensitive keys
          fileListingsResult.forEach(file => {
            next.set(file.path.toLowerCase(), {
              status: file.status,
              object_id: file.object_id,
              originalPath: file.path
            });
          });
          return next;
        });
      } catch (err) {
        console.error('Error fetching linked file statuses:', err);
      }
    })();
    return () => {
      cancelled = true;
      // allow a retry if this request was abandoned before it completed
      if (!done) paths.forEach(p => statusRequestedRef.current.delete(p));
    };
  }, [visibleGroups, source]);

  const handleFileClick = async (targetPath, linkInfo) => {
    try {
      if (linkInfo?.status === 'collected' && linkInfo?.object_id) {
        // File is collected and has an object_id, navigate directly
        navigate(`/files/${linkInfo.object_id}`, {
          state: { from: 'file' }
        });
      } else {
        console.log('Linked file not collected or not available:', targetPath, 'status:', linkInfo?.status);
      }
    } catch (err) {
      console.error('Error navigating to linked file:', err);
    }
  };

  const handleDeleteClick = (linkingId) => {
    setLinkingToDelete(linkingId);
    setShowDeleteDialog(true);
  };

  const handleConfirmDelete = async () => {
    if (!linkingToDelete) return;

    try {
      const mutation = {
        query: `
          mutation DeleteLinking($linkingId: bigint!) {
            delete_file_linkings_by_pk(linking_id: $linkingId) {
              linking_id
            }
          }
        `,
        variables: { linkingId: linkingToDelete }
      };

      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(mutation)
      });

      if (!response.ok) {
        throw new Error('Network response was not ok');
      }

      const result = await response.json();
      if (result.errors) {
        throw new Error(result.errors[0].message);
      }

      // Remove the deleted linking from the state
      setLinkedFiles(linkedFiles.filter(linking => linking.linking_id !== linkingToDelete));
      setTotalLinkings(n => Math.max(0, n - 1));
      setShowDeleteDialog(false);
      setLinkingToDelete(null);
    } catch (err) {
      console.error('Error deleting linking:', err);
      setError(err.message);
      setShowDeleteDialog(false);
      setLinkingToDelete(null);
    }
  };

  const handleCancelDelete = () => {
    setShowDeleteDialog(false);
    setLinkingToDelete(null);
  };

  // Without a path/source there is nothing to fetch
  if (loading && filePath && source) {
    return (
      <Card className="bg-white dark:bg-dark-secondary shadow-lg transition-colors">
        <CardHeader className="pb-4">
          <CardTitle className="text-gray-900 dark:text-gray-100">Linked Files</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex justify-center py-4">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600 dark:border-blue-400"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="bg-white dark:bg-dark-secondary shadow-lg transition-colors">
        <CardHeader className="pb-4">
          <CardTitle className="text-gray-900 dark:text-gray-100">Linked Files</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
            <p className="text-red-600 dark:text-red-400 text-sm">Error loading linked files: {error}</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (linkedFiles.length === 0) {
    return null;
  }

  return (
    <>
      <Card className="bg-white dark:bg-dark-secondary shadow-lg transition-colors">
        <CardHeader className="pb-4">
          <CardTitle className="text-gray-900 dark:text-gray-100 flex items-center gap-2">
            Linked Files
            <span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 text-xs px-2 py-1 rounded-full">
              {totalLinkings.toLocaleString()}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {visibleGroups.map((group) => {
                const fileName = group.linkedPath.split(/[/\\]/).pop() || group.linkedPath;

                // Get file status info (case-insensitive lookup)
                let fileInfo = fileStatusMap.get(group.linkedPath.toLowerCase());
                const isCollected = fileInfo?.status === 'collected' && fileInfo?.object_id;

                return (
                  <div
                    key={group.linkingId}
                    className={`relative flex items-start justify-between p-3 rounded-lg transition-colors ${isCollected
                      ? 'bg-green-50 dark:bg-green-900/20 hover:bg-green-100 dark:hover:bg-green-900/30 border border-green-200 dark:border-green-800'
                      : 'bg-gray-50 dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700'
                      }`}
                  >
                    {!isCollected && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeleteClick(group.linkingId);
                        }}
                        className="absolute top-2 right-2 p-1 rounded-full bg-red-600 hover:bg-red-700 text-white transition-colors"
                        title="Delete this linking"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    )}
                    <div className="flex items-start space-x-3 flex-1 min-w-0">
                      <div className="flex flex-col items-center flex-shrink-0">
                        <FileText className={`w-4 h-4 mt-1 ${isCollected ? 'text-green-600 dark:text-green-400' : 'text-gray-500 dark:text-gray-400'
                          }`} />
                        {isCollected && (
                          <button
                            onClick={() => handleFileClick(group.linkedPath, fileInfo)}
                            className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-200 cursor-pointer mt-2"
                            title="Navigate to linked file"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className={`text-sm font-medium truncate ${isCollected ? 'text-green-900 dark:text-green-100' : 'text-gray-900 dark:text-gray-100'
                            }`}>
                            {fileName}
                          </p>
                          {Array.from(group.linkTypes).map((linkType) => (
                            <span key={linkType} className="bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 text-xs px-2 py-1 rounded">
                              {linkType}
                            </span>
                          ))}
                          {Array.from(group.directions).map((direction) => (
                            <span key={direction} className={`text-xs px-2 py-1 rounded ${direction === 'outbound'
                              ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'
                              : 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200'
                              }`}>
                              {direction}
                            </span>
                          ))}
                          {fileInfo && !isCollected && (
                            <span className={`text-xs px-2 py-1 rounded ${fileInfo.status === 'needs_to_be_collected'
                              ? 'bg-yellow-200 dark:bg-yellow-800 text-yellow-900 dark:text-yellow-100'
                              : 'bg-red-200 dark:bg-red-800 text-red-900 dark:text-red-100'
                              }`}>
                              {fileInfo.status.replace(/_/g, ' ')}
                            </span>
                          )}
                        </div>
                        {isCollected ? (
                          <button
                            type="button"
                            className="block w-full text-left text-xs truncate mt-1 text-green-600 dark:text-green-400 cursor-pointer hover:text-green-800 dark:hover:text-green-200 hover:underline"
                            onClick={() => handleFileClick(group.linkedPath, fileInfo)}
                            title="Click to navigate to file"
                          >
                            {group.linkedPath}
                          </button>
                        ) : (
                          <p className="text-xs truncate mt-1 text-gray-500 dark:text-gray-400">
                            {group.linkedPath}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                );
            })}
          </div>
          {(groupedFiles.length > visibleCount || totalLinkings > linkedFiles.length) && (
            <div className="mt-3 flex items-center justify-between text-sm text-gray-500 dark:text-gray-400">
              <span>
                Showing {Math.min(visibleCount, groupedFiles.length).toLocaleString()} of {groupedFiles.length.toLocaleString()} linked files
                {totalLinkings > linkedFiles.length && ` (first ${linkedFiles.length.toLocaleString()} of ${totalLinkings.toLocaleString()} links loaded)`}
              </span>
              {groupedFiles.length > visibleCount && (
                <button
                  onClick={() => setVisibleCount(c => c + VISIBLE_STEP)}
                  className="px-3 py-1 rounded bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-200"
                >
                  Show {Math.min(VISIBLE_STEP, groupedFiles.length - visibleCount).toLocaleString()} more
                </button>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Confirmation Dialog */}
      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <div className="text-center">
          <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">
            Delete this linking?
          </h3>
          <div className="flex gap-3 justify-center">
            <button
              onClick={handleCancelDelete}
              className="px-4 py-2 bg-gray-300 hover:bg-gray-400 text-gray-800 rounded-lg transition-colors"
            >
              No
            </button>
            <button
              onClick={handleConfirmDelete}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              Yes
            </button>
          </div>
        </div>
      </Dialog>
    </>
  );
};

export default LinkedFilesSection;
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle
} from "@/components/ui/card";
import Dialog from "@/components/ui/dialog";
import { ExternalLink, FileText, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const LinkedFilesSection = ({ filePath, source }) => {
  const [linkedFiles, setLinkedFiles] = useState([]);
  const [fileStatusMap, setFileStatusMap] = useState(new Map());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [linkingToDelete, setLinkingToDelete] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!filePath || !source) {
      setLoading(false);
      return;
    }

    const fetchLinkedFiles = async () => {
      try {
        // Normalize path by replacing backslashes with forward slashes
        const normalizedFilePath = filePath.replace(/\\/g, '/');

        // Debug: log what we're searching for
        // console.log('LinkedFiles: Original filePath:', filePath);
        // console.log('LinkedFiles: Normalized filePath:', normalizedFilePath, 'source:', source);
        // console.log('LinkedFiles: Component props - filePath type:', typeof filePath, 'source type:', typeof source);

        const query = {
          query: `
            query GetLinkedFiles($filePath: String!, $normalizedFilePath: String!, $source: String!) {
              file_linkings(where: {
                _and: [
                  { source: { _eq: $source } },
                  { _or: [
                    { file_path_1: { _eq: $filePath } },
                    { file_path_2: { _eq: $filePath } },
                    { file_path_1: { _eq: $normalizedFilePath } },
                    { file_path_2: { _eq: $normalizedFilePath } }
                  ]}
                ]
              }) {
                linking_id
                file_path_1
                file_path_2
                link_type
                created_at
              }
            }
          `,
          variables: { filePath: filePath, normalizedFilePath: normalizedFilePath, source }
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

        // console.log('LinkedFiles: Query result:', linkedFilesResult);

        // Now fetch file status for each linked file
        const statusMap = new Map();

        if (linkedFilesResult.length > 0) {
          // Collect all unique linked file paths
          const linkedPaths = new Set();
          linkedFilesResult.forEach(linking => {
            const normalizedCurrentPath = normalizedFilePath;
            const originalCurrentPath = filePath;
            const normalizedPath1 = linking.file_path_1.replace(/\\/g, '/');
            const normalizedPath2 = linking.file_path_2.replace(/\\/g, '/');

            // Add the path that's not the current file (check both original and normalized)
            if (linking.file_path_1 !== originalCurrentPath && normalizedPath1 !== normalizedCurrentPath) {
              linkedPaths.add(linking.file_path_1);
            }
            if (linking.file_path_2 !== originalCurrentPath && normalizedPath2 !== normalizedCurrentPath) {
              linkedPaths.add(linking.file_path_2);
            }
          });

          // console.log('LinkedFiles: Linked paths to check status for:', Array.from(linkedPaths));
          // console.log('LinkedFiles: Current file path (normalized):', normalizedFilePath);

          // Query file status for each linked path - also include normalized versions
          const allPathsToCheck = new Set();
          linkedPaths.forEach(path => {
            allPathsToCheck.add(path);
            allPathsToCheck.add(path.replace(/\\/g, '/'));
          });

          const statusQuery = {
            query: `
              query GetFileStatuses($paths: [String!]!, $source: String!) {
                file_listings(where: {
                  _and: [
                    { source: { _eq: $source } },
                    { path: { _in: $paths } }
                  ]
                }) {
                  path
                  status
                  object_id
                }
              }
            `,
            variables: { paths: Array.from(allPathsToCheck), source }
          };

          const statusResponse = await fetch('/hasura/v1/graphql', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
            },
            body: JSON.stringify(statusQuery)
          });

          if (statusResponse.ok) {
            const statusResult = await statusResponse.json();
            if (!statusResult.errors) {
              const fileListingsResult = statusResult.data.file_listings || [];

              // Create status map with both normalized and original path keys
              fileListingsResult.forEach(file => {
                const normalizedPath = file.path.replace(/\\/g, '/');
                const fileInfo = {
                  status: file.status,
                  object_id: file.object_id
                };

                // Store with both original and normalized paths as keys
                statusMap.set(file.path, fileInfo);
                statusMap.set(normalizedPath, fileInfo);
              });

              // console.log('LinkedFiles: Status query result:', fileListingsResult);
              // console.log('LinkedFiles: Status map:', statusMap);

              // Debug: Check what paths we're actually looking for vs what we got
              Array.from(linkedPaths).forEach(path => {
                const normalizedPath = path.replace(/\\/g, '/');
                const found = statusMap.get(path) || statusMap.get(normalizedPath);
                // console.log(`LinkedFiles: Path "${path}" (normalized: "${normalizedPath}") -> Status:`, found);
              });
            }
          }
        }

        setLinkedFiles(linkedFilesResult);
        setFileStatusMap(statusMap);
      } catch (err) {
        setError(err.message);
        console.error('Error fetching linked files:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchLinkedFiles();
  }, [filePath, source]);

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

  const getLinkedFilePath = (linking, currentPath) => {
    // Normalize both paths for comparison
    const normalizedPath1 = linking.file_path_1.replace(/\\/g, '/');
    const normalizedPath2 = linking.file_path_2.replace(/\\/g, '/');
    const normalizedCurrentPath = currentPath.replace(/\\/g, '/');

    return normalizedPath1 === normalizedCurrentPath ? linking.file_path_2 : linking.file_path_1;
  };

  const getRelationshipDirection = (linking, currentPath) => {
    // Normalize both paths for comparison
    const normalizedPath1 = linking.file_path_1.replace(/\\/g, '/');
    const normalizedCurrentPath = currentPath.replace(/\\/g, '/');

    return normalizedPath1 === normalizedCurrentPath ? 'outbound' : 'inbound';
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

  if (loading) {
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
              {linkedFiles.length}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {(() => {
              // Group linked files by path to merge entries with different directions
              const groupedFiles = new Map();

              linkedFiles.forEach((linking) => {
                const linkedPath = getLinkedFilePath(linking, filePath);
                const normalizedLinkedPath = linkedPath.replace(/\\/g, '/');
                const direction = getRelationshipDirection(linking, filePath);

                if (groupedFiles.has(normalizedLinkedPath)) {
                  const existing = groupedFiles.get(normalizedLinkedPath);
                  existing.directions.add(direction);
                  existing.linkTypes.add(linking.link_type);
                } else {
                  groupedFiles.set(normalizedLinkedPath, {
                    linkedPath,
                    normalizedLinkedPath,
                    directions: new Set([direction]),
                    linkTypes: new Set([linking.link_type].filter(Boolean)),
                    linkingId: linking.linking_id
                  });
                }
              });

              return Array.from(groupedFiles.values()).map((group) => {
                const fileName = group.linkedPath.split(/[\/\\]/).pop() || group.linkedPath;

                // Get file status info - try both normalized and original path
                let fileInfo = fileStatusMap.get(group.normalizedLinkedPath) || fileStatusMap.get(group.linkedPath);
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
                        <p
                          className={`text-xs truncate mt-1 ${isCollected
                            ? 'text-green-600 dark:text-green-400 cursor-pointer hover:text-green-800 dark:hover:text-green-200 hover:underline'
                            : 'text-gray-500 dark:text-gray-400'
                            }`}
                          onClick={isCollected ? () => handleFileClick(group.linkedPath, fileInfo) : undefined}
                          title={isCollected ? "Click to navigate to file" : undefined}
                        >
                          {group.linkedPath}
                        </p>
                      </div>
                    </div>
                  </div>
                );
              });
            })()}
          </div>
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
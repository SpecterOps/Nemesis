import MarkdownRenderer from '@/components/shared/MarkdownRenderer';
import { useTheme } from '@/components/ThemeProvider';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import Dialog from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useUser } from '@/contexts/UserContext';
import { cachedFetch } from '@/utils/fileCache';
import { createClient } from 'graphql-ws';
import { Archive, ArrowLeft, ChevronDown, Database, Download, Eye, File, FileText, Image } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import CsvViewer from './CsvViewer';
import EnrichmentStatusSection from './EnrichmentStatusSection';
import FileDetailsSection from './FileDetailsSection';
import { getMonacoLanguage } from './languageMap';
import LinkedFilesSection from './LinkedFilesSection';
import MonacoContentViewer from './MonacoViewer';
import SCCMLogViewer from './SCCMLogViewer';
import SQLiteViewer from './SQLiteViewer';
import ZipFileViewer from './ZipFileViewer';


const MAX_VIEW_SIZE = 1024 * 1024; // 1MB text display limit
const MAX_RENDERABLE_VIEW_SIZE = 100 * 1024 * 1024; // 100MB limit for sqlite/zip/etc.

const recordedViews = new Map();

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

const createHexView = (data, maxSize = MAX_VIEW_SIZE) => {
  const bytes = new Uint8Array(data.slice(0, maxSize));
  const hexRows = [];

  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hexLine = Array.from(chunk)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join(' ');
    const asciiLine = Array.from(chunk)
      .map(byte => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')
      .join('');

    hexRows.push(`${i.toString(16).padStart(8, '0')}  ${hexLine.padEnd(48, ' ')}  ${asciiLine}`);
  }

  return hexRows.join('\n');
};

const isZipFile = (fileName, mimeType) => {
  if (!fileName && !mimeType) return false;

  const zipExtensions = ['.zip', '.jar', '.war', '.ear', '.apk'];
  const zipMimeTypes = [
    'application/zip',
    'application/java-archive',
    'application/x-zip-compressed',
    'application/vnd.android.package-archive'
  ];

  const fileExt = fileName ? '.' + fileName.split('.').pop().toLowerCase() : '';

  return zipMimeTypes.includes(mimeType) || zipExtensions.includes(fileExt);
};

const isSqliteFile = (fileName, mimeType) => {
  if (!fileName && !mimeType) return false;

  const sqliteExtensions = ['.db', '.sqlite', '.sqlite3', '.db3'];
  const sqliteMimeTypes = [
    'application/x-sqlite3',
    'application/vnd.sqlite3',
    'application/sqlite',
    'application/sqlite3'
  ];

  const fileExt = fileName ? '.' + fileName.split('.').pop().toLowerCase() : '';

  return sqliteMimeTypes.includes(mimeType) ||
    sqliteExtensions.includes(fileExt) ||
    fileName === 'database';
};

const isCsvFile = (fileName, mimeType) => {
  if (!fileName && !mimeType) return false;

  const csvExtensions = ['.csv'];
  const csvMimeTypes = [
    'text/csv',
    'application/csv',
    'application/vnd.ms-excel',
    'text/comma-separated-values'
  ];

  const fileExt = fileName ? '.' + fileName.split('.').pop().toLowerCase() : '';

  return csvMimeTypes.includes(mimeType) || csvExtensions.includes(fileExt);
};

const isSCCMLogFile = (fileName, content) => {
  if (!content) return false;
  const firstLine = content.split('\n')[0];
  return firstLine.includes('<![LOG[') && firstLine.includes(']LOG]!>');
};

const detectEncodingFromBOM = (buffer) => {
  if (!buffer || buffer.length < 2) return null;

  const bytes = new Uint8Array(buffer.slice(0, 4));

  // UTF-8 BOM: EF BB BF
  if (bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) {
    return 'utf-8';
  }

  // UTF-16 BE BOM: FE FF
  if (bytes[0] === 0xFE && bytes[1] === 0xFF) {
    return 'utf-16be';
  }

  // UTF-16 LE BOM: FF FE
  if (bytes[0] === 0xFF && bytes[1] === 0xFE) {
    return 'utf-16le';
  }

  // UTF-32 BE BOM: 00 00 FE FF
  if (bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0xFE && bytes[3] === 0xFF) {
    return 'utf-32be';
  }

  // UTF-32 LE BOM: FF FE 00 00
  if (bytes[0] === 0xFF && bytes[1] === 0xFE && bytes[2] === 0x00 && bytes[3] === 0x00) {
    return 'utf-32le';
  }

  // No BOM found - try to detect based on content pattern
  // Check for common UTF-8 patterns
  let isLikelyUTF8 = true;
  for (let i = 0; i < Math.min(buffer.length, 1024); i++) {
    const byte = bytes[i];
    // Check for invalid UTF-8 sequences
    if (byte > 0x7F) { // non-ASCII
      if (byte >= 0xC0 && byte <= 0xDF) { // 2-byte sequence
        if (i + 1 >= buffer.length || (bytes[i + 1] & 0xC0) !== 0x80) {
          isLikelyUTF8 = false;
          break;
        }
        i += 1;
      } else if (byte >= 0xE0 && byte <= 0xEF) { // 3-byte sequence
        if (i + 2 >= buffer.length ||
          (bytes[i + 1] & 0xC0) !== 0x80 ||
          (bytes[i + 2] & 0xC0) !== 0x80) {
          isLikelyUTF8 = false;
          break;
        }
        i += 2;
      } else {
        isLikelyUTF8 = false;
        break;
      }
    }
  }

  return isLikelyUTF8 ? 'utf-8' : 'iso-8859-1';
};


const EncodingSelector = ({ onEncodingChange, initialEncoding }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [selectedEncoding, setSelectedEncoding] = useState(initialEncoding || 'utf-8');

  const encodings = [
    { value: 'utf-8', label: 'UTF-8' },
    { value: 'utf-16le', label: 'UTF-16LE' },
    { value: 'utf-16be', label: 'UTF-16BE' },
    { value: 'iso-8859-1', label: 'ISO-8859-1' },
    { value: 'ascii', label: 'ASCII' }
  ];

  const handleEncodingChange = (encoding) => {
    setSelectedEncoding(encoding);
    onEncodingChange(encoding);
    setIsOpen(false);
  };

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-1 px-3 h-9 bg-gray-800 dark:bg-gray-800 text-gray-300 text-sm rounded hover:bg-gray-700 dark:hover:bg-gray-700 border border-gray-700 dark:border-gray-700"
      >
        {encodings.find(e => e.value === selectedEncoding)?.label}
        <ChevronDown className="w-4 h-4 opacity-50" />
      </button>

      {isOpen && (
        <>
          <div
            className="fixed inset-0"
            onClick={() => setIsOpen(false)}
          />
          <div className="absolute z-50 mt-1 w-40 rounded-md shadow-lg bg-gray-800 border border-gray-700">
            <div className="py-1">
              {encodings.map((encoding) => (
                <button
                  key={encoding.value}
                  onClick={() => handleEncodingChange(encoding.value)}
                  className={`w-full text-left px-4 py-2 text-sm ${selectedEncoding === encoding.value
                    ? 'bg-gray-700 text-white'
                    : 'text-gray-300 hover:bg-gray-700'
                    }`}
                >
                  {encoding.label}
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
};


const FileViewer = () => {
  // main File viewing functionality
  const { objectId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { isDark } = useTheme();
  const [fileData, setFileData] = useState(null);
  const [fileContent, setFileContent] = useState(null);
  const [pdfContent, setPdfContent] = useState(null);
  const [transformContents, setTransformContents] = useState({});
  const [textContent, setTextContent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [currentLanguage, setCurrentLanguage] = useState('plaintext');
  const [isContentTruncated, setIsContentTruncated] = useState(false);
  const fileContentRef = useRef(null);
  const [transformData, setTransformData] = useState({});
  const { username } = useUser();
  // const [hasRecordedView, setHasRecordedView] = useState(false);
  const viewRecorded = useRef(false);
  const [containerAnalysisStarted, setContainerAnalysisStarted] = useState(false);
  const [summarizationStarted, setSummarizationStarted] = useState(false);
  const [credentialAnalysisStarted, setCredentialAnalysisStarted] = useState(false);
  const [dotnetAnalysisStarted, setDotnetAnalysisStarted] = useState(false);
  const [translationStarted, setTranslationStarted] = useState(false);
  const [showConfirmDialog, setShowConfirmDialog] = useState(false);
  const [showSuccessDialog, setShowSuccessDialog] = useState(false);
  const [showTranslateDialog, setShowTranslateDialog] = useState(false);
  const [targetLanguage, setTargetLanguage] = useState('English');
  const [isLiteLLMAvailable, setIsLiteLLMAvailable] = useState(false);

  // Determine where we came from
  const isFromSearch = location.state?.from === 'search';
  const isFromFile = location.state?.from === 'file';
  const isFromFindings = location.state?.from === 'findings';
  const previousFileId = location.state?.previousFileId;

  const [detectedEncoding, setDetectedEncoding] = useState('utf-8');

  const recordFileView = async (objectId) => {
    // Check global map first
    if (recordedViews.has(objectId)) {
      return;
    }

    const mutation = {
      query: `
        mutation InsertFileView($object_id: uuid!, $username: String!) {
          insert_files_view_history_one(object: {
            object_id: $object_id,
            username: $username,
            automated: false
          }) {
            id
            timestamp
          }
        }
      `,
      variables: {
        object_id: objectId,
        username: username
      }
    };

    try {
      // Set the recorded flag before making the request
      recordedViews.set(objectId, true);

      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify(mutation)
      });

      if (!response.ok) throw new Error('Network response was not ok');

      const result = await response.json();
      if (result.errors) {
        const errorMessage = result.errors[0].message;

        // Silently handle foreign key violations (file doesn't exist)
        if (errorMessage.includes('foreign key constraint') && errorMessage.includes('fk_files_view_history_object_id')) {
          return;
        }

        throw new Error(errorMessage);
      }

    } catch (err) {
      // If there's an error, remove the flag so it can be retried
      recordedViews.delete(objectId);

      // Only log non-foreign-key errors
      const errorMessage = err.message || '';
      if (!errorMessage.includes('foreign key constraint')) {
        console.error('Failed to record file view:', err);
      }
    }
  };

  // check if LiteLLM service is available
  useEffect(() => {
    const checkLiteLLMAvailability = async () => {
      try {
        const response = await fetch('/api/system/available-services');
        if (response.ok) {
          const data = await response.json();
          setIsLiteLLMAvailable(data.services?.includes('/llm') || false);
        }
      } catch (error) {
        console.error('Error checking LiteLLM availability:', error);
      }
    };

    checkLiteLLMAvailability();
  }, []);

  // record that a user viewed this file
  useEffect(() => {
    if (objectId && username) {
      recordFileView(objectId);
    }
  }, [objectId, username]);

  useEffect(() => {
    if (!objectId) return;

    const subscription = {
      query: `
        subscription WatchFileTransforms($objectId: uuid!) {
          files_enriched(where: {object_id: {_eq: $objectId}}) {
            object_id
            transforms {
              metadata
              type
              transform_object_id
            }
          }
        }
      `,
      variables: { objectId }
    };

    let unsubscribe;

    (async () => {
      unsubscribe = wsClient.subscribe(
        subscription,
        {
          next: ({ data }) => {
            if (data?.files_enriched && data.files_enriched.length > 0) {
              const updatedFile = data.files_enriched[0];

              // Update fileData with the new transforms
              setFileData(prev => ({
                ...prev,
                transforms: updatedFile.transforms
              }));

              // Fetch new transform content if needed
              if (updatedFile.transforms) {
                const newTransforms = updatedFile.transforms.filter(transform =>
                  isDisplayableTransform(transform) &&
                  !transformData[transform.transform_object_id]
                );

                newTransforms.forEach(async (transform) => {
                  const response = await cachedFetch(`/api/files/${transform.transform_object_id}`);
                  if (response.ok) {
                    const content = await response.arrayBuffer();
                    setTransformData(prev => ({
                      ...prev,
                      [transform.transform_object_id]: {
                        content,
                        type: transform.metadata.display_type_in_dashboard,
                        fileName: transform.metadata.file_name
                      }
                    }));
                  }
                });
              }
            }
          },
          error: (err) => {
            console.error('Subscription error:', err);
            setError('Error in real-time updates');
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
  }, [objectId]);

  // Helper to determine if a transform should be shown as a tab
  const isDisplayableTransform = (transform) => {
    return transform.metadata?.display_type_in_dashboard === 'monaco' ||
      transform.metadata?.display_type_in_dashboard === 'pdf' ||
      transform.metadata?.display_type_in_dashboard === 'markdown' ||
      transform.metadata?.display_type_in_dashboard === 'image' ||
      transform.metadata?.display_type_in_dashboard === 'csv' ||
      transform.type === 'csv';
  };

  // Helper to determine if a transform should be offered as a download
  const isDownloadableTransform = (transform) => {
    return transform.metadata?.offer_as_download === true;
  };

  const handleBackClick = () => {
    if (isFromFile && previousFileId) {
      navigate('/files', {
        state: {
          maintainSelectedIndex: selectedIndex,
          filters: location.state?.filters
        }
      });
    } else if (isFromSearch) {
      navigate('/search');
    } else if (isFromFindings) {
      // Go back to the previous page
      window.history.back();

      // navigate('/findings', {
      //   state: {
      //     from: 'file',
      //     // filters: location.state?.filters
      //   }
      // });
    } else {
      // Preserve the URL search params when navigating back to files
      const searchParams = new URLSearchParams(location.search);
      navigate(`/files${searchParams.toString() ? '?' + searchParams.toString() : ''}`, {
        state: {
          filters: location.state?.filters
        }
      });
    }
  };

  const displayableImageTypes = {
    extensions: new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'avif']),
    mimeTypes: new Set([
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'image/svg+xml',
      'image/avif'
    ])
  };

  const isDisplayableImage = (fileName, mimeType) => {
    const ext = fileName.split('.').pop()?.toLowerCase();
    return displayableImageTypes.extensions.has(ext) ||
      displayableImageTypes.mimeTypes.has(mimeType);
  };

  const hasPreviewableImage = Boolean(fileContent && isDisplayableImage(fileData?.file_name, fileData?.mime_type));
  const hasPreviewableContent = Boolean(pdfContent || hasPreviewableImage || (fileData && fileData.mime_type === 'application/pdf'));

  // helper to get the file view tabs available
  const getAvailableTabs = () => {
    const tabs = [];

    // Add preview tab if content is previewable
    if (hasPreviewableContent) {
      tabs.push({ id: 'preview', type: 'preview', label: 'Preview', icon: Eye });
    }

    // Add ZIP explorer if file is a ZIP
    if (fileData && isZipFile(fileData.file_name, fileData.mime_type) && fileContent) {
      tabs.push({ id: 'zip-explorer', type: 'zip', label: 'ZIP Explorer', icon: Archive });
    }

    // add SQLite explorer if it's a sqlite file
    if (fileData && isSqliteFile(fileData.file_name, fileData.mime_type) && fileContent) {
      tabs.push({ id: 'sqlite-explorer', type: 'sqlite', label: 'SQLite Explorer', icon: Database });
    }

    // // add CSV explorer if it's a CSV file
    // if (fileData && isCsvFile(fileData.file_name, fileData.mime_type) && fileContent) {
    //   tabs.push({ id: 'csv-explorer', type: 'csv', label: 'CSV Explorer', icon: FileText });
    // }

    if (isSCCMLogFile(fileData.file_name, textContent)) {
      tabs.push({ id: 'sccm-log', type: 'sccm-log', label: 'SCCM Log', icon: FileText });
    }

    // Add base tabs
    if (fileData?.is_plaintext) {
      tabs.push({ id: 'text', type: 'text', label: 'Text', icon: FileText });
    }

    // Add transform tabs (keep your existing code here)
    if (fileData?.transforms) {
      fileData.transforms.forEach(transform => {
        if (isDisplayableTransform(transform)) {
          tabs.push({
            id: transform.transform_object_id,
            type: transform.type,
            label: transform.metadata.display_title || transform.type,
            displayType: transform.metadata.display_type_in_dashboard,
            icon: transform.metadata.display_type_in_dashboard === 'pdf' ? Eye :
              transform.metadata.display_type_in_dashboard === 'image' ? Image : FileText
          });
        }
      });
    }

    // Add enrichment tabs
    if (fileData?.enrichments) {
      fileData.enrichments.forEach(enrichment => {
        if (enrichment.result_data) {
          tabs.push({
            id: `enrichment-${enrichment.module_name}`,
            type: 'enrichment',
            label: `Enrichment - ${enrichment.module_name}`,
            enrichmentData: enrichment,
            icon: FileText
          });
        }
      });
    }

    // Always add hex view
    tabs.push({ id: 'hex', type: 'hex', label: 'Hex', icon: File });

    return tabs;
  };

  const getDownloadableTransforms = () => {
    if (!fileData?.transforms) return [];
    return fileData.transforms.filter(isDownloadableTransform);
  };

  const shouldShowContainerAnalysisButton = () => {
    if (!fileData?.is_container || containerAnalysisStarted) return false;

    // Check if container_contents enrichment already exists
    return !fileData.enrichments?.some(enrichment =>
      enrichment.module_name === 'container_contents'
    );
  };

  const shouldShowSummarizationButton = () => {
    if (!isLiteLLMAvailable || summarizationStarted) return false;

    // Check if a text_summary transform already exists
    const hasTextSummaryTransform = fileData?.transforms?.some(transform =>
      transform.type === 'text_summary'
    );

    if (hasTextSummaryTransform) return false;

    // Check if file is plaintext OR has an extracted_text transform
    const hasExtractedTextTransform = fileData?.transforms?.some(transform =>
      transform.type === 'extracted_text'
    );

    return fileData?.is_plaintext || hasExtractedTextTransform;
  };

  const shouldShowCredentialAnalysisButton = () => {
    if (!isLiteLLMAvailable || credentialAnalysisStarted) return false;

    // Check if a llm_extracted_credentials transform already exists
    const hasExtractedCredentialTransform = fileData?.transforms?.some(transform =>
      transform.type === 'llm_extracted_credentials'
    );

    if (hasExtractedCredentialTransform) return false;

    // Check if file is plaintext OR has an extracted_text transform
    const hasExtractedTextTransform = fileData?.transforms?.some(transform =>
      transform.type === 'extracted_text'
    );

    return fileData?.is_plaintext || hasExtractedTextTransform;
  };

  const shouldShowDotNetAnalysisButton = () => {
    if (!isLiteLLMAvailable || dotnetAnalysisStarted) return false;

    // Check if a dotnet_analysis transform already exists
    const hasDotNetAnalysisTransform = fileData?.transforms?.some(transform =>
      transform.type === 'dotnet_analysis'
    );

    if (hasDotNetAnalysisTransform) return false;

    // Check if file is a .NET assembly based on magic_type
    return fileData?.magic_type && fileData.magic_type.toLowerCase().includes('mono/.net assembly');
  };

  const shouldShowTranslationButton = () => {
    if (!isLiteLLMAvailable || translationStarted) return false;

    // Check if a text_translation transform already exists
    const hasTranslationTransform = fileData?.transforms?.some(transform =>
      transform.type === 'text_translation'
    );

    if (hasTranslationTransform) return false;

    // Check if file is plaintext OR has an extracted_text transform
    const hasExtractedTextTransform = fileData?.transforms?.some(transform =>
      transform.type === 'extracted_text'
    );

    return fileData?.is_plaintext || hasExtractedTextTransform;
  };

  // Start with hex as fallback
  const [activeTab, setActiveTab] = useState('hex');

  // Update this useEffect in your FileViewer.jsx component

  // Set the initial tab based on transform metadata and fallback order
  useEffect(() => {
    if (fileData || pdfContent) {
      const tabs = getAvailableTabs();

      // First check if the file is a ZIP file and we have content for it
      if (fileData && isZipFile(fileData.file_name, fileData.mime_type) && fileContent) {
        setActiveTab('zip-explorer');
        return;
      }

      // Then check for .zip transforms
      if (fileData?.transforms) {
        const zipTransform = fileData.transforms.find(transform =>
          transform.metadata?.file_name && transform.metadata.file_name.endsWith('.zip')
        );
        if (zipTransform) {
          setActiveTab(zipTransform.transform_object_id);
          return;
        }
      }

      // Then check for PDF transforms
      if (fileData?.transforms) {
        const pdfTransform = fileData.transforms.find(transform =>
          isDisplayableTransform(transform) && transform.type === 'converted_pdf'
        );
        if (pdfTransform) {
          setActiveTab(pdfTransform.transform_object_id);
          return;
        }

        // Then check for transforms with default_display=true
        const defaultTransform = fileData.transforms.find(transform =>
          isDisplayableTransform(transform) && transform.metadata?.default_display === true
        );
        if (defaultTransform) {
          setActiveTab(defaultTransform.transform_object_id);
          return;
        }
      }

      // Then follow fallback order: Preview -> Text -> Hex
      if (hasPreviewableContent) {
        setActiveTab('preview');
      } else if (tabs.find(tab => tab.id === 'text')) {
        setActiveTab('text');
      }
      // If no other conditions met, it will stay as 'hex'
    }
  }, [fileData, pdfContent, hasPreviewableContent, fileContent]);

  // left arrow to go back
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'ArrowLeft' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        handleBackClick();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [navigate]);

  useEffect(() => {
    const fetchFileData = async () => {
      try {
        // Fetch file metadata
        const query = {
          query: `
            query GetFileDetails($objectId: uuid!) {
              files_enriched(where: {object_id: {_eq: $objectId}}) {
                object_id
                agent_id
                source
                project
                timestamp
                expiration
                path
                file_name
                size
                magic_type
                mime_type
                is_plaintext
                is_container
                originating_object_id
                originating_container_id
                nesting_level
                hashes
                file_tags
                created_at
                updated_at
                enrichments {
                  module_name
                  result_data
                  created_at
                  updated_at
                }
                transforms {
                  metadata
                  type
                  transform_object_id
                }
                files_view_histories {
                  username
                  timestamp
                }
                findingsByObjectId_aggregate {
                  aggregate {
                    count
                  }
                }
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

        const file = result.data.files_enriched[0];

        // Check if file exists
        if (!file) {
          throw new Error(`File not found: The file with UUID ${objectId} does not exist in the database`);
        }

        setFileData(file);
        setCurrentLanguage(getMonacoLanguage(file.file_name, file.mime_type));

        // If file is under size limit, fetch the file content content

        if (file.size <= MAX_RENDERABLE_VIEW_SIZE) {
          const contentResponse = await cachedFetch(`/api/files/${file.object_id}`);
          if (contentResponse.ok) {
            const buffer = await contentResponse.arrayBuffer();

            if (file.mime_type === 'application/pdf') {
              setPdfContent(buffer);
            } else {
              setFileContent(buffer);

              // Detect encoding from BOM
              const detected = detectEncodingFromBOM(buffer);
              setDetectedEncoding(detected);

              // Decode content with detected encoding
              const decoder = new TextDecoder(detected);
              setTextContent(decoder.decode(buffer.slice(0, MAX_VIEW_SIZE)));
              setIsContentTruncated(buffer.byteLength > MAX_VIEW_SIZE);
            }
          }
        }

        // Handle transforms - fetch in parallel
        if (file.transforms) {
          const transformPromises = file.transforms
            .filter(isDisplayableTransform)
            .map(async (transform) => {
              const response = await cachedFetch(`/api/files/${transform.transform_object_id}`);
              if (response.ok) {
                const content = await response.arrayBuffer();
                return {
                  id: transform.transform_object_id,
                  content,
                  type: transform.metadata.display_type_in_dashboard,
                  fileName: transform.metadata.file_name
                };
              }
              return null;
            });

          const transformResults = await Promise.all(transformPromises);

          // Update state with all transforms at once
          const newTransformData = {};
          transformResults.forEach(result => {
            if (result) {
              newTransformData[result.id] = {
                content: result.content,
                type: result.type,
                fileName: result.fileName
              };
            }
          });

          setTransformData(newTransformData);
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchFileData();
  }, [objectId, username]);

  // Render transform content based on type
  const renderTransformContent = (tabId) => {
    const transform = transformData[tabId];
    if (!transform) return null;

    if (transform.type === 'pdf') {
      return (
        <div className="aspect-[8.5/11] w-full bg-gray-100 dark:bg-gray-800 rounded-lg">
          <iframe
            src={URL.createObjectURL(new Blob([transform.content], { type: 'application/pdf' }))}
            className="w-full h-full rounded-lg"
          />
        </div>
      );
    }

    if (transform.type === 'monaco') {
      const content = new TextDecoder().decode(transform.content.slice(0, MAX_VIEW_SIZE));
      return (
        <MonacoContentViewer
          content={content}
          language={getMonacoLanguage(transform.fileName)}
          onLanguageChange={setCurrentLanguage}
        />
      );
    }

    if (transform.type === 'markdown') {
      const content = new TextDecoder().decode(transform.content.slice(0, MAX_VIEW_SIZE));
      return (
        <div className="border-t dark:border-gray-700 pt-6 dark:bg-dark-secondary p-4 rounded-lg">
          <div className="max-w-6xl mx-auto">
            <MarkdownRenderer content={content} />
          </div>
        </div>
      );
    }

    if (transform.type === 'image') {
      return (
        <div className="flex justify-center items-center bg-gray-100 dark:bg-gray-800 rounded-lg p-4">
          <img
            src={URL.createObjectURL(new Blob([transform.content]))}
            alt={transform.fileName}
            className="max-w-full max-h-[80vh] object-contain"
          />
        </div>
      );
    }

    if (transform.type === 'json') {
      const content = new TextDecoder().decode(transform.content);
      return (
        <MonacoContentViewer
          content={JSON.stringify(JSON.parse(content), null, 2)}
          language="json"
          onLanguageChange={() => { }}
          showLanguageSelect={false}
        />
      );
    }

    if (transform.type === 'csv') {
      const content = new TextDecoder().decode(transform.content);
      return (
        <div className="bg-gray-50 dark:bg-gray-900 rounded-lg">
          <CsvViewer content={content} />
        </div>
      );
    }

    return null;
  };

  // Render enrichment content as JSON
  const renderEnrichmentContent = (tabId) => {
    const enrichmentKey = tabId.replace('enrichment-', '');
    const enrichment = fileData?.enrichments?.find(e => e.module_name === enrichmentKey);
    if (!enrichment || !enrichment.result_data) return null;

    const jsonContent = JSON.stringify(enrichment.result_data, null, 2);
    return (
      <MonacoContentViewer
        content={jsonContent}
        language="json"
        onLanguageChange={() => { }}
        showLanguageSelect={false}
      />
    );
  };

  // "p"" to swap preview tabs, <- to go back, tab to scroll to file data area
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Only handle keyboard shortcuts when not in an input/textarea/monaco-editor
      const isEditingText = ['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName) ||
        document.activeElement.classList.contains('monaco-editor');

      if (!isEditingText) {
        if (e.key === 'Tab' && !e.ctrlKey && !e.metaKey && !e.altKey) {
          e.preventDefault();
          fileContentRef.current?.scrollIntoView({
            behavior: 'smooth',
            block: 'start',
            inline: 'nearest'
          });
        } else if (e.key === 'ArrowLeft' && !e.ctrlKey && !e.metaKey && !e.altKey) {
          e.preventDefault();
          handleBackClick();
        } else if (e.key === 'p' && !e.ctrlKey && !e.metaKey && !e.altKey) {
          e.preventDefault();
          const tabs = getAvailableTabs();
          const currentIndex = tabs.findIndex(tab => tab.id === activeTab);
          const nextIndex = (currentIndex + 1) % tabs.length;
          setActiveTab(tabs[nextIndex].id);
        } else if (e.key === 'f' && !e.ctrlKey && !e.metaKey && !e.altKey) {
          e.preventDefault();
          // Navigate to findings if count > 0
          const findingsCount = fileData?.findingsByObjectId_aggregate?.aggregate?.count || 0;
          if (findingsCount > 0) {
            navigate(`/findings?object_id=${fileData.object_id}`);
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activeTab, handleBackClick]);

  const handleDownload = async () => {
    // Handle the "Download" button action
    const response = await fetch(`/api/files/${fileData.object_id}`);
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileData.file_name;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  const handleContainerAnalysis = async () => {
    try {
      setContainerAnalysisStarted(true); // Hide the button immediately

      const response = await fetch(`/api/enrichments/container_contents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          object_id: fileData.object_id
        })
      });

      if (!response.ok) {
        throw new Error('Analysis request failed');
      }
      // Even if there's an error, we keep the button hidden since the analysis was triggered
    } catch (error) {
      console.error('Error triggering container analysis:', error);
      // We don't set containerAnalysisStarted back to false on error
      // because the request was still made
    }
  };

  const handleSummarization = async () => {
    try {
      setSummarizationStarted(true);

      // Determine which object_id to send
      let objectIdToSummarize;

      // If the file has an extracted_text transform, use that transform's object_id
      const extractedTextTransform = fileData?.transforms?.find(transform =>
        transform.type === 'extracted_text'
      );

      if (extractedTextTransform) {
        objectIdToSummarize = extractedTextTransform.transform_object_id;
      } else {
        // Otherwise use the file's object_id (for plaintext files)
        objectIdToSummarize = fileData.object_id;
      }

      // Fire-and-forget: don't await the response since analysis runs in background
      fetch(`/api/agents/text_summarizer`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          object_id: objectIdToSummarize
        })
      }).then(response => {
        if (!response.ok) {
          console.error('Text summarization request failed:', response.status);
        } else {
          console.log('Text summarization started successfully');
        }
      }).catch(error => {
        console.error('Error triggering text summarization:', error);
      });
    } catch (error) {
      console.error('Error triggering text summarization:', error);
      // Still keeping the button hidden as the request was made
    }
  };

  const handleCredentialAnalysis = async () => {
    try {
      setCredentialAnalysisStarted(true);

      // Determine which object_id to send
      let objectIdToAnalyze;

      // If the file has an extracted_text transform, use that transform's object_id
      const extractedTextTransform = fileData?.transforms?.find(transform =>
        transform.type === 'extracted_text'
      );

      if (extractedTextTransform) {
        objectIdToAnalyze = extractedTextTransform.transform_object_id;
      } else {
        // Otherwise use the file's object_id (for plaintext files)
        objectIdToAnalyze = fileData.object_id;
      }
      console.error("objectIdToAnalyze", objectIdToAnalyze);

      // Fire-and-forget: don't await the response since analysis runs in background
      fetch(`/api/agents/llm_credential_analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          object_id: objectIdToAnalyze
        })
      }).then(response => {
        if (!response.ok) {
          console.error('LLM credential analysis request failed:', response.status);
        } else {
          console.log('LLM credential analysis started successfully');
        }
      }).catch(error => {
        console.error('Error triggering LLM credential analysis:', error);
      });
    } catch (error) {
      console.error('Error triggering LLM credential analysis:', error);
      // Still keeping the button hidden as the request was made
    }
  };

  const handleDotNetAnalysis = () => {
    // Show confirmation dialog
    setShowConfirmDialog(true);
  };

  const handleConfirmAnalysis = async () => {
    setShowConfirmDialog(false);

    try {
      setDotnetAnalysisStarted(true);

      // Show success message immediately
      setShowSuccessDialog(true);

      // Fire-and-forget: don't await the response since analysis runs in background
      fetch(`/api/agents/dotnet_analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          object_id: fileData.object_id
        })
      }).then(response => {
        if (!response.ok) {
          console.error('.NET analysis request failed:', response.status);
        } else {
          console.log('.NET analysis started successfully');
        }
      }).catch(error => {
        console.error('Error triggering .NET analysis:', error);
      });

    } catch (error) {
      console.error('Error triggering .NET analysis:', error);
    }
  };

  const handleCancelAnalysis = () => {
    setShowConfirmDialog(false);
  };

  const handleTranslation = () => {
    // Show translation dialog
    setShowTranslateDialog(true);
  };

  const handleConfirmTranslation = async () => {
    setShowTranslateDialog(false);

    try {
      setTranslationStarted(true);

      // Always use the original file's object_id
      // The backend will figure out where to read the text from
      const objectIdToTranslate = fileData.object_id;

      // Fire-and-forget: don't await the response since translation runs in background
      fetch(`/api/agents/translate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          object_id: objectIdToTranslate,
          target_language: targetLanguage
        })
      }).then(response => {
        if (!response.ok) {
          console.error('Translation request failed:', response.status);
        } else {
          console.log('Translation started successfully');
        }
      }).catch(error => {
        console.error('Error triggering translation:', error);
      });

    } catch (error) {
      console.error('Error triggering translation:', error);
    }
  };

  const handleCancelTranslation = () => {
    setShowTranslateDialog(false);
    setTargetLanguage('English'); // Reset to default
  };

  const renderContentTruncationAlert = () => {
    // used to display a nicely formatted warning if data was truncated
    if (!isContentTruncated) return null;

    return (
      <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4 mb-4">
        <p className="text-yellow-800 dark:text-yellow-200 text-sm">
          This view shows the first 1MB of the file content. To view the complete file, please download it or use the "View Raw" option.
        </p>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
        <p className="text-red-600 dark:text-red-400">Error loading file: {error}</p>
      </div>
    );
  }

  if (!fileData) {
    return <div className="text-gray-600 dark:text-gray-400">File not found</div>;
  }

  // Get the appropriate back button text
  const getBackButtonText = () => {
    if (isFromFile) {
      return 'Back to Previous File';
    } else if (isFromSearch) {
      return 'Back to Document Search';
    } else if (isFromFindings) {
      return 'Back to Findings';
    }
    return 'Back to Files';
  };

  return (
    <div className="space-y-1">
      <div className="flex justify-between items-center">
        <div className="flex items-center space-x-4">
          <button
            onClick={handleBackClick}
            className="flex items-center space-x-2 px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>{getBackButtonText()}</span>
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">{fileData?.file_name}</h1>
            <p className="text-gray-500 dark:text-gray-400">{fileData?.path}</p>
          </div>
        </div>
      </div>

      <div className="rounded-lg bg-blue-50 dark:bg-blue-900/20 border dark:border-gray-700 p-3">
        <p className="text-sm text-blue-600 dark:text-blue-400">
          Use ← to return to file list, [tab] to jump to preview, 'p' to cycle previews, and 'f' to jump to findings (if present)
        </p>
      </div>

      <FileDetailsSection
        fileData={fileData}
        setFileData={setFileData}
      />

      <div ref={fileContentRef} id="file-content-section">
        <Card className="bg-white dark:bg-dark-secondary shadow-lg transition-colors">
          <CardHeader className="pb-1 pt-1">
            <div className="flex items-center gap-3 py-3">
              <CardTitle className="text-gray-900 dark:text-gray-100">File Content</CardTitle>
              <button
                onClick={handleDownload}
                className="flex items-center space-x-2 px-2 py-1 bg-blue-600 dark:bg-blue-500 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition-colors"
              >
                <Download className="w-4 h-4" />
                <span>Download</span>
              </button>
              {activeTab === 'text' && (
                <EncodingSelector
                  initialEncoding={detectedEncoding}
                  onEncodingChange={(encoding) => {
                    if (fileContent) {
                      const decoder = new TextDecoder(encoding);
                      setTextContent(decoder.decode(fileContent.slice(0, MAX_VIEW_SIZE)));
                    }
                  }}
                />
              )}
              <button
                onClick={() => navigate(`/findings?object_id=${fileData.object_id}`)}
                className={`${(fileData.findingsByObjectId_aggregate?.aggregate?.count || 0) > 0
                  ? 'bg-red-600 hover:bg-red-700'
                  : 'bg-gray-600 hover:bg-gray-700'
                  } text-white px-4 py-1.5 rounded-lg transition-colors text-sm font-medium`}
              >
                Findings: {fileData.findingsByObjectId_aggregate?.aggregate?.count || 0}
              </button>
              {shouldShowContainerAnalysisButton() && (
                <button
                  onClick={handleContainerAnalysis}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded-lg transition-colors text-sm font-medium"
                >
                  Extract/Process Container Contents
                </button>
              )}
              {shouldShowSummarizationButton() && (
                <button
                  onClick={handleSummarization}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded-lg transition-colors text-sm font-medium"
                >
                  Summarize Document Text (via LLM)
                </button>
              )}
              {shouldShowCredentialAnalysisButton() && (
                <button
                  onClick={handleCredentialAnalysis}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded-lg transition-colors text-sm font-medium"
                >
                  Extract Credentials (via LLM)
                </button>
              )}
              {shouldShowDotNetAnalysisButton() && (
                <button
                  onClick={handleDotNetAnalysis}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded-lg transition-colors text-sm font-medium"
                >
                  Analyze .NET Assembly (via LLM)
                </button>
              )}
              {shouldShowTranslationButton() && (
                <button
                  onClick={handleTranslation}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded-lg transition-colors text-sm font-medium"
                >
                  Translate Document (via LLM)
                </button>
              )}
            </div>
            {fileData?.size > 10 * 1024 * 1024 && (
              <CardDescription className="text-yellow-600 dark:text-yellow-400 mt-1">
                File is too large to view directly. Maximum size is 10MB.
              </CardDescription>
            )}
          </CardHeader>
          <CardContent className="pt-1">
            {isContentTruncated && renderContentTruncationAlert()}
            <Tabs
              value={activeTab}
              onValueChange={setActiveTab}
              className="w-full"
            >
              <TabsList className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 h-10">
                {getAvailableTabs().map(tab => (
                  <TabsTrigger
                    key={tab.id}
                    value={tab.id}
                    className="data-[state=active]:bg-white data-[state=active]:text-gray-900 dark:data-[state=active]:bg-gray-800 dark:data-[state=active]:text-gray-100 text-gray-600 dark:text-gray-400 h-9"
                  >
                    <tab.icon className="w-4 h-4 mr-2" />
                    {tab.label}
                  </TabsTrigger>
                ))}

                <div className="ml-2 border-l border-gray-200 dark:border-gray-700 pl-2 flex space-x-2">
                  <button
                    onClick={() => window.open(`/api/files/${fileData?.object_id}?raw=True`, '_blank')}
                    className="inline-flex items-center justify-center whitespace-nowrap rounded-sm px-3 h-9 text-sm font-medium text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                  >
                    <Eye className="w-4 h-4 mr-2" />
                    View Raw
                  </button>

                  {getDownloadableTransforms().map(transform => {
                    const isZipTransform = transform.metadata.file_name && transform.metadata.file_name.endsWith('.zip');
                    const buttonText = isZipTransform ? "View" : "Download";
                    const buttonIcon = isZipTransform ? <Eye className="w-4 h-4 mr-2" /> : <Download className="w-4 h-4 mr-2" />;

                    return (
                      <button
                        key={transform.transform_object_id}
                        onClick={() => {
                          if (isZipTransform) {
                            // Navigate to file view page for zip files
                            window.location.href = `/files/${transform.transform_object_id}`;
                          } else {
                            // Download other file types
                            const a = document.createElement('a');
                            a.href = `/api/files/${transform.transform_object_id}?name=${transform.metadata.file_name}`;
                            document.body.appendChild(a);
                            a.click();
                            document.body.removeChild(a);
                          }
                        }}
                        className="inline-flex items-center justify-center whitespace-nowrap rounded-sm px-3 h-9 text-sm font-medium text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                      >
                        {buttonIcon}
                        {buttonText} {transform.metadata.display_title || transform.type}
                      </button>
                    );
                  })}
                </div>
              </TabsList>

              {/* Render tab content */}
              {getAvailableTabs().map(tab => (
                <TabsContent key={tab.id} value={tab.id} className="mt-2">
                  {tab.id === 'preview' ? (
                    hasPreviewableImage ? (
                      <div className="w-full flex justify-center bg-gray-100 dark:bg-gray-800 rounded-lg p-4">
                        <img
                          src={URL.createObjectURL(new Blob([fileContent], { type: fileData.mime_type }))}
                          alt={fileData.file_name}
                          className="max-w-full max-h-[800px] object-contain"
                        />
                      </div>
                    ) : (
                      <div className="aspect-[8.5/11] w-full bg-gray-100 dark:bg-gray-800 rounded-lg">
                        <iframe
                          src={URL.createObjectURL(new Blob([pdfContent], { type: 'application/pdf' }))}
                          className="w-full h-full rounded-lg"
                        />
                      </div>
                    )
                  ) : tab.id === 'zip-explorer' ? (
                    <div className="h-[600px]">
                      <ZipFileViewer
                        fileBuffer={fileContent}
                        fileName={fileData.file_name}
                      />
                    </div>
                  ) : tab.id === 'sccm-log' ? (
                    <SCCMLogViewer
                      fileContent={textContent}
                      fileName={fileData.file_name}
                    />
                  ) : tab.id === 'sqlite-explorer' ? (
                    <div className="h-[600px]">
                      <SQLiteViewer
                        fileBuffer={fileContent}
                        fileName={fileData.file_name}
                      />
                    </div>
                  ) : tab.id === 'csv-explorer' ? (
                    <CsvViewer
                      content={textContent || (fileData?.is_plaintext && fileContent ?
                        new TextDecoder().decode(fileContent.slice(0, MAX_VIEW_SIZE)) :
                        'No CSV content available')}
                    />
                  ) : tab.id === 'text' ? (
                    fileData?.mime_type === 'application/json' ? (
                      <MonacoContentViewer
                        content={(() => {
                          try {
                            const jsonContent = textContent || (fileData?.is_plaintext && fileContent ?
                              new TextDecoder().decode(fileContent.slice(0, MAX_VIEW_SIZE)) :
                              '{}');
                            return JSON.stringify(JSON.parse(jsonContent || '{}'), null, 2);
                          } catch (e) {
                            return textContent || (fileData?.is_plaintext && fileContent ?
                              new TextDecoder().decode(fileContent.slice(0, MAX_VIEW_SIZE)) :
                              'Invalid JSON');
                          }
                        })()}
                        language="json"
                        onLanguageChange={() => { }}
                        showLanguageSelect={false}
                      />
                    ) : fileData?.mime_type === 'text/csv' || fileData?.file_name.endsWith('.csv') ? (
                      <CsvViewer
                        content={textContent || (fileData?.is_plaintext && fileContent ?
                          new TextDecoder().decode(fileContent.slice(0, MAX_VIEW_SIZE)) :
                          'No CSV content available')}
                      />
                    ) : (
                      <MonacoContentViewer
                        content={textContent || (fileData?.is_plaintext && fileContent ?
                          new TextDecoder().decode(fileContent.slice(0, MAX_VIEW_SIZE)) :
                          'No text content available')}
                        language={currentLanguage}
                        onLanguageChange={setCurrentLanguage}
                      />
                    )
                  ) : tab.id === 'hex' ? (
                    <MonacoContentViewer
                      content={fileContent ? createHexView(fileContent) : 'File content not available or too large'}
                      language="plaintext"
                      onLanguageChange={() => { }}
                      showLanguageSelect={false}
                    />
                  ) : tab.type === 'enrichment' ? (
                    renderEnrichmentContent(tab.id)
                  ) : (
                    renderTransformContent(tab.id)
                  )}
                </TabsContent>
              ))}
            </Tabs>
          </CardContent>
        </Card>
      </div>

      <LinkedFilesSection
        filePath={fileData?.path}
        source={fileData?.source}
      />

      <EnrichmentStatusSection objectId={objectId} />

      {/* Confirmation Dialog */}
      <Dialog open={showConfirmDialog} onOpenChange={setShowConfirmDialog}>
        <div className="text-center">
          <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">
            Confirm .NET Analysis
          </h3>
          <p className="text-gray-600 dark:text-gray-300 mb-6">
            This could take a bit of time and tokens, continue?
          </p>
          <div className="flex gap-3 justify-center">
            <button
              onClick={handleCancelAnalysis}
              className="px-4 py-2 bg-gray-300 hover:bg-gray-400 text-gray-800 rounded-lg transition-colors"
            >
              No
            </button>
            <button
              onClick={handleConfirmAnalysis}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              Yes
            </button>
          </div>
        </div>
      </Dialog>

      {/* Success Dialog */}
      <Dialog open={showSuccessDialog} onOpenChange={setShowSuccessDialog}>
        <div className="text-center">
          <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">
            Analysis Started
          </h3>
          <p className="text-gray-600 dark:text-gray-300 mb-6">
            Analysis started, results will appear here when completed
          </p>
          <button
            onClick={() => setShowSuccessDialog(false)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            OK
          </button>
        </div>
      </Dialog>

      {/* Translation Dialog */}
      <Dialog open={showTranslateDialog} onOpenChange={setShowTranslateDialog}>
        <div className="text-center">
          <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">
            Translate Document
          </h3>
          <p className="text-gray-600 dark:text-gray-300 mb-4">
            Enter the target language for translation:
          </p>
          <input
            type="text"
            value={targetLanguage}
            onChange={(e) => setTargetLanguage(e.target.value)}
            className="w-full px-4 py-2 mb-6 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="English"
          />
          <div className="flex gap-3 justify-center">
            <button
              onClick={handleCancelTranslation}
              className="px-4 py-2 bg-gray-300 hover:bg-gray-400 text-gray-800 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleConfirmTranslation}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              Translate
            </button>
          </div>
        </div>
      </Dialog>
    </div>
  );
};

export default FileViewer;
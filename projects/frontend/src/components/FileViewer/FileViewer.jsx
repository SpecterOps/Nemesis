import MarkdownRenderer from '@/components/shared/MarkdownRenderer';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import Dialog from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useUser } from '@/contexts/UserContext';
import { isEditableTarget } from '@/hooks/pagedList';
import { cachedFetch } from '@/utils/fileCache';
import { createClient } from 'graphql-ws';
import { Archive, ArrowLeft, ChevronDown, Database, Download, Eye, File, FileText, Image } from 'lucide-react';
import { LoadingState } from '@/components/shared/LoadingSpinner';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { BlobFrame, BlobImage } from './blobUrl';
import CsvViewer from './CsvViewer';
import { useLazyFileContent } from './useLazyFileContent';
import EnrichmentStatusSection from './EnrichmentStatusSection';
import FileDetailsSection from './FileDetailsSection';
import { getMonacoLanguage } from './languageMap';
import LinkedFilesSection from './LinkedFilesSection';
import MonacoContentViewer from './MonacoViewer';
import SCCMLogViewer from './SCCMLogViewer';
import SQLiteViewer from './SQLiteViewer';
import ZipFileViewer from './ZipFileViewer';


const MAX_VIEW_SIZE = 10 * 1024 * 1024; // 10MB preview/display limit
const MAX_RENDERABLE_VIEW_SIZE = 100 * 1024 * 1024; // 100MB limit for sqlite/zip/etc.

// Transforms produced on files derived from this one (e.g. a summary of extracted_plaintext.txt).
// Queried from the transforms side so a container with 100k+ children doesn't return one row per child.
const DERIVED_TRANSFORM_TYPES = ['text_summary', 'text_translation', 'llm_extracted_credentials'];
const DERIVED_TRANSFORMS_SELECTION = `
  derived_transforms: transforms(where: {
    type: {_in: ${JSON.stringify(DERIVED_TRANSFORM_TYPES)}},
    files_enriched: {originating_object_id: {_eq: $objectId}}
  }) {
    metadata
    type
    transform_object_id
  }
`;

// Signature of the subscription payload, used to skip refetches when nothing relevant changed
const transformsSignature = (updatedAt, transforms) =>
  `${updatedAt}|${(transforms || []).map(t => `${t.transform_object_id}:${t.type}`).sort().join(',')}`;

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

const isSCCMLogFile = (fileName, content) => {
  if (!content) return false;
  // Only look at the first line (content can be a 10MB preview; avoid splitting all of it)
  const newline = content.indexOf('\n');
  const firstLine = newline === -1 ? content : content.slice(0, newline);
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
          {/* Click-outside catcher (mouse only; the toggle button and options stay keyboard accessible) */}
          <div
            role="presentation"
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
  const [fileData, setFileData] = useState(null);
  const [pdfContent, setPdfContent] = useState(null);
  const [textContent, setTextContent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [currentLanguage, setCurrentLanguage] = useState('plaintext');
  const [isContentTruncated, setIsContentTruncated] = useState(false);
  const fileContentRef = useRef(null);
  const [transformData, setTransformData] = useState({});
  const { username } = useUser();
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

  const [detectedEncoding, setDetectedEncoding] = useState('utf-8');

  const {
    previewContent, fullFileContent, previewError, fullFileError,
    isPreviewLoading, isFullFileLoading, fetchPreviewContent, fetchFullFile,
    setPreviewContent, setFullFileContent
  } = useLazyFileContent(objectId, fileData);

  const initialTabSet = useRef(false);
  const [tabInitialized, setTabInitialized] = useState(false);
  const lastTransformsSignatureRef = useRef(null);


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

    if (objectId && username) {
      recordFileView(objectId);
    }
  }, [objectId, username]);

  useEffect(() => {
    if (!objectId) return;
    lastTransformsSignatureRef.current = null;

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
            updated_at
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
          next: (/** @type {{ data?: any }} */ { data }) => {
            if (data?.files_enriched && data.files_enriched.length > 0) {
              const updatedFile = data.files_enriched[0];

              // The first snapshot normally matches what the initial query already loaded;
              // only refetch when the file or its transforms actually changed.
              // Before the initial query finishes there is nothing to merge into (and that
              // query already includes these transforms).
              if (lastTransformsSignatureRef.current === null) return;
              const signature = transformsSignature(updatedFile.updated_at, updatedFile.transforms);
              if (signature === lastTransformsSignatureRef.current) return;
              lastTransformsSignatureRef.current = signature;

              // When main file updates, re-fetch everything including derived transforms
              // This is simpler than trying to maintain sync
              const refetchData = async () => {
                try {
                  const response = await fetch('/hasura/v1/graphql', {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
                    },
                    body: JSON.stringify({
                      query: `
                        query GetDerivedFileTransforms($objectId: uuid!) {
                          ${DERIVED_TRANSFORMS_SELECTION}
                        }
                      `,
                      variables: { objectId }
                    })
                  });

                  if (response.ok) {
                    const result = await response.json();
                    const derivedTransforms = result.data?.derived_transforms || [];
                    const allTransforms = [...(updatedFile.transforms || []), ...derivedTransforms];

                    // Update fileData with merged transforms
                    setFileData(prev => (prev ? {
                      ...prev,
                      transforms: allTransforms
                    } : prev));

                    // Register tab metadata for new displayable transforms (content loads lazily);
                    // the functional update below skips entries whose content was already fetched
                    const newTransforms = allTransforms.filter(isDisplayableTransform);

                    newTransforms.forEach(transform => {
                      setTransformData(prev => {
                        const existing = prev[transform.transform_object_id];
                        if (existing?.content) return prev; // Don't overwrite fetched content
                        return {
                          ...prev,
                          [transform.transform_object_id]: {
                            content: null,
                            type: transform.metadata.display_type_in_dashboard,
                            fileName: transform.metadata.file_name
                          }
                        };
                      });
                    });
                  }
                } catch (err) {
                  console.error('Error fetching derived transforms:', err);
                }
              };

              refetchData();
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


  const handleBackClick = () => {
    if (isFromFile) {
      // Opened from another file's linked-files list: return to that file
      navigate(-1);
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


  const hasPreviewableImage = Boolean(fileData && isDisplayableImage(fileData.file_name, fileData.mime_type));
  const hasPreviewableContent = Boolean(pdfContent || hasPreviewableImage || (fileData && fileData.mime_type === 'application/pdf'));

  // helper to get the file view tabs available
  const getAvailableTabs = () => {
    const tabs = [];

    // Add preview tab if content is previewable
    if (hasPreviewableContent) {
      tabs.push({ id: 'preview', type: 'preview', label: 'Preview', icon: Eye });
    }

    // Add ZIP explorer if file is a ZIP
    if (fileData && isZipFile(fileData.file_name, fileData.mime_type)) {
      tabs.push({ id: 'zip-explorer', type: 'zip', label: 'ZIP Explorer', icon: Archive });
    }

    // add SQLite explorer if it's a sqlite file
    if (fileData && isSqliteFile(fileData.file_name, fileData.mime_type)) {
      tabs.push({ id: 'sqlite-explorer', type: 'sqlite', label: 'SQLite Explorer', icon: Database });
    }

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
        tabs.push({
          id: `enrichment-${enrichment.module_name}`,
          type: 'enrichment',
          label: `Enrichment - ${enrichment.module_name}`,
          icon: FileText
        });
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

  const [transformsLoading, setTransformsLoading] = useState({});
  const transformFetchedRef = useRef({});
  const transformFullFetchedRef = useRef({});
  const [enrichmentExpanded, setEnrichmentExpanded] = useState({});
  // Enrichment result_data is loaded per tab on demand (can be many MB for containers);
  // cached as { [module_name]: { json: string } | { error } | { loading: true } }
  const [enrichmentResults, setEnrichmentResults] = useState({});
  const enrichmentFetchedRef = useRef({});
  useEffect(() => {
    setEnrichmentResults({});
    enrichmentFetchedRef.current = {};
  }, [objectId]);

  const fetchTransformContent = useCallback(async (tabId) => {
    if (transformFetchedRef.current[tabId]) return;
    const transform = transformData[tabId];
    if (!transform || transform.content) return;

    transformFetchedRef.current[tabId] = true;
    setTransformsLoading(prev => ({ ...prev, [tabId]: true }));

    const textBasedTypes = ['monaco', 'markdown', 'csv'];
    const isTextBased = textBasedTypes.includes(transform.type) || transform.type === 'csv';
    const url = isTextBased
      ? `/api/files/${tabId}?length=${MAX_VIEW_SIZE}`
      : `/api/files/${tabId}`;

    try {
      const response = await cachedFetch(url);
      if (response.ok) {
        const content = await response.arrayBuffer();
        setTransformData(prev => ({
          ...prev,
          [tabId]: { ...prev[tabId], content }
        }));
      } else {
        console.error(`Failed to fetch transform content: ${response.status}`);
        transformFetchedRef.current[tabId] = false; // Allow retry
      }
    } catch (err) {
      console.error('Error fetching transform content:', err);
      transformFetchedRef.current[tabId] = false; // Allow retry
    } finally {
      setTransformsLoading(prev => ({ ...prev, [tabId]: false }));
    }
  }, [transformData]);

  const fetchFullTransformContent = useCallback(async (tabId) => {
    if (transformFullFetchedRef.current[tabId]) return;
    transformFullFetchedRef.current[tabId] = true;
    setTransformsLoading(prev => ({ ...prev, [tabId]: true }));

    try {
      const response = await cachedFetch(`/api/files/${tabId}`);
      if (response.ok) {
        const content = await response.arrayBuffer();
        setTransformData(prev => ({
          ...prev,
          [tabId]: { ...prev[tabId], content }
        }));
      } else {
        console.error(`Failed to fetch full transform content: ${response.status}`);
        transformFullFetchedRef.current[tabId] = false;
      }
    } catch (err) {
      console.error('Error fetching full transform content:', err);
      transformFullFetchedRef.current[tabId] = false;
    } finally {
      setTransformsLoading(prev => ({ ...prev, [tabId]: false }));
    }
  }, []);

  const fetchEnrichmentResult = useCallback(async (moduleName) => {
    if (!objectId || enrichmentFetchedRef.current[moduleName]) return;
    enrichmentFetchedRef.current[moduleName] = true;
    setEnrichmentResults(prev => ({ ...prev, [moduleName]: { loading: true } }));
    try {
      const response = await fetch('/hasura/v1/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-hasura-admin-secret': window.ENV.HASURA_ADMIN_SECRET,
        },
        body: JSON.stringify({
          query: `
            query GetEnrichmentResult($objectId: uuid!, $moduleName: String!) {
              enrichments(where: {object_id: {_eq: $objectId}, module_name: {_eq: $moduleName}}, limit: 1) {
                result_data
              }
            }
          `,
          variables: { objectId, moduleName }
        })
      });
      if (!response.ok) throw new Error(`Network response error: ${response.status}`);
      const result = await response.json();
      if (result.errors) throw new Error(result.errors[0].message);
      const resultData = result.data.enrichments[0]?.result_data ?? null;
      // Stringify once here instead of on every render
      setEnrichmentResults(prev => ({ ...prev, [moduleName]: { json: JSON.stringify(resultData, null, 2) } }));
    } catch (err) {
      console.error('Error fetching enrichment result:', err);
      enrichmentFetchedRef.current[moduleName] = false;
      setEnrichmentResults(prev => ({ ...prev, [moduleName]: { error: err.message } }));
    }
  }, [objectId]);

  const handleTabChange = useCallback((tabId) => {
    setActiveTab(tabId);
    if (tabId.startsWith('enrichment-')) {
      fetchEnrichmentResult(tabId.replace('enrichment-', ''));
    }
    if (['zip-explorer', 'sqlite-explorer'].includes(tabId) && !fullFileContent && !isFullFileLoading) {
      fetchFullFile();
    }
    if (tabId === 'preview' && !fullFileContent && !isFullFileLoading &&
      fileData && isDisplayableImage(fileData.file_name, fileData.mime_type)) {
      fetchFullFile();
    }
    // Hex tab — fetch preview content (first 10MB) on activation
    if (tabId === 'hex' && !previewContent && !isPreviewLoading) {
      fetchPreviewContent();
    }
    // Transform tabs — fetch content on activation
    if (transformData[tabId] && !transformData[tabId].content && !transformsLoading[tabId]) {
      fetchTransformContent(tabId);
    }
  }, [fullFileContent, isFullFileLoading, fileData, fetchFullFile, previewContent, isPreviewLoading, fetchPreviewContent, transformData, transformsLoading, fetchTransformContent, fetchEnrichmentResult]);

  // Handler to disable truncation and show full file content in the text view
  const handleShowFullContent = useCallback(async () => {
    if (fullFileContent) {
      // Already have full content, just re-decode
      const decoder = new TextDecoder(detectedEncoding);
      setTextContent(decoder.decode(fullFileContent));
      setIsContentTruncated(false);
      return;
    }
    // Need to fetch full file first
    await fetchFullFile();
  }, [fullFileContent, detectedEncoding, fetchFullFile]);

  // When fullFileContent becomes available after handleShowFullContent triggered a fetch,
  // update textContent if it was truncated
  useEffect(() => {
    if (fullFileContent && isContentTruncated && fileData?.is_plaintext) {
      const decoder = new TextDecoder(detectedEncoding);
      setTextContent(decoder.decode(fullFileContent));
      setIsContentTruncated(false);
    }
  }, [fullFileContent, isContentTruncated, detectedEncoding, fileData]);

  // Set the initial tab based on transform metadata and fallback order
  useEffect(() => {
    if (initialTabSet.current) return;
    if (fileData || pdfContent) {
      const tabs = getAvailableTabs();

      // First check if the file is a ZIP file
      if (fileData && isZipFile(fileData.file_name, fileData.mime_type)) {
        initialTabSet.current = true;
        setTabInitialized(true);
        setActiveTab('zip-explorer');
        return;
      }

      // Then check for .zip transforms
      if (fileData?.transforms) {
        const zipTransform = fileData.transforms.find(transform =>
          transform.metadata?.file_name && transform.metadata.file_name.endsWith('.zip')
        );
        if (zipTransform) {
          initialTabSet.current = true;
          setTabInitialized(true);
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
          initialTabSet.current = true;
          setTabInitialized(true);
          setActiveTab(pdfTransform.transform_object_id);
          return;
        }

        // Then check for transforms with default_display=true
        const defaultTransform = fileData.transforms.find(transform =>
          isDisplayableTransform(transform) && transform.metadata?.default_display === true
        );
        if (defaultTransform) {
          initialTabSet.current = true;
          setTabInitialized(true);
          setActiveTab(defaultTransform.transform_object_id);
          return;
        }
      }

      // Then follow fallback order: Preview -> Text -> Hex
      if (hasPreviewableContent) {
        initialTabSet.current = true;
        setTabInitialized(true);
        setActiveTab('preview');
      } else if (tabs.find(tab => tab.id === 'text')) {
        initialTabSet.current = true;
        setTabInitialized(true);
        setActiveTab('text');
      }
      initialTabSet.current = true;
      setTabInitialized(true);
      // If no other conditions met, it will stay as 'hex'
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one-shot (guarded by initialTabSet); getAvailableTabs is derived from these same values
  }, [fileData, pdfContent, hasPreviewableContent]);

  // Trigger lazy fetch for auto-selected tabs (ZIP, SQLite, image preview, hex).
  // Only runs after initial tab selection to avoid eagerly fetching for the
  // default 'hex' tab before a better tab has been chosen.
  // (Keyed on state, not the ref: the ref flips during the same commit in which activeTab is
  // still the default 'hex', which used to trigger a wasted 10MB hex preview download.)
  useEffect(() => {
    if (!fileData || !tabInitialized) return;
    if (['zip-explorer', 'sqlite-explorer'].includes(activeTab) && !fullFileContent && !isFullFileLoading) {
      fetchFullFile();
    }
    if (activeTab === 'preview' && !fullFileContent && !isFullFileLoading &&
      isDisplayableImage(fileData.file_name, fileData.mime_type)) {
      fetchFullFile();
    }
    // Hex tab — fetch preview content (first 10MB) on activation
    if (activeTab === 'hex' && !previewContent && !isPreviewLoading) {
      fetchPreviewContent();
    }
    // Auto-selected transform tabs (e.g. converted_pdf)
    if (transformData[activeTab] && !transformData[activeTab].content && !transformsLoading[activeTab]) {
      fetchTransformContent(activeTab);
    }
    if (activeTab.startsWith('enrichment-')) {
      fetchEnrichmentResult(activeTab.replace('enrichment-', ''));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs on tab/data changes only; keying on the loading flags would retry a failed fetch in a loop
  }, [activeTab, fileData, transformData, tabInitialized]);

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
                  created_at
                  updated_at
                }
                transforms {
                  metadata
                  type
                  transform_object_id
                }
                findingsByObjectId_aggregate {
                  aggregate {
                    count
                  }
                }
              }
              ${DERIVED_TRANSFORMS_SELECTION}
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

        // Merge transforms from derived files (like extracted_plaintext.txt)
        lastTransformsSignatureRef.current = transformsSignature(file.updated_at, file.transforms);
        const derivedTransforms = result.data.derived_transforms || [];
        file.transforms = [...(file.transforms || []), ...derivedTransforms];

        setFileData(file);
        setCurrentLanguage(getMonacoLanguage(file.file_name, file.mime_type));

        // Fetch file content conditionally based on file type
        if (file.size <= MAX_RENDERABLE_VIEW_SIZE) {
          if (file.mime_type === 'application/pdf') {
            // PDF: fetch full file immediately for preview
            const contentResponse = await cachedFetch(`/api/files/${file.object_id}`);
            if (contentResponse.ok) {
              const buffer = await contentResponse.arrayBuffer();
              setPdfContent(buffer);
            }
          } else if (file.is_plaintext) {
            // Plaintext: fetch 1MB preview for text tab
            const previewUrl = file.size > MAX_VIEW_SIZE
              ? `/api/files/${file.object_id}?length=${MAX_VIEW_SIZE}`
              : `/api/files/${file.object_id}`;
            const contentResponse = await cachedFetch(previewUrl);
            if (contentResponse.ok) {
              const buffer = await contentResponse.arrayBuffer();
              setPreviewContent(buffer);

              // Detect encoding from BOM
              const detected = detectEncodingFromBOM(buffer);
              setDetectedEncoding(detected);

              // Decode content with detected encoding
              const decoder = new TextDecoder(detected);
              setTextContent(decoder.decode(buffer.slice(0, MAX_VIEW_SIZE)));
              setIsContentTruncated(file.size > MAX_VIEW_SIZE);

              // If file fits in 1MB, it's also the full content
              if (file.size <= MAX_VIEW_SIZE) {
                setFullFileContent(buffer);
              }
            }
          }
          // Binary files: hex tab will lazy-fetch preview on activation
        }

        // Store transform metadata without fetching content — content is
        // lazy-loaded when the user clicks the tab.
        if (file.transforms) {
          const newTransformData = {};
          file.transforms
            .filter(isDisplayableTransform)
            .forEach(transform => {
              newTransformData[transform.transform_object_id] = {
                content: null,
                type: transform.metadata.display_type_in_dashboard,
                fileName: transform.metadata.file_name
              };
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
  }, [objectId, username, setPreviewContent, setFullFileContent]);

  // Render transform content based on type
  const renderTransformContent = (tabId) => {
    const transform = transformData[tabId];
    if (!transform) return null;

    if (!transform.content) {
      if (transformsLoading[tabId]) {
        return <LoadingState message="Loading content..." />;
      }
      // Loading finished but content is null — show retry
      return (
        <div className="flex flex-col items-center justify-center py-12 text-gray-400">
          <p className="mb-3">Failed to load content</p>
          <button
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
            onClick={() => {
              transformFetchedRef.current[tabId] = false;
              fetchTransformContent(tabId);
            }}
          >
            Retry
          </button>
        </div>
      );
    }

    if (transform.type === 'pdf') {
      return (
        <div className="h-[80vh] min-h-[480px] w-full bg-gray-100 dark:bg-gray-800 rounded-lg">
          <BlobFrame
            title={`${transform.fileName || 'Transform'} (PDF)`}
            data={transform.content}
            type="application/pdf"
            className="w-full h-full rounded-lg"
          />
        </div>
      );
    }

    if (transform.type === 'monaco') {
      const content = new TextDecoder().decode(transform.content.slice(0, MAX_VIEW_SIZE));
      const isTruncated = transform.content.byteLength >= MAX_VIEW_SIZE && !transformFullFetchedRef.current[tabId];
      return (
        <MonacoContentViewer
          content={content}
          language={getMonacoLanguage(transform.fileName)}
          onLanguageChange={setCurrentLanguage}
          isTruncated={isTruncated}
          onShowFullContent={() => fetchFullTransformContent(tabId)}
          isLoadingFullContent={!!transformsLoading[tabId]}
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
          <BlobImage
            data={transform.content}
            alt={transform.fileName}
            className="max-w-full max-h-[80vh] object-contain"
          />
        </div>
      );
    }

    if (transform.type === 'json') {
      const content = new TextDecoder().decode(transform.content);
      const isTruncated = transform.content.byteLength >= MAX_VIEW_SIZE && !transformFullFetchedRef.current[tabId];
      let parsed;
      try { parsed = JSON.stringify(JSON.parse(content), null, 2); } catch { parsed = content; }
      return (
        <MonacoContentViewer
          content={parsed}
          language="json"
          onLanguageChange={() => { }}
          showLanguageSelect={false}
          isTruncated={isTruncated}
          onShowFullContent={() => fetchFullTransformContent(tabId)}
          isLoadingFullContent={!!transformsLoading[tabId]}
        />
      );
    }

    if (transform.type === 'csv') {
      const content = new TextDecoder().decode(transform.content);
      return (
        <div className="bg-gray-50 dark:bg-gray-900 rounded-lg">
          <CsvViewer content={content} fileName={transform.fileName} />
        </div>
      );
    }

    return null;
  };

  // Render enrichment content as JSON
  const renderEnrichmentContent = (tabId) => {
    const enrichmentKey = tabId.replace('enrichment-', '');
    const enrichment = fileData?.enrichments?.find(e => e.module_name === enrichmentKey);
    if (!enrichment) return null;

    const loaded = enrichmentResults[enrichmentKey];
    if (!loaded || loaded.loading) return <LoadingState message="Loading enrichment results..." />;
    if (loaded.error) {
      return (
        <div className="p-4 text-center">
          <p className="text-red-500 mb-2">Error loading enrichment: {loaded.error}</p>
          <button
            onClick={() => {
              enrichmentFetchedRef.current[enrichmentKey] = false;
              fetchEnrichmentResult(enrichmentKey);
            }}
            className="text-blue-500 hover:underline"
          >
            Retry
          </button>
        </div>
      );
    }

    const jsonContent = loaded.json;
    const isTruncated = jsonContent.length > MAX_VIEW_SIZE && !enrichmentExpanded[tabId];
    const displayContent = isTruncated ? jsonContent.slice(0, MAX_VIEW_SIZE) : jsonContent;
    return (
      <MonacoContentViewer
        content={displayContent}
        language="json"
        onLanguageChange={() => { }}
        showLanguageSelect={false}
        isTruncated={isTruncated}
        onShowFullContent={() => setEnrichmentExpanded(prev => ({ ...prev, [tabId]: true }))}
      />
    );
  };

  // Helper for the common loading → error → content pattern used by tabs that load full files
  const renderFullFileContent = (loadingMsg, renderContent) => {
    if (isFullFileLoading) return <LoadingState message={loadingMsg} />;
    if (fullFileError) {
      return (
        <div className="p-4 text-center">
          <p className="text-red-500 mb-2">Error loading file: {fullFileError}</p>
          <button onClick={fetchFullFile} className="text-blue-500 hover:underline">Retry</button>
        </div>
      );
    }
    if (fullFileContent) return renderContent();
    return <LoadingState message={loadingMsg} />;
  };

  // Helper to get text content for text/csv tabs
  const getTextContent = (fallback = 'No text content available') => {
    return textContent || (fileData?.is_plaintext && previewContent
      ? new TextDecoder().decode(previewContent.slice(0, MAX_VIEW_SIZE))
      : fallback);
  };

  // Per-tab-type render functions — keeps the main render clean
  const renderPreviewTab = () => {
    if (hasPreviewableImage) {
      return renderFullFileContent('Loading image...', () => (
        <div className="w-full flex justify-center bg-gray-100 dark:bg-gray-800 rounded-lg p-4">
          <BlobImage
            data={fullFileContent}
            type={fileData.mime_type}
            alt={fileData.file_name}
            className="max-w-full max-h-[800px] object-contain"
          />
        </div>
      ));
    }
    return (
      <div className="h-[80vh] min-h-[480px] w-full bg-gray-100 dark:bg-gray-800 rounded-lg">
        <BlobFrame
          title={`${fileData.file_name} (PDF preview)`}
          data={pdfContent}
          type="application/pdf"
          className="w-full h-full rounded-lg"
        />
      </div>
    );
  };

  const renderZipTab = () => renderFullFileContent('Loading ZIP file...', () => (
    <div className="h-[600px]">
      <ZipFileViewer fileBuffer={fullFileContent} fileName={fileData.file_name} />
    </div>
  ));

  const renderSqliteTab = () => renderFullFileContent('Loading SQLite database...', () => (
    <div className="h-[600px]">
      <SQLiteViewer fileBuffer={fullFileContent} fileName={fileData.file_name} />
    </div>
  ));

  const renderTextTab = () => {
    if (fileData?.mime_type === 'application/json') {
      let content;
      try {
        content = JSON.stringify(JSON.parse(getTextContent('{}') || '{}'), null, 2);
      } catch {
        content = getTextContent('Invalid JSON');
      }
      return (
        <MonacoContentViewer
          content={content}
          language="json"
          onLanguageChange={() => { }}
          showLanguageSelect={false}
          isTruncated={isContentTruncated}
          onShowFullContent={handleShowFullContent}
          isLoadingFullContent={isFullFileLoading}
        />
      );
    }
    if (fileData?.mime_type === 'text/csv' || fileData?.file_name.endsWith('.csv')) {
      return <CsvViewer content={getTextContent('No CSV content available')} />;
    }
    return (
      <MonacoContentViewer
        content={getTextContent()}
        language={currentLanguage}
        onLanguageChange={setCurrentLanguage}
        isTruncated={isContentTruncated}
        onShowFullContent={handleShowFullContent}
        isLoadingFullContent={isFullFileLoading}
      />
    );
  };

  const renderHexTab = () => {
    if (isPreviewLoading) return <LoadingState message="Loading hex view..." />;
    if (previewError) {
      return (
        <div className="p-4 text-center">
          <p className="text-red-500 mb-2">Error loading hex view: {previewError}</p>
          <button onClick={fetchPreviewContent} className="text-blue-500 hover:underline">Retry</button>
        </div>
      );
    }
    if (previewContent || fullFileContent) {
      return (
        <MonacoContentViewer
          content={createHexView(fullFileContent || previewContent)}
          language="plaintext"
          onLanguageChange={() => { }}
          showLanguageSelect={false}
          isTruncated={fileData?.size > MAX_VIEW_SIZE && !fullFileContent}
          onShowFullContent={fetchFullFile}
          isLoadingFullContent={isFullFileLoading}
        />
      );
    }
    return <LoadingState message="Loading hex view..." />;
  };

  const renderTabContent = (tab) => {
    switch (tab.id) {
      case 'preview': return renderPreviewTab();
      case 'zip-explorer': return renderZipTab();
      case 'sqlite-explorer': return renderSqliteTab();
      case 'sccm-log': return <SCCMLogViewer fileContent={textContent} fileName={fileData.file_name} />;
      case 'csv-explorer': return <CsvViewer content={getTextContent('No CSV content available')} />;
      case 'text': return renderTextTab();
      case 'hex': return renderHexTab();
      default:
        if (tab.type === 'enrichment') return renderEnrichmentContent(tab.id);
        return renderTransformContent(tab.id);
    }
  };

  // <- to go back, tab to scroll to file data area or cycle tabs if already in view, f to jump to findings
  const handleGlobalKeyDown = (e) => {
    // Only handle keyboard shortcuts when not in an input/textarea/monaco-editor
    const isEditingText = isEditableTarget(e.target) || isEditableTarget(document.activeElement);

    if (!isEditingText) {
      if (e.key === 'Tab' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();

        // Check if the file content section is already in view
        if (fileContentRef.current) {
          const rect = fileContentRef.current.getBoundingClientRect();
          // Element is considered in view if its top is within the viewport
          // Using a more lenient check: if the top is less than 100px from the top of viewport
          const isInView = rect.top >= -50 && rect.top <= 100;

          if (isInView) {
            // If already in view, cycle through tabs
            const tabs = getAvailableTabs();
            const currentIndex = tabs.findIndex(tab => tab.id === activeTab);
            const nextIndex = (currentIndex + 1) % tabs.length;
            handleTabChange(tabs[nextIndex].id);
          } else {
            // If not in view, scroll to it
            fileContentRef.current.scrollIntoView({
              behavior: 'smooth',
              block: 'start',
              inline: 'nearest'
            });
          }
        }
      } else if (e.key === 'ArrowLeft' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        handleBackClick();
      } else if (e.key === 'f' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        // Navigate to findings if count > 0
        const findingsCount = fileData?.findingsByObjectId_aggregate?.aggregate?.count || 0;
        if (findingsCount > 0) {
          navigate(`/findings?object_id=${fileData.object_id}`, { state: { fromFile: fileData.object_id } });
        }
      }
    }
  };

  // Subscribe once and dispatch to the latest handler (it reads the current tab/file state)
  const globalKeyDownRef = useRef(handleGlobalKeyDown);
  useEffect(() => {
    globalKeyDownRef.current = handleGlobalKeyDown;
  });
  useEffect(() => {
    const listener = (e) => globalKeyDownRef.current(e);
    window.addEventListener('keydown', listener);
    return () => window.removeEventListener('keydown', listener);
  }, []);

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
      <div className="rounded-lg bg-blue-50 dark:bg-blue-900/20 border dark:border-gray-700 p-1">
        <p className="text-sm text-blue-600 dark:text-blue-400">
          Use ← to return to file list, [tab] to jump to preview (or cycle tabs if already there), and &apos;f&apos; to jump to findings (if present)
        </p>
      </div>
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
                    if (previewContent) {
                      const decoder = new TextDecoder(encoding);
                      setTextContent(decoder.decode(previewContent.slice(0, MAX_VIEW_SIZE)));
                    }
                  }}
                />
              )}
              <button
                onClick={() => navigate(`/findings?object_id=${fileData.object_id}`, { state: { fromFile: fileData.object_id } })}
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
          </CardHeader>
          <CardContent className="pt-1">
            <Tabs
              value={activeTab}
              onValueChange={handleTabChange}
              className="w-full"
            >
              {/* Wrap instead of widening the page: files can have dozens of enrichment/transform tabs */}
              <TabsList className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 h-auto min-h-[2.5rem] flex-wrap justify-start">
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

                <div className="ml-2 border-l border-gray-200 dark:border-gray-700 pl-2 flex flex-wrap gap-2">
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
                  {renderTabContent(tab)}
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
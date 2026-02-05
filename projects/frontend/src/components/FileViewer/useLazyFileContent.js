import { useCallback, useRef, useState } from 'react';
import { cachedFetch } from '@/utils/fileCache';

const MAX_VIEW_SIZE = 10 * 1024 * 1024; // 10MB preview limit

/**
 * Custom hook for lazy file content fetching.
 * Manages preview content (1MB for hex/text) and full file content (for zip/sqlite/image).
 */
export function useLazyFileContent(objectId, fileData) {
  const [previewContent, setPreviewContent] = useState(null);
  const [fullFileContent, setFullFileContent] = useState(null);
  const [previewError, setPreviewError] = useState(null);
  const [fullFileError, setFullFileError] = useState(null);
  const [isPreviewLoading, setIsPreviewLoading] = useState(false);
  const [isFullFileLoading, setIsFullFileLoading] = useState(false);

  // Guards to prevent double-fire
  const previewFetchedRef = useRef(false);
  const fullFileFetchedRef = useRef(false);

  const fetchPreviewContent = useCallback(async () => {
    if (previewFetchedRef.current || !objectId) return;
    previewFetchedRef.current = true;
    setIsPreviewLoading(true);
    setPreviewError(null);

    try {
      const response = await cachedFetch(`/api/files/${objectId}?length=${MAX_VIEW_SIZE}`);
      if (!response.ok) throw new Error(`Failed to fetch preview: ${response.status}`);
      const buffer = await response.arrayBuffer();
      setPreviewContent(buffer);
      // If the file is small enough, also set it as the full content
      if (fileData && fileData.size <= MAX_VIEW_SIZE) {
        setFullFileContent(buffer);
        fullFileFetchedRef.current = true;
      }
    } catch (err) {
      setPreviewError(err.message);
      previewFetchedRef.current = false; // Allow retry on error
    } finally {
      setIsPreviewLoading(false);
    }
  }, [objectId, fileData]);

  const fetchFullFile = useCallback(async () => {
    if (fullFileFetchedRef.current || !objectId) return;
    fullFileFetchedRef.current = true;
    setIsFullFileLoading(true);
    setFullFileError(null);

    try {
      const response = await cachedFetch(`/api/files/${objectId}`);
      if (!response.ok) throw new Error(`Failed to fetch file: ${response.status}`);
      const buffer = await response.arrayBuffer();
      setFullFileContent(buffer);
      // If we don't have preview content yet, derive it
      if (!previewFetchedRef.current) {
        setPreviewContent(buffer);
        previewFetchedRef.current = true;
      }
    } catch (err) {
      setFullFileError(err.message);
      fullFileFetchedRef.current = false; // Allow retry on error
    } finally {
      setIsFullFileLoading(false);
    }
  }, [objectId]);

  const reset = useCallback(() => {
    setPreviewContent(null);
    setFullFileContent(null);
    setPreviewError(null);
    setFullFileError(null);
    setIsPreviewLoading(false);
    setIsFullFileLoading(false);
    previewFetchedRef.current = false;
    fullFileFetchedRef.current = false;
  }, []);

  return {
    previewContent,
    fullFileContent,
    previewError,
    fullFileError,
    isPreviewLoading,
    isFullFileLoading,
    fetchPreviewContent,
    fetchFullFile,
    setPreviewContent,
    setFullFileContent,
    reset,
  };
}

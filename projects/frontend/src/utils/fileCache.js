/**
 * In-memory cache for /api/files/* responses
 * Works with authenticated requests and self-signed certificates
 */

const isDev = import.meta.env.DEV;
const log = (...args) => isDev && console.log(...args);

class FileCache {
  constructor() {
    this.cache = new Map();
    this.pendingRequests = new Map(); // Track in-flight requests
    this.maxSize = 50; // Maximum number of files to cache
    this.maxFileSize = 50 * 1024 * 1024; // 50MB - don't cache files larger than this
    this.cacheDuration = 60 * 60 * 1000; // 1 hour in milliseconds
  }

  /**
   * Generate cache key from URL
   */
  getCacheKey(url) {
    const urlObj = new URL(url, window.location.origin);
    return urlObj.pathname + urlObj.search; // Include query string to differentiate range requests
  }

  /**
   * Check if a cache entry is still valid
   */
  isValid(entry) {
    const age = Date.now() - entry.timestamp;
    return age < this.cacheDuration;
  }

  /**
   * Get item from cache
   */
  async get(url) {
    const key = this.getCacheKey(url);
    const entry = this.cache.get(key);

    if (!entry) {
      return null;
    }

    if (!this.isValid(entry)) {
      log('[FileCache] Cache expired:', key);
      this.cache.delete(key);
      return null;
    }

    // Move to end (LRU)
    this.cache.delete(key);
    this.cache.set(key, entry);

    // Create a new Response from the stored blob to avoid body stream issues
    const blob = entry.blob;
    return new Response(blob, {
      status: entry.status,
      statusText: entry.statusText,
      headers: entry.headers
    });
  }

  /**
   * Add item to cache
   */
  async set(url, response) {
    const key = this.getCacheKey(url);

    // Clone the response to read it
    const responseClone = response.clone();

    // Read the response body as blob (more reliable than storing Response objects)
    const blob = await responseClone.blob();

    // Check actual blob size
    const fileSize = blob.size;

    // Don't cache if too large
    if (fileSize > this.maxFileSize) {
      log('[FileCache] File too large to cache:', key, `(${fileSize} bytes)`);
      return;
    }

    // Store blob and metadata separately to avoid Response stream issues
    const entry = {
      blob: blob,
      status: response.status,
      statusText: response.statusText,
      headers: new Headers(response.headers), // Clone headers
      timestamp: Date.now(),
      size: fileSize
    };

    this.cache.set(key, entry);
    log('[FileCache] Cached:', key, `(${fileSize} bytes)`);

    // Enforce size limit
    this.enforceSizeLimit();
  }

  /**
   * Remove oldest entries if cache is full (LRU)
   */
  enforceSizeLimit() {
    if (this.cache.size > this.maxSize) {
      // Get first (oldest) entry
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
      log('[FileCache] Pruned oldest entry:', firstKey);
    }
  }

  /**
   * Clear entire cache
   */
  clear() {
    this.cache.clear();
    log('[FileCache] Cache cleared');
  }

  /**
   * Get cache statistics
   */
  getStats() {
    const entries = Array.from(this.cache.entries()).map(([key, entry]) => ({
      key,
      size: entry.size,
      age: Date.now() - entry.timestamp,
      valid: this.isValid(entry)
    }));

    const totalSize = entries.reduce((sum, e) => sum + e.size, 0);

    return {
      entryCount: this.cache.size,
      maxSize: this.maxSize,
      totalSize,
      entries
    };
  }
}

// Create singleton instance
const fileCache = new FileCache();

/**
 * Enhanced fetch that uses the file cache with request deduplication
 * Drop-in replacement for fetch() for /api/files/* endpoints
 */
export async function cachedFetch(url, options = {}) {
  // Parse URL
  const urlObj = new URL(url, window.location.origin);

  // Only cache GET requests to /api/files/*
  const shouldCache =
    (!options.method || options.method === 'GET') &&
    urlObj.pathname.startsWith('/api/files/') &&
    !urlObj.searchParams.has('name'); // Don't cache downloads

  if (!shouldCache) {
    return fetch(url, options);
  }

  const cacheKey = fileCache.getCacheKey(url);

  // Check cache first
  const cachedResponse = await fileCache.get(url);
  if (cachedResponse) {
    return cachedResponse;
  }

  // Check if there's already a pending request for this URL
  if (fileCache.pendingRequests.has(cacheKey)) {
    log('[FileCache] Deduplicating request:', cacheKey);
    // Wait for the pending request to complete
    const { blob, status, statusText, headers } = await fileCache.pendingRequests.get(cacheKey);
    return new Response(blob, { status, statusText, headers: new Headers(headers) });
  }

  // Fetch from network
  log('[FileCache] Fetching from network:', cacheKey);

  // Read the body once; every caller (including deduplicated ones) gets its own Response built from
  // that blob, so a file too large to cache or an error response is never downloaded a second time.
  const fetchPromise = (async () => {
    const response = await fetch(url, options);
    const blob = await response.blob();
    const snapshot = {
      blob,
      status: response.status,
      statusText: response.statusText,
      headers: new Headers(response.headers),
    };
    if (response.ok) {
      await fileCache.set(url, new Response(blob, snapshot));
    }
    return snapshot;
  })();

  // Store the promise so concurrent requests can reuse it
  fileCache.pendingRequests.set(cacheKey, fetchPromise);

  try {
    const { blob, status, statusText, headers } = await fetchPromise;
    return new Response(blob, { status, statusText, headers: new Headers(headers) });
  } finally {
    // Remove from pending requests when done
    fileCache.pendingRequests.delete(cacheKey);
  }
}

// Export cache instance for debugging
export { fileCache };

// Expose to window for debugging
if (typeof window !== 'undefined') {
  /** @type {any} */ (window).fileCache = fileCache;
}

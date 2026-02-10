/**
 * In-memory cache for /api/files/* responses
 * Works with authenticated requests and self-signed certificates
 */

const isDev = import.meta.env.DEV;
const log = (...args) => isDev && console.log(...args);
const warn = (...args) => isDev && console.warn(...args);

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
    await fileCache.pendingRequests.get(cacheKey);
    // Get a fresh copy from cache (each caller gets their own Response object)
    const cached = await fileCache.get(url);
    if (cached) {
      return cached;
    }
    // If not in cache (caching may have failed), fallback to direct fetch
    warn('[FileCache] Deduplicated request cache miss, falling back to direct fetch:', cacheKey);
    return fetch(url, options);
  }

  // Fetch from network
  log('[FileCache] Fetching from network:', cacheKey);

  const fetchPromise = (async () => {
    const response = await fetch(url, options);

    // Cache successful responses
    if (response.ok) {
      await fileCache.set(url, response);
    }

    // Signal completion (don't return the response itself to avoid stream issues)
    return response.ok;
  })();

  // Store the promise so concurrent requests can reuse it
  fileCache.pendingRequests.set(cacheKey, fetchPromise);

  try {
    const success = await fetchPromise;
    if (success) {
      // Get from cache so we return a fresh Response object
      const cached = await fileCache.get(url);
      if (!cached) {
        warn('[FileCache] Cache miss after successful fetch, falling back to direct fetch:', cacheKey);
        log('[FileCache] Cache contents:', Array.from(fileCache.cache.keys()));
        // Fallback to direct fetch if caching failed
        return fetch(url, options);
      }
      return cached;
    } else {
      // Request failed, fetch again to get the actual error response
      return fetch(url, options);
    }
  } finally {
    // Remove from pending requests when done
    fileCache.pendingRequests.delete(cacheKey);
  }
}

// Export cache instance for debugging
export { fileCache };

// Expose to window for debugging
if (typeof window !== 'undefined') {
  window.fileCache = fileCache;
}

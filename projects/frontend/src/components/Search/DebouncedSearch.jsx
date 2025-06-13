import { Loader2, Search } from 'lucide-react';
import React, { useEffect, useState } from 'react';

const DebouncedSearch = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);

  // Debounced search effect
  useEffect(() => {
    // Create a timer
    const timer = setTimeout(() => {
      setDebouncedQuery(searchQuery);
    }, 300); // Wait 300ms after last keystroke

    // Cleanup: cancel timer if user types again
    return () => clearTimeout(timer);
  }, [searchQuery]); // Effect runs when searchQuery changes

  // Perform search when debouncedQuery changes
  useEffect(() => {
    const performSearch = async () => {
      // Don't search if query is empty
      if (!debouncedQuery.trim()) {
        setResults([]);
        return;
      }

      setLoading(true);
      try {
        // Simulate API call
        await new Promise(resolve => setTimeout(resolve, 1000));
        setResults([`Results for: ${debouncedQuery}`]);
      } catch (error) {
        console.error('Search failed:', error);
      } finally {
        setLoading(false);
      }
    };

    performSearch();
  }, [debouncedQuery]);

  return (
    <div className="max-w-md mx-auto p-4">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Type to search..."
          className="w-full pl-10 pr-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
        />
        {loading && (
          <Loader2 className="absolute right-3 top-1/2 transform -translate-y-1/2 w-5 h-5 animate-spin text-blue-500" />
        )}
      </div>

      <div className="mt-4 space-y-2">
        {results.map((result, index) => (
          <div key={index} className="p-3 bg-white border rounded-lg">
            {result}
          </div>
        ))}
      </div>

      <div className="mt-4 text-sm text-gray-500">
        <p>Debug Info:</p>
        <p>Current Input: {searchQuery}</p>
        <p>Debounced Query: {debouncedQuery}</p>
      </div>
    </div>
  );
};

export default DebouncedSearch;
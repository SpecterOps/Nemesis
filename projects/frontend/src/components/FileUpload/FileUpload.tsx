// src/components/FileUpload/FileUpload.tsx
import { useUser } from '@/contexts/UserContext';
import { AlertTriangle, Clock, FileText, Folder, HelpCircle, Loader2 } from 'lucide-react';
import React, { useCallback, useEffect, useState } from 'react';

interface UploadResponse {
  object_id: string;
}

interface Metadata {
  object_id: string;
  agent_id: string;
  project: string;
  timestamp: string;
  expiration: string;
  path: string;
}

// Custom hook for updating expiration time
const useExpirationTime = (dataExpirationDate: string | null, dataExpirationDays: string | null) => {
  const [expirationTime, setExpirationTime] = useState<string>('Not set');

  useEffect(() => {
    const updateExpiration = () => {
      if (dataExpirationDate) {
        setExpirationTime(new Date(dataExpirationDate).toLocaleString());
        return;
      }
      
      if (dataExpirationDays) {
        const date = new Date();
        date.setDate(date.getDate() + parseInt(dataExpirationDays));
        setExpirationTime(date.toLocaleString());
      }
    };

    updateExpiration();

    let interval: NodeJS.Timeout | null = null;
    if (dataExpirationDays) {
      interval = setInterval(updateExpiration, 1000);
    }

    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [dataExpirationDate, dataExpirationDays]);

  return expirationTime;
};

const InputField: React.FC<{
  icon: React.FC<any>;
  label: string;
  required?: boolean;
  value: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  type?: string;
  tooltip?: string;
  readOnly?: boolean;
}> = ({ icon: Icon, label, required, value, onChange, placeholder, type = "text", tooltip, readOnly }) => (
  <div>
    <div className="flex items-center gap-2 mb-1">
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
        {label} {required && <span className="text-red-500">*</span>}
      </label>
      {tooltip && (
        <div className="relative group">
          <HelpCircle className="h-4 w-4 text-gray-400 hover:text-gray-500 cursor-help" />
          <div className="absolute left-0 mt-2 px-2 py-1 bg-gray-900 text-white text-sm rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-50">
            {tooltip}
          </div>
        </div>
      )}
    </div>
    <div className="relative">
      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
        <Icon className="h-5 w-5 text-gray-400" />
      </div>
      <input
        type={type}
        value={value}
        onChange={onChange}
        className={`w-full pl-10 pr-3 py-2 border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200 focus:outline-none ${!readOnly && "focus:ring-2 focus:ring-blue-500"} ${readOnly && "bg-gray-100 dark:bg-gray-700"}`}
        placeholder={placeholder}
        required={required}
        readOnly={readOnly}
      />
    </div>
  </div>
);

const FileUpload: React.FC = () => {
  const { username, project: contextProject, dataExpirationDays, dataExpirationDate } = useUser();
  const [file, setFile] = useState<File | null>(null);
  const [filePath, setFilePath] = useState('');
  const [project, setProject] = useState(contextProject);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const expirationTime = useExpirationTime(dataExpirationDate, dataExpirationDays);

  useEffect(() => {
    setProject(contextProject);
  }, [contextProject]);

  const getFormattedPath = (basePath: string, fileName: string): string => {
    if (!basePath) return fileName;

    // Determine if we're using forward or backward slashes
    const isForwardSlash = basePath.includes('/');
    const separator = isForwardSlash ? '/' : '\\';
    
    // Remove trailing separator if it exists
    const cleanPath = basePath.replace(/[/\\]$/, '');
    
    // Combine path and filename with the appropriate separator
    return `${cleanPath}${separator}${fileName}`;
  };

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      setFile(droppedFile);
      setError(null);
    }
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
      setError(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsUploading(true);
    setError(null);
    setSuccess(false);
  
    try {
      if (!file || !project) {
        throw new Error('Please fill in all required fields');
      }
  
      let expiration: Date;
      if (dataExpirationDate) {
        expiration = new Date(dataExpirationDate);
      } else {
        expiration = new Date();
        expiration.setDate(expiration.getDate() + parseInt(dataExpirationDays));
      }
  
      const formData = new FormData();
      formData.append('file', file);
      
      const metadata = {
        agent_id: username,
        project,
        timestamp: new Date().toISOString(),
        expiration: expiration.toISOString(),
        path: getFormattedPath(filePath, file.name)
      };
  
      formData.append('metadata', JSON.stringify(metadata));
  
      const response = await fetch('/api/files', {
        method: 'POST',
        body: formData,
      });
  
      if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`);
      }
  
      const result = await response.json() as UploadResponse;
      setSuccess(true);
      setFile(null);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div className="bg-white dark:bg-dark-secondary rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
        <div className="mb-6">
          <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
            Upload File
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Upload a file for enrichment processing
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
              isDragging 
                ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' 
                : 'border-gray-300 dark:border-gray-600'
            }`}
          >
            <FileText className="w-12 h-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
            <div className="text-gray-600 dark:text-gray-400">
              {file ? (
                <div className="text-blue-600 dark:text-blue-400 font-medium">
                  {file.name}
                </div>
              ) : (
                <>
                  <p className="mb-2">Drag and drop your file here, or</p>
                  <label className="cursor-pointer text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300">
                    <span>browse</span>
                    <input
                      type="file"
                      onChange={handleFileSelect}
                      className="hidden"
                    />
                  </label>
                </>
              )}
            </div>
          </div>

          <div className="grid gap-6">
            <InputField
              icon={FileText}
              label="Originating Folder Path"
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
              placeholder="C:\Folder\ or /folder/"
            />

            <InputField
              icon={Folder}
              label="Project Name"
              required
              value={project}
              onChange={(e) => setProject(e.target.value)}
              placeholder="Enter project name (e.g. ASSESS-123)"
            />

            <InputField
              icon={Clock}
              label="Expiration Time"
              value={expirationTime}
              tooltip="Change in 'Settings' at the top right."
              readOnly
            />
          </div>

          {error && (
            <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-red-500 dark:text-red-400" />
              <span className="text-red-600 dark:text-red-400">{error}</span>
            </div>
          )}

          {success && (
            <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg flex items-center space-x-2">
              <svg
                className="w-5 h-5 text-green-500 dark:text-green-400"
                fill="none"
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-green-800 dark:text-green-400">
                File uploaded successfully! The file will be processed shortly.
              </span>
            </div>
          )}

          <button
            type="submit"
            disabled={isUploading || !file}
            className={`w-full py-2 px-4 rounded-md text-white font-medium transition-colors ${
              isUploading || !file
                ? 'bg-gray-400 dark:bg-gray-600 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600'
            }`}
          >
            {isUploading ? (
              <div className="flex items-center justify-center">
                <Loader2 className="w-5 h-5 animate-spin mr-2" />
                Uploading...
              </div>
            ) : (
              'Upload File'
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default FileUpload;

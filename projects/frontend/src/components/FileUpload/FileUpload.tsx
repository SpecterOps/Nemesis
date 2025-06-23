// src/components/FileUpload/FileUpload.tsx
import { useUser } from '@/contexts/UserContext';
import { AlertTriangle, Clock, FileText, Folder, HelpCircle, Loader2, X } from 'lucide-react';
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

interface FileUploadStatus {
  file: File;
  status: 'pending' | 'uploading' | 'success' | 'error';
  progress: number;
  error?: string;
  objectId?: string;
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

const FileListItem: React.FC<{
  fileStatus: FileUploadStatus;
  onRemove: () => void;
}> = ({ fileStatus, onRemove }) => {
  const { file, status, progress, error } = fileStatus;

  const getStatusIcon = () => {
    switch (status) {
      case 'uploading':
        return <Loader2 className="h-4 w-4 animate-spin text-blue-500" />;
      case 'success':
        return (
          <svg className="h-4 w-4 text-green-500" fill="none" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 24 24" stroke="currentColor">
            <path d="M5 13l4 4L19 7" />
          </svg>
        );
      case 'error':
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default:
        return <FileText className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusColor = () => {
    switch (status) {
      case 'uploading':
        return 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800';
      case 'success':
        return 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800';
      case 'error':
        return 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
      default:
        return 'bg-gray-50 dark:bg-gray-700 border-gray-200 dark:border-gray-600';
    }
  };

  return (
    <div className={`flex items-center justify-between p-3 rounded-md border ${getStatusColor()}`}>
      <div className="flex items-center space-x-3 flex-1 min-w-0">
        {getStatusIcon()}
        <div className="flex-1 min-w-0">
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-700 dark:text-gray-300 truncate">{file.name}</span>
            <span className="text-xs text-gray-500 whitespace-nowrap">
              ({(file.size / 1024 / 1024).toFixed(2)} MB)
            </span>
          </div>
          {status === 'uploading' && (
            <div className="mt-1">
              <div className="w-full bg-gray-200 dark:bg-gray-600 rounded-full h-1.5">
                <div
                  className="bg-blue-500 h-1.5 rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
            </div>
          )}
          {error && (
            <div className="text-xs text-red-600 dark:text-red-400 mt-1">{error}</div>
          )}
        </div>
      </div>
      {status !== 'uploading' && (
        <button
          type="button"
          onClick={onRemove}
          className="text-gray-400 hover:text-red-500 p-1 ml-2"
          title="Remove file"
        >
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  );
};

const FileUpload: React.FC = () => {
  const { username, project: contextProject, dataExpirationDays, dataExpirationDate } = useUser();
  const [fileStatuses, setFileStatuses] = useState<FileUploadStatus[]>([]);
  const [filePath, setFilePath] = useState('');
  const [project, setProject] = useState(contextProject);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successCount, setSuccessCount] = useState(0);

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

  const validateFiles = (newFiles: File[]): File[] => {
    const maxSize = 100 * 1024 * 1024; // 100MB per file
    const validFiles: File[] = [];
    const errors: string[] = [];

    newFiles.forEach(file => {
      if (file.size > maxSize) {
        errors.push(`${file.name} is too large (max 100MB)`);
      } else {
        validFiles.push(file);
      }
    });

    if (errors.length > 0) {
      setError(errors.join(', '));
    }

    return validFiles;
  };

  const addFiles = (newFiles: File[]) => {
    const validFiles = validateFiles(newFiles);
    const newFileStatuses: FileUploadStatus[] = validFiles.map(file => ({
      file,
      status: 'pending',
      progress: 0
    }));

    setFileStatuses(prev => [...prev, ...newFileStatuses]);
    setError(null);
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
    const droppedFiles = Array.from(e.dataTransfer.files);
    if (droppedFiles.length > 0) {
      addFiles(droppedFiles);
    }
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(e.target.files || []);
    if (selectedFiles.length > 0) {
      addFiles(selectedFiles);
    }
    // Reset the input so the same files can be selected again if needed
    e.target.value = '';
  };

  const removeFile = (index: number) => {
    setFileStatuses(prev => prev.filter((_, i) => i !== index));
  };

  const clearAllFiles = () => {
    setFileStatuses([]);
    setSuccessCount(0);
    setError(null);
  };

  const uploadFile = async (fileStatus: FileUploadStatus, index: number): Promise<void> => {
    const { file } = fileStatus;

    // Update status to uploading
    setFileStatuses(prev => prev.map((fs, i) =>
      i === index ? { ...fs, status: 'uploading', progress: 0 } : fs
    ));

    try {
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

      // Simulate progress (since fetch doesn't provide upload progress by default)
      const progressInterval = setInterval(() => {
        setFileStatuses(prev => prev.map((fs, i) => {
          if (i === index && fs.status === 'uploading' && fs.progress < 90) {
            return { ...fs, progress: fs.progress + 10 };
          }
          return fs;
        }));
      }, 200);

      const response = await fetch('/api/files', {
        method: 'POST',
        body: formData,
      });

      clearInterval(progressInterval);

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`);
      }

      const result = await response.json() as UploadResponse;

      // Update status to success
      setFileStatuses(prev => prev.map((fs, i) =>
        i === index ? {
          ...fs,
          status: 'success',
          progress: 100,
          objectId: result.object_id
        } : fs
      ));

      setSuccessCount(prev => prev + 1);

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Upload failed';

      // Update status to error
      setFileStatuses(prev => prev.map((fs, i) =>
        i === index ? {
          ...fs,
          status: 'error',
          progress: 0,
          error: errorMessage
        } : fs
      ));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (fileStatuses.length === 0 || !project) {
      setError('Please select files and fill in all required fields');
      return;
    }

    setIsUploading(true);
    setError(null);
    setSuccessCount(0);

    try {
      // Upload files sequentially to avoid overwhelming the server
      for (let i = 0; i < fileStatuses.length; i++) {
        const fileStatus = fileStatuses[i];
        if (fileStatus.status === 'pending') {
          await uploadFile(fileStatus, i);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
    } finally {
      setIsUploading(false);
    }
  };

  const pendingFiles = fileStatuses.filter(fs => fs.status === 'pending');
  const completedFiles = fileStatuses.filter(fs => fs.status === 'success' || fs.status === 'error');

  return (
    <div className="max-w-2xl mx-auto">
      <div className="bg-white dark:bg-dark-secondary rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
        <div className="mb-6">
          <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100">
            Upload Files
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            <strong>Note:</strong> <em>ZIPs/containers are not auto-extracted, but this can be triggered when analyzing the file.</em>
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
              <p className="mb-2">Drag and drop multiple files here, or</p>
              <label className="cursor-pointer text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300">
                <span>browse</span>
                <input
                  type="file"
                  multiple
                  onChange={handleFileSelect}
                  className="hidden"
                />
              </label>
            </div>
          </div>

          {fileStatuses.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                  Selected Files ({fileStatuses.length})
                </h3>
                <button
                  type="button"
                  onClick={clearAllFiles}
                  className="text-sm text-gray-500 hover:text-red-500 dark:text-gray-400 dark:hover:text-red-400"
                  disabled={isUploading}
                >
                  Clear All
                </button>
              </div>

              <div className="space-y-2 max-h-60 overflow-y-auto">
                {fileStatuses.map((fileStatus, index) => (
                  <FileListItem
                    key={`${fileStatus.file.name}-${index}`}
                    fileStatus={fileStatus}
                    onRemove={() => removeFile(index)}
                  />
                ))}
              </div>
            </div>
          )}

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

          {successCount > 0 && (
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
                {successCount} file{successCount > 1 ? 's' : ''} uploaded successfully!
                {pendingFiles.length > 0 && ` ${pendingFiles.length} remaining...`}
              </span>
            </div>
          )}

          <button
            type="submit"
            disabled={isUploading || fileStatuses.length === 0 || !project}
            className={`w-full py-2 px-4 rounded-md text-white font-medium transition-colors ${
              isUploading || fileStatuses.length === 0 || !project
                ? 'bg-gray-400 dark:bg-gray-600 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600'
            }`}
          >
            {isUploading ? (
              <div className="flex items-center justify-center">
                <Loader2 className="w-5 h-5 animate-spin mr-2" />
                Uploading {pendingFiles.length} file{pendingFiles.length !== 1 ? 's' : ''}...
              </div>
            ) : (
              `Upload ${fileStatuses.length} File${fileStatuses.length !== 1 ? 's' : ''}`
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default FileUpload;
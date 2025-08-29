import JSZip from 'jszip';

export interface CompressionProgress {
  currentFile: string;
  filesProcessed: number;
  totalFiles: number;
  uncompressedSize: number;
  compressedSize: number;
  percentage: number;
}

export interface CompressionResult {
  blob: Blob;
  uncompressedSize: number;
  compressedSize: number;
  fileCount: number;
}

export interface CompressionOptions {
  maxUncompressedSize?: number; // Default: 500MB
  maxCompressedSize?: number;   // Default: 100MB
  onProgress?: (progress: CompressionProgress) => void;
  compressionLevel?: number;    // 0-9, default 6
}

export class FolderCompressor {
  private static readonly DEFAULT_MAX_UNCOMPRESSED = 500 * 1024 * 1024; // 500MB uncompressed
  private static readonly DEFAULT_MAX_COMPRESSED = 100 * 1024 * 1024;  // 100MB compressed
  
  private abortController: AbortController | null = null;

  async compressFolder(
    folderEntry: FileSystemDirectoryEntry,
    options: CompressionOptions = {}
  ): Promise<CompressionResult> {
    const {
      maxUncompressedSize = FolderCompressor.DEFAULT_MAX_UNCOMPRESSED,
      maxCompressedSize = FolderCompressor.DEFAULT_MAX_COMPRESSED,
      onProgress,
      compressionLevel = 6
    } = options;

    this.abortController = new AbortController();
    
    const zip = new JSZip();
    let uncompressedSize = 0;
    let filesProcessed = 0;
    
    // First, collect all files and check total size
    const allFiles = await this.collectFiles(folderEntry);
    const totalFiles = allFiles.length;
    
    if (totalFiles === 0) {
      throw new Error('Folder is empty');
    }
    
    // Calculate total uncompressed size
    const totalUncompressedSize = allFiles.reduce((sum, { file }) => sum + file.size, 0);
    
    if (totalUncompressedSize > maxUncompressedSize) {
      throw new Error(
        `Folder size (${this.formatSize(totalUncompressedSize)}) exceeds maximum allowed size (${this.formatSize(maxUncompressedSize)})`
      );
    }
    
    // Add files to zip with progress tracking
    for (const { path, file } of allFiles) {
      if (this.abortController.signal.aborted) {
        throw new Error('Compression cancelled');
      }
      
      // Remove leading slash if present
      const zipPath = path.startsWith('/') ? path.slice(1) : path;
      
      // Add file to zip
      zip.file(zipPath, file, {
        compression: 'DEFLATE',
        compressionOptions: { level: compressionLevel }
      });
      
      uncompressedSize += file.size;
      filesProcessed++;
      
      // Report progress
      if (onProgress) {
        onProgress({
          currentFile: path,
          filesProcessed,
          totalFiles,
          uncompressedSize,
          compressedSize: 0, // Will be updated after compression
          percentage: (filesProcessed / totalFiles) * 100
        });
      }
    }
    
    // Generate the compressed blob
    const blob = await zip.generateAsync(
      {
        type: 'blob',
        compression: 'DEFLATE',
        compressionOptions: { level: compressionLevel },
        streamFiles: true
      },
      (metadata) => {
        // Update progress during compression
        if (onProgress && metadata.percent) {
          onProgress({
            currentFile: 'Compressing...',
            filesProcessed,
            totalFiles,
            uncompressedSize,
            compressedSize: 0,
            percentage: metadata.percent
          });
        }
      }
    );
    
    // Check compressed size
    if (blob.size > maxCompressedSize) {
      throw new Error(
        `Compressed size (${this.formatSize(blob.size)}) exceeds maximum allowed size (${this.formatSize(maxCompressedSize)})`
      );
    }
    
    return {
      blob,
      uncompressedSize,
      compressedSize: blob.size,
      fileCount: totalFiles
    };
  }
  
  abort(): void {
    if (this.abortController) {
      this.abortController.abort();
    }
  }
  
  private async collectFiles(
    entry: FileSystemEntry,
    basePath: string = ''
  ): Promise<Array<{ path: string; file: File }>> {
    const files: Array<{ path: string; file: File }> = [];
    
    if (entry.isFile) {
      const fileEntry = entry as FileSystemFileEntry;
      const file = await this.getFile(fileEntry);
      files.push({ path: basePath + entry.name, file });
    } else if (entry.isDirectory) {
      const dirEntry = entry as FileSystemDirectoryEntry;
      const dirPath = basePath + entry.name + '/';
      const entries = await this.readDirectory(dirEntry);
      
      for (const childEntry of entries) {
        if (this.abortController?.signal.aborted) {
          break;
        }
        const childFiles = await this.collectFiles(childEntry, dirPath);
        files.push(...childFiles);
      }
    }
    
    return files;
  }
  
  private getFile(fileEntry: FileSystemFileEntry): Promise<File> {
    return new Promise((resolve, reject) => {
      fileEntry.file(resolve, reject);
    });
  }
  
  private readDirectory(dirEntry: FileSystemDirectoryEntry): Promise<FileSystemEntry[]> {
    return new Promise((resolve, reject) => {
      const entries: FileSystemEntry[] = [];
      const reader = dirEntry.createReader();
      
      const readEntries = () => {
        reader.readEntries(
          (results) => {
            if (results.length > 0) {
              entries.push(...results);
              readEntries(); // Continue reading
            } else {
              resolve(entries);
            }
          },
          reject
        );
      };
      
      readEntries();
    });
  }
  
  private formatSize(bytes: number): string {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    
    return `${size.toFixed(2)} ${units[unitIndex]}`;
  }
}

export const folderCompressor = new FolderCompressor();
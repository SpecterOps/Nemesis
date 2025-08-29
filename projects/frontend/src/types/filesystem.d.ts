// TypeScript declarations for FileSystem API
interface DataTransferItem {
  webkitGetAsEntry(): FileSystemEntry | null;
}

interface FileSystemEntry {
  readonly isFile: boolean;
  readonly isDirectory: boolean;
  readonly name: string;
  readonly fullPath: string;
  readonly filesystem: FileSystem;
  
  getMetadata(successCallback: (metadata: Metadata) => void, errorCallback?: (error: Error) => void): void;
  moveTo(parent: FileSystemDirectoryEntry, newName?: string, successCallback?: (entry: FileSystemEntry) => void, errorCallback?: (error: Error) => void): void;
  copyTo(parent: FileSystemDirectoryEntry, newName?: string, successCallback?: (entry: FileSystemEntry) => void, errorCallback?: (error: Error) => void): void;
  toURL(): string;
  remove(successCallback: () => void, errorCallback?: (error: Error) => void): void;
  getParent(successCallback: (parent: FileSystemDirectoryEntry) => void, errorCallback?: (error: Error) => void): void;
}

interface FileSystemFileEntry extends FileSystemEntry {
  file(successCallback: (file: File) => void, errorCallback?: (error: Error) => void): void;
}

interface FileSystemDirectoryEntry extends FileSystemEntry {
  createReader(): FileSystemDirectoryReader;
  getFile(path: string, options?: FileSystemFlags, successCallback?: (entry: FileSystemFileEntry) => void, errorCallback?: (error: Error) => void): void;
  getDirectory(path: string, options?: FileSystemFlags, successCallback?: (entry: FileSystemDirectoryEntry) => void, errorCallback?: (error: Error) => void): void;
}

interface FileSystemDirectoryReader {
  readEntries(successCallback: (entries: FileSystemEntry[]) => void, errorCallback?: (error: Error) => void): void;
}

interface FileSystemFlags {
  create?: boolean;
  exclusive?: boolean;
}

interface Metadata {
  modificationTime: Date;
  size: number;
}

interface FileSystem {
  readonly name: string;
  readonly root: FileSystemDirectoryEntry;
}
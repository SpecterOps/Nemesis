# Frontend Service

A modern React-based web application that provides the primary user interface for the Nemesis platform.

## Purpose

This service delivers a comprehensive dashboard for security analysts to upload, analyze, and investigate files, findings, and intelligence gathered by the Nemesis platform. It provides intuitive interfaces for file management, security analysis, and threat investigation workflows.

## Features

### File Management
- **File upload**: Drag-and-drop interface for uploading files and directories
- **File browser**: Advanced file listing with filtering, sorting, and search capabilities
- **File viewer**: Multi-format file viewing including text, PDF, images, CSV, SQLite, and binary files
- **Monaco editor**: Syntax-highlighted code viewing for various programming languages
- **Archive support**: Inline viewing of ZIP file contents and nested structures

### Security Analysis
- **Findings dashboard**: Centralized view of security findings with triage capabilities
- **YARA rule management**: Create, edit, and manage YARA rules for malware detection
- **NoseyParker integration**: View secret scanning results and potential credential exposures
- **Alert system**: Real-time notifications for critical security findings

### Search and Investigation
- **Document search**: Full-text search across all uploaded file contents
- **Advanced filtering**: Filter files and findings by type, date, project, and custom criteria
- **Triage mode**: Streamlined interface for security analyst workflows
- **Finding correlation**: Link related findings and track investigation progress

### Data Visualization
- **Statistics dashboard**: Overview charts showing file counts, types, and processing status
- **Enrichment status**: Visual indicators of file processing progress and module results
- **Interactive charts**: Dynamic visualizations using Recharts library

### User Experience
- **Dark/light themes**: Toggle between light and dark interface modes
- **Responsive design**: Optimized for desktop and mobile viewing
- **Real-time updates**: Live data refresh using GraphQL subscriptions
- **Contextual help**: Built-in help system and documentation

## Technical Architecture

### Frontend Stack
- **React 18**: Modern React with hooks and concurrent features
- **Vite**: Fast build tool and development server
- **Tailwind CSS**: Utility-first CSS framework for responsive design
- **TypeScript**: Type-safe JavaScript for enhanced development experience

### Data Integration
- **Hasura GraphQL**: Real-time data queries and subscriptions
- **WebSocket connections**: Live updates for findings and file processing
- **RESTful APIs**: Integration with backend services for file operations

### Specialized Components
- **Monaco Editor**: Code syntax highlighting and editing
- **React Router**: Client-side routing for single-page application navigation
- **Radix UI**: Accessible component primitives
- **SQL.js**: In-browser SQLite database viewing

## Access

Available at the root path `/` when Nemesis is running, typically accessed through the configured web interface URL.

## Configuration

The frontend adapts to the Nemesis environment through:
- Environment-specific API endpoints
- Hasura admin secret configuration
- Theme persistence in local storage
- User preference management
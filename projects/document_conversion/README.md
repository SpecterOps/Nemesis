# Document Conversion Service

A microservice for the Nemesis platform that handles document processing, text extraction, and file format conversion.

## Purpose

This service processes uploaded files to extract textual content, convert documents to PDF format, and extract strings from binary files. It serves as a key component in making file contents searchable and viewable within the Nemesis platform.

## Features

- **Text extraction**: Extract readable text from various document formats using Apache Tika
- **PDF conversion**: Convert Office documents and other formats to PDF using Gotenberg
- **String extraction**: Extract printable strings from binary files
- **Encryption detection**: Automatically detect and skip encrypted or protected files
- **Parallel processing**: Execute multiple extraction methods simultaneously using Dapr workflows
- **Container support**: Process files extracted from archives and containers

## Document Processing Pipeline

The service uses a Dapr workflow to process files through three parallel activities:

1. **Tika text extraction**: Extracts formatted text from documents
2. **String extraction**: Pulls ASCII/Unicode strings from binary files  
3. **PDF conversion**: Converts supported formats to PDF for viewing

## Supported File Types

- **Text extraction**: Office documents, PDFs, HTML, RTF, and other text-based formats
- **PDF conversion**: Microsoft Office files, LibreOffice documents, text files
- **String extraction**: Any binary file format

## Configuration

The service integrates with external components:

- **Apache Tika**: Java-based text extraction engine
- **Gotenberg**: Document to PDF conversion service via HTTP API
- **Minio**: Object storage for input files and generated outputs
- **PostgreSQL**: Workflow state and transform metadata storage

## Workflow Behavior

Files are processed only if they meet specific criteria:
- Not already plaintext
- Not encrypted or password protected
- Either original submissions or container-extracted files
- Not existing transforms to avoid duplicate processing

## Health Monitoring

- `GET /healthz`: Comprehensive health check including database connectivity, JVM status, and workflow runtime verification
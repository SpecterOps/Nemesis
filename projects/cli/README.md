# CLI Service

A command-line interface for the Nemesis platform that provides file submission, monitoring, and C2 connector functionality.

## Purpose

This CLI tool serves as the primary interface for uploading files to Nemesis, monitoring directories for new files, and synchronizing data from C2 frameworks like Mythic and Outflank.

## Features

- **File submission**: Upload single files or entire directories to Nemesis
- **Directory monitoring**: Real-time monitoring of folders for new files
- **C2 connectors**: Synchronize data from Mythic and Outflank C2 frameworks
- **Stress testing**: Load testing capabilities for the Nemesis API
- **Module testing**: Execute file enrichment modules standalone for development

## Commands

### submit
Upload files or directories to Nemesis for processing.

**Key options:**
- `-r, --recursive`: Process subdirectories recursively
- `-w, --workers`: Number of concurrent upload threads (default: 10)
- `--project`: Project name for metadata (default: assess-test)
- `--agent-id`: Agent identifier for tracking uploads

### monitor
Monitor a directory for new files and automatically submit them to Nemesis.

**Key options:**
- `--only-monitor`: Skip existing files, only watch for new ones
- `-w, --workers`: Number of threads for initial submission

### connect-mythic
Synchronize data between Mythic C2 framework and Nemesis.

**Configuration:**
- Uses `settings_mythic.yaml` configuration file
- `--showconfig`: Display example configuration

### connect-outflank
Ingest data from Outflank Stage1 C2 into Nemesis.

**Configuration:**
- Uses `settings_outflank.yaml` configuration file
- `--showconfig`: Display example configuration

## Additional Tools

- **stress_test**: Load testing tool for API performance evaluation
- **module_runner**: Standalone execution of file enrichment modules for development and testing

## Authentication

All commands support basic authentication with configurable username and password options (default: n/n).
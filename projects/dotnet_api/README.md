# .NET API Service

A microservice for the Nemesis platform that provides comprehensive analysis of .NET assemblies including decompilation and metadata extraction.

## Purpose

This service processes .NET executable files and libraries to extract source code, analyze assembly structure, and provide insights into .NET applications for security assessment and reverse engineering purposes.

## Features

- **.NET decompilation**: Convert compiled assemblies back to readable C# source code using ILSpy
- **Assembly analysis**: Extract detailed metadata including types, methods, dependencies, and security attributes
- **Source code packaging**: Generate downloadable archives of decompiled source code
- **Cross-platform support**: Process .NET Framework, .NET Core, and .NET 5+ assemblies

## Analysis Capabilities

The service performs two primary analysis functions:

### 1. Source Code Decompilation
- Uses ILSpy command-line tool to decompile .NET assemblies
- Reconstructs C# source code from IL bytecode
- Packages decompiled source into ZIP archives for download
- Preserves project structure and namespace organization

### 2. Assembly Inspection
- Leverages custom InspectAssembly tool for metadata extraction
- Analyzes assembly manifest, types, and dependencies
- Extracts security permissions and attributes
- Identifies obfuscation and protection mechanisms

## Supported File Types

- .NET executables (.exe)
- .NET libraries (.dll)
- .NET Framework assemblies
- .NET Core/5+ assemblies
- Managed C++/CLI assemblies

## Configuration

- `INSPECT_ASSEMBLY_PATH`: Path to the InspectAssembly analysis tool (default: `/opt/InspectAssembly/InspectAssembly.dll`)

## Dependencies

- **ILSpy**: Command-line decompiler for .NET assemblies
- **.NET Runtime**: Required for executing analysis tools
- **InspectAssembly**: Custom tool for detailed assembly metadata extraction

## Endpoints

- `GET /file/{object_id}`: Analyze a .NET assembly by object ID, returns decompilation results and assembly metadata
- `GET /healthz`: Health check endpoint for service monitoring

## Output Format

Returns JSON containing:
- `decompilation`: Object ID of the ZIP archive containing decompiled source code
- `inspect_assembly`: Detailed assembly metadata including types, methods, and security information
# DotNet Service

Provides decompilation capabilities using the ILSpy decompiler engine as well as deserialization analysis with functionality pulled from InspectAssembly.

Integrates directly with Dapr's pub/sub and Minio to cut down on process creates via Python.

Original [ILSpy code](https://github.com/icsharpcode/ILSpy/tree/master/ICSharpCode.ILSpyCmd) was adapted (MIT license).

Original [InspectAssembly code](https://github.com/matterpreter/OffensiveCSharp/tree/master/InspectAssembly) is by [@matterpreter](https://github.com/matterpreter/OffensiveCSharp/tree/master/InspectAssembly) under a BSD 3-Clause license.


## Features

- Listens for decompilation requests via Dapr pub/sub
- Downloads .NET assemblies from Minio object storage
- Decompiles assemblies using the ILSpy decompiler engine natively
- Compresses output to ZIP files
- Uploads results back to Minio
- Analyzes the original assembly using InspectAssembly
- Publishes decompilation + analysis results via Dapr pub/sub

## Environment Variables

The following environment variables are required:

- `MINIO_ENDPOINT` - Minio server endpoint (e.g., `http://minio:9000`)
- `MINIO_ACCESS_KEY` - Minio access key
- `MINIO_SECRET_KEY` - Minio secret key
- `MINIO_BUCKET` - Minio bucket name (e.g., `files`)

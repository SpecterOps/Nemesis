# DotNet Service

Provides decompilation capabilities using the ILSpy decompiler engine as well as deserialization analysis with functionality pulled from InspectAssembly.

Integrates directly with Dapr's pub/sub and SeaweedFS (S3-compatible object storage) to cut down on process creates via Python.

Original [ILSpy code](https://github.com/icsharpcode/ILSpy/tree/master/ICSharpCode.ILSpyCmd) was adapted (MIT license).

Original [InspectAssembly code](https://github.com/matterpreter/OffensiveCSharp/tree/master/InspectAssembly) is by [@matterpreter](https://github.com/matterpreter/OffensiveCSharp/tree/master/InspectAssembly) under a BSD 3-Clause license.


## Features

- Listens for decompilation requests via Dapr pub/sub
- Downloads .NET assemblies from SeaweedFS object storage
- Decompiles assemblies using the ILSpy decompiler engine natively
- Compresses output to ZIP files
- Uploads results back to SeaweedFS
- Analyzes the original assembly using InspectAssembly
- Publishes decompilation + analysis results via Dapr pub/sub

## Environment Variables

The following environment variables are required:

- `S3_ENDPOINT` - S3-compatible storage endpoint (e.g., `http://seaweedfs:8333`)
- `S3_ACCESS_KEY` - S3 access key
- `S3_SECRET_KEY` - S3 secret key
- `S3_BUCKET` - S3 bucket name (e.g., `files`)

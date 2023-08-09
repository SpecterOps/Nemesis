# dotnet

Downloads the supplied Nemesis file/object ID from storage, and then:
- Uses ilspy to decompile the assembly as a complete project, zips and uploads the source to storage, and returns a new Nemesis object ID referencing the new .zip
- Uses a customized version of InspectAssembly to examine the assembly for deserialization/remoting vulns

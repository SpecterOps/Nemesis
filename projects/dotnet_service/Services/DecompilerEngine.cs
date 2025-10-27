using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.ProjectDecompiler;
using ICSharpCode.Decompiler.Metadata;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Threading.Tasks;

namespace ILSpyDecompilerService
{
    public class DecompilerEngine
    {
        private readonly ILogger<DecompilerEngine> _logger;

        public DecompilerEngine(ILogger<DecompilerEngine> logger)
        {
            _logger = logger;
        }

        public async Task<string> DecompileAssemblyAsync(string assemblyPath, string outputDirectory)
        {
            try
            {
                _logger.LogInformation($"Starting decompilation of {assemblyPath}");
                
                var module = new PEFile(assemblyPath);
                var resolver = new UniversalAssemblyResolver(assemblyPath, false, module.Metadata.DetectTargetFrameworkId());
                
                var decompilerSettings = new DecompilerSettings(LanguageVersion.Latest)
                {
                    ThrowOnAssemblyResolveErrors = false,
                    RemoveDeadCode = false,
                    RemoveDeadStores = false,
                    UseSdkStyleProjectFormat = WholeProjectDecompiler.CanUseSdkStyleProjectFormat(module),
                    UseNestedDirectoriesForNamespaces = false,
                };

                var decompiler = new WholeProjectDecompiler(decompilerSettings, resolver, resolver, null);
                
                Directory.CreateDirectory(outputDirectory);
                
                string projectFileName = Path.Combine(outputDirectory, Path.GetFileNameWithoutExtension(assemblyPath) + ".csproj");
                
                await Task.Run(() =>
                {
                    using (var projectFileWriter = new StreamWriter(File.OpenWrite(projectFileName)))
                    {
                        decompiler.DecompileProject(module, outputDirectory, projectFileWriter);
                    }
                });
                
                _logger.LogInformation($"Decompilation completed for {assemblyPath}");
                return outputDirectory;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to decompile assembly {assemblyPath}");
                throw;
            }
        }

        public async Task<string> CreateZipFromDirectoryAsync(string sourceDirectory, string zipFilePath)
        {
            try
            {
                _logger.LogInformation($"Creating ZIP file from {sourceDirectory}");
                
                await Task.Run(() =>
                {
                    if (File.Exists(zipFilePath))
                        File.Delete(zipFilePath);
                    
                    ZipFile.CreateFromDirectory(sourceDirectory, zipFilePath);
                });
                
                _logger.LogInformation($"ZIP file created at {zipFilePath}");
                return zipFilePath;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to create ZIP file from {sourceDirectory}");
                throw;
            }
        }

        public void CleanupTemporaryFiles(params string[] paths)
        {
            foreach (var path in paths)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        File.Delete(path);
                        _logger.LogDebug($"Deleted temporary file: {path}");
                    }
                    else if (Directory.Exists(path))
                    {
                        Directory.Delete(path, true);
                        _logger.LogDebug($"Deleted temporary directory: {path}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, $"Failed to cleanup temporary path: {path}");
                }
            }
        }
    }
}
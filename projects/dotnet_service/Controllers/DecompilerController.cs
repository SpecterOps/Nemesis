using Dapr;
using Dapr.Client;
using ILSpyDecompilerService.Models;
using ILSpyDecompilerService.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace ILSpyDecompilerService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class DecompilerController : ControllerBase
    {
        private readonly ILogger<DecompilerController> _logger;
        private readonly DaprClient _daprClient;
        private readonly MinioService _minioService;
        private readonly DecompilerEngine _decompilerEngine;
        private readonly AssemblyAnalysisService _assemblyAnalysisService;
        private readonly SemaphoreSlim _processingSemaphore;
        private const string PubSubName = "dotnet";
        private const string InputTopicName = "dotnet_input";
        private const string OutputTopicName = "dotnet_output";

        public DecompilerController(
            ILogger<DecompilerController> logger,
            DaprClient daprClient,
            MinioService minioService,
            DecompilerEngine decompilerEngine,
            AssemblyAnalysisService assemblyAnalysisService,
            IConfiguration configuration)
        {
            _logger = logger;
            _daprClient = daprClient;
            _minioService = minioService;
            _decompilerEngine = decompilerEngine;
            _assemblyAnalysisService = assemblyAnalysisService;
            
            // Get max concurrent processing from environment variable, default to 5
            var maxConcurrentProcessing = configuration.GetValue<int>("MAX_CONCURRENT_PROCESSING", 5);
            _processingSemaphore = new SemaphoreSlim(maxConcurrentProcessing, maxConcurrentProcessing);
            _logger.LogInformation("Maximum concurrent processing set to: {MaxConcurrentProcessing}", maxConcurrentProcessing);
        }

        [Topic(PubSubName, InputTopicName)]
        [HttpPost("process")]
        public async Task<IActionResult> ProcessDecompilationRequest([FromBody] InputMessage inputMessage)
        {
            var rawObjectJson = JsonConvert.SerializeObject(inputMessage, Formatting.Indented);
            // _logger.LogDebug("Raw input object: {RawObject}", rawObjectJson);

            // Wait for semaphore to limit concurrent processing
            await _processingSemaphore.WaitAsync();
            
            string downloadedFilePath = null;
            string outputDirectory = null;
            string zipFilePath = null;

            try
            {
                _logger.LogInformation("Processing decompilation request for object ID: {ObjectId}", inputMessage.ObjectId);

                if (string.IsNullOrEmpty(inputMessage.ObjectId))
                {
                    _logger.LogError("Invalid input message - ObjectId is null or empty");
                    return BadRequest("ObjectId is required");
                }

                var objectId = inputMessage.ObjectId;

                // Download file from Minio
                downloadedFilePath = await _minioService.DownloadFileAsync(objectId);
                _logger.LogDebug("File downloaded to: {downloadedFilePath}", downloadedFilePath);

                // Perform assembly analysis
                _logger.LogInformation("Starting assembly analysis for object ID: {ObjectId}", objectId);
                var analysisResult = _assemblyAnalysisService.AnalyzeAssembly(downloadedFilePath);
                _logger.LogDebug("Assembly analysis completed for: {ObjectId}", objectId);

                // Decompile assembly
                outputDirectory = Path.Combine(Path.GetTempPath(), $"{objectId}_source");
                await _decompilerEngine.DecompileAssemblyAsync(downloadedFilePath, outputDirectory);
                _logger.LogDebug("File decompiled to: {outputDirectory}", outputDirectory);

                // Create ZIP file
                var newObjectId = Guid.NewGuid().ToString();
                zipFilePath = Path.Combine(Path.GetTempPath(), newObjectId);
                await _decompilerEngine.CreateZipFromDirectoryAsync(outputDirectory, zipFilePath);

                // Upload ZIP to Minio
                await _minioService.UploadFileAsync(zipFilePath, newObjectId);
                _logger.LogDebug("Zip uploaded to: {newObjectId}", newObjectId);

                // Publish result with both decompilation and analysis data
                var outputMessage = new OutputMessage
                {
                    ObjectId = objectId,
                    Decompilation = newObjectId,
                    Analysis = analysisResult
                };

                await _daprClient.PublishEventAsync(PubSubName, OutputTopicName, outputMessage);

                _logger.LogInformation("Successfully processed decompilation request and published result: {NewObjectId}", newObjectId);

                return Ok(new { success = true, outputId = newObjectId, analysisResult = analysisResult });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process decompilation request for object ID: {ObjectId}", inputMessage?.ObjectId);
                return StatusCode(500, new { success = false, error = ex.Message });
            }
            finally
            {
                // Cleanup temporary files
                _decompilerEngine.CleanupTemporaryFiles(downloadedFilePath, outputDirectory, zipFilePath);
                
                // Release semaphore
                _processingSemaphore.Release();
            }
        }
    }
}
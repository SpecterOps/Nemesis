using Microsoft.Extensions.Logging;
using Minio;
using Minio.DataModel.Args;
using System;
using System.IO;
using System.Threading.Tasks;

namespace ILSpyDecompilerService
{
    public class S3StorageService
    {
        private readonly IMinioClient _minioClient;
        private readonly ILogger<S3StorageService> _logger;
        private readonly string _bucketName;

        public S3StorageService(ILogger<S3StorageService> logger)
        {
            _logger = logger;

            var endpoint = Environment.GetEnvironmentVariable("S3_ENDPOINT") ?? throw new InvalidOperationException("S3_ENDPOINT environment variable is required");
            var accessKey = Environment.GetEnvironmentVariable("S3_ACCESS_KEY") ?? throw new InvalidOperationException("S3_ACCESS_KEY environment variable is required");
            var secretKey = Environment.GetEnvironmentVariable("S3_SECRET_KEY") ?? throw new InvalidOperationException("S3_SECRET_KEY environment variable is required");
            _bucketName = Environment.GetEnvironmentVariable("S3_BUCKET") ?? throw new InvalidOperationException("S3_BUCKET environment variable is required");

            // Strip protocol from endpoint if present (Minio SDK expects hostname:port format)
            var cleanEndpoint = endpoint.Replace("http://", "").Replace("https://", "");

            _minioClient = new MinioClient()
                .WithEndpoint(cleanEndpoint)
                .WithCredentials(accessKey, secretKey)
                .Build();
        }

        public async Task<string> DownloadFileAsync(string objectId)
        {
            try
            {
                var tempFilePath = Path.GetTempFileName();

                var getObjectArgs = new GetObjectArgs()
                    .WithBucket(_bucketName)
                    .WithObject(objectId)
                    .WithFile(tempFilePath);

                await _minioClient.GetObjectAsync(getObjectArgs);

                _logger.LogInformation($"Downloaded file {objectId} to {tempFilePath}");
                return tempFilePath;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to download file {objectId}");
                throw;
            }
        }

        public async Task<string> UploadFileAsync(string filePath, string newObjectId)
        {
            try
            {
                var putObjectArgs = new PutObjectArgs()
                    .WithBucket(_bucketName)
                    .WithObject(newObjectId)
                    .WithFileName(filePath)
                    .WithContentType("application/zip");

                await _minioClient.PutObjectAsync(putObjectArgs);

                _logger.LogInformation($"Uploaded file {filePath} as {newObjectId}");
                return newObjectId;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to upload file {filePath} as {newObjectId}");
                throw;
            }
        }
    }
}

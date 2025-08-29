// NoseyParker Scanner - Scan files for secrets using NoseyParker with Dapr pub/sub
// This version includes MinIO integration and Dapr pub/sub

use dapr_macros::topic;
use tonic::transport::Server;
use dapr::{appcallback::*, dapr::proto::runtime::v1::app_callback_server::AppCallbackServer};

use anyhow::{Context, Result};
use clap::Parser;
use dapr::client::{Client as DaprClient, TonicClient};
use dotenv::dotenv;
use s3::{Bucket, Region};
use s3::creds::Credentials;
use serde::{Deserialize, Serialize};
use serde_json;
use std::convert::TryInto;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tempfile::NamedTempFile;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use std::fs::File;
use std::io::Read;
use walkdir::WalkDir;
use zip::ZipArchive;
#[cfg(target_os = "linux")]
use libc;
// use gix_object::FindExt;
use gix::objs::FindExt;


use noseyparker::blob_id::BlobId;
use noseyparker::blob::Blob;
use noseyparker::blob_id_map::BlobIdMap;
use noseyparker::defaults::get_builtin_rules;
use noseyparker::location;
use noseyparker::matcher::{Matcher, ScanResult};
use noseyparker::matcher_stats::MatcherStats;
use noseyparker::provenance::Provenance;
use noseyparker::rules_database::RulesDatabase;
// use input_enumerator::git_repo_enumerator::BlobMetadata;
use noseyparker_rules::Rule;
use input_enumerator::{
    FilesystemEnumerator, FoundInput, GitRepoWithMetadataEnumerator, 
    GitignoreBuilder
};
use crossbeam_channel::unbounded;

// Global static reference to the rules database for performance
use lazy_static::lazy_static;

/// Load custom rules from /opt/noseyparker/ directory if it exists
fn load_custom_rules() -> Option<noseyparker_rules::Rules> {
    let custom_rules_dir = std::path::Path::new("/opt/noseyparker");

    if !custom_rules_dir.exists() || !custom_rules_dir.is_dir() {
        info!("Custom rules directory /opt/noseyparker/ not found, using default rules only");
        return None;
    }

    info!("Found custom rules directory at /opt/noseyparker/, loading rules...");
    match noseyparker_rules::Rules::from_directory(custom_rules_dir) {
        Ok(rules) => {
            if rules.is_empty() {
                info!("No custom rules found in /opt/noseyparker/");
                None
            } else {
                info!("Loaded {} custom rules from /opt/noseyparker/", rules.num_rules());
                Some(rules)
            }
        },
        Err(e) => {
            error!("Error loading custom rules from /opt/noseyparker/: {}", e);
            None
        }
    }
}

lazy_static! {
    static ref RULES_DATABASE: Arc<RulesDatabase> = {
        info!("Loading rules at startup...");

        // First, load the built-in rules
        let mut rules_collection = get_builtin_rules()
            .expect("Failed to load default rules");

        info!("Loaded {} built-in rules", rules_collection.num_rules());

        // Then, try to load any custom rules and add them
        if let Some(custom_rules) = load_custom_rules() {
            info!("Adding {} custom rules to the database", custom_rules.num_rules());
            rules_collection.update(custom_rules);
        }

        // Convert the rules to a vector of Rule objects
        let rules: Vec<Rule> = rules_collection.iter_rules()
            .map(|syntax| Rule::new(syntax.clone()))
            .collect();

        let rules_db = RulesDatabase::from_rules(rules)
            .expect("Failed to compile rules");

        info!("Total rules loaded: {}", rules_db.rules().len());
        Arc::new(rules_db)
    };

    static ref CONCURRENCY_SEMAPHORE: Arc<Semaphore> = {
        let max_concurrent_files = std::env::var("MAX_CONCURRENT_FILES")
            .map(|s| s.parse::<usize>().unwrap_or(5))
            .unwrap_or(5);

        info!("Setting maximum concurrent file processing to: {}", max_concurrent_files);
        Arc::new(Semaphore::new(max_concurrent_files))
    };
}

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

// Default values for pub/sub and scanner settings (overridable by environment variables)
const DEFAULT_SNIPPET_LENGTH: usize = 512;

#[derive(Parser, Debug)]
#[command(name = "noseyparker-scanner")]
#[command(author = "NoseyParker Integration")]
#[command(version = "0.1.0")]
#[command(about = "Scans files from MinIO for secrets using NoseyParker")]
struct Args {
    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Length of the snippet context (in bytes) to include before and after matches (default: from SNIPPET_LENGTH env var or 512)
    #[arg(long)]
    snippet_length: Option<usize>,

    /// Use colored output
    #[arg(long, default_value_t = true)]
    color: bool,
}

// Input model that matches the Python pydantic model
#[derive(Debug, Deserialize, Serialize)]
struct NoseyParkerInput {
    object_id: String,
}

// Output model that matches the Python pydantic model
#[derive(Debug, Deserialize, Serialize)]
struct NoseyParkerOutput {
    object_id: String,
    scan_result: ScanResults,
}

/// Simplified match information to avoid Serde issues with NoseyParker internal types
#[derive(Debug, Deserialize, Serialize)]
struct MatchInfo {
    rule_name: String,
    rule_type: String,
    matched_content: String,
    location: MatchLocation,
    snippet: String,
    // New fields for file path and git information
    file_path: Option<String>,
    git_commit: Option<GitCommitInfo>,
}

/// Git commit information
#[derive(Debug, Deserialize, Serialize, Clone)]
struct GitCommitInfo {
    commit_id: String,
    author: String,
    author_email: String,
    commit_date: String,
    message: String,
}

/// Location information for a match
#[derive(Debug, Deserialize, Serialize)]
struct MatchLocation {
    line: u32,
    column: u32,
}

/// Results from scanning a file
#[derive(Debug, Deserialize, Serialize)]
struct ScanResults {
    scan_duration_ms: u128,
    bytes_scanned: u64,
    matches: Vec<MatchInfo>,
    stats: ScanStats,
    // New field to indicate the type of scan
    scan_type: String, // "regular", "zip", "git_repo"
}

/// Statistics from the scan
#[derive(Debug, Deserialize, Serialize)]
struct ScanStats {
    blobs_seen: u64,
    blobs_scanned: u64,
    bytes_seen: u64,
    bytes_scanned: u64,
    matches_found: usize,
}

// The callback handler with memory management
#[topic(pub_sub_name = "pubsub", topic = "noseyparker-input")]
async fn handle_input_event(input: NoseyParkerInput) {
    info!("Processing pub/sub event for object_id: {}", input.object_id);

    // Acquire semaphore permit to limit concurrent processing
    let _permit = match CONCURRENCY_SEMAPHORE.acquire().await {
        Ok(permit) => {
            info!("Acquired processing permit for object_id: {} (permits available: {})",
                  input.object_id, CONCURRENCY_SEMAPHORE.available_permits());
            permit
        },
        Err(e) => {
            error!("Failed to acquire processing permit: {}", e);
            return;
        }
    };

    // Get snippet length from environment or use default
    let snippet_length = std::env::var("SNIPPET_LENGTH")
        .map(|s| s.parse::<usize>().unwrap_or(DEFAULT_SNIPPET_LENGTH))
        .unwrap_or(DEFAULT_SNIPPET_LENGTH);

    info!("Using snippet length: {} bytes", snippet_length);

    // Process the scan request
    let result = process_scan_request(&input.object_id, snippet_length).await;

    // Force memory cleanup after processing (regardless of success/failure)
    force_memory_cleanup();

    match result {
        Ok(scan_results) => {
            // Create output message
            let output = NoseyParkerOutput {
                object_id: input.object_id.clone(),
                scan_result: scan_results,
            };

            // Log the result summary
            info!(
                "Scan complete: Found {} matches in {} bytes",
                output.scan_result.stats.matches_found,
                output.scan_result.bytes_scanned
            );

            // Get pub/sub configuration from environment variables or use defaults
            let pubsub_name = std::env::var("PUBSUB_NAME").unwrap_or_else(|_| "pubsub".to_string());
            let output_topic = std::env::var("OUTPUT_TOPIC").unwrap_or_else(|_| "noseyparker-output".to_string());

            // Publish the result to the output topic
            let output_json = match serde_json::to_string(&output) {
                Ok(json) => json,
                Err(e) => {
                    error!("Failed to serialize output to JSON: {}", e);
                    return;
                }
            };

            info!("Publishing result to output topic: {}", output_topic);

            // Publish results through Dapr client
            match dapr_publish_event(&pubsub_name, &output_topic, &output_json).await {
                Ok(_) => {
                    info!("Successfully published result to Dapr output topic");
                }
                Err(e) => {
                    error!("Failed to publish result to Dapr: {:?}", e);
                    // Print results to console as fallback
                    info!("Results (not published): {}", output_json);
                }
            }
        }
        Err(e) => {
            error!("Error processing scan request: {}", e);
        }
    }

    // Final memory cleanup
    force_memory_cleanup();

    // Permit is automatically released when _permit goes out of scope
    info!("Released processing permit for object_id: {} (permits available: {})",
          input.object_id, CONCURRENCY_SEMAPHORE.available_permits() + 1);
}

/// Force memory cleanup and log memory usage - Enhanced for jemalloc
fn force_memory_cleanup() {
    // Force garbage collection and memory trim on supported platforms
    #[cfg(target_os = "linux")]
    unsafe {
        // malloc_trim works well with jemalloc and forces it to return memory to OS
        let _result = libc::malloc_trim(0);
    }

    // For jemalloc, trigger arena cleanup with allocation patterns
    // jemalloc responds well to allocation/deallocation cycles
    {
        // Force several allocation/deallocation cycles of different sizes
        // This helps jemalloc clean up its internal structures
        for i in 0..3 {
            let size = (i + 1) * 1024 * 1024; // 1MB, 2MB, 3MB
            let _dummy = vec![0u8; size];
            drop(_dummy);
        }
    }

    // Additional cleanup: force a larger allocation/deallocation
    // This can trigger jemalloc to consolidate and return larger chunks
    {
        let _large_cleanup: Vec<u8> = Vec::with_capacity(10 * 1024 * 1024); // 10MB
        drop(_large_cleanup);
    }

    // Force another malloc_trim after the allocation cycles
    #[cfg(target_os = "linux")]
    unsafe {
        libc::malloc_trim(0);
    }

    // Memory barrier to prevent optimizations
    std::hint::black_box(());
}

// Helper function to publish events
async fn dapr_publish_event(pubsub_name: &str, topic: &str, data: &str) -> Result<(), anyhow::Error> {
    // Connect to Dapr sidecar - this uses DAPR_GRPC_PORT implicitly under the hood
    let dapr_addr = "http://127.0.0.1".to_string();
    let mut client = DaprClient::<TonicClient>::connect(dapr_addr.clone()).await?;

    debug!("Publishing JSON: {}", data);

    // Publish the event
    client.publish_event(
        pubsub_name,
        topic,
        data,
        data.as_bytes().to_vec(),
        None
    ).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();

    // Parse command-line arguments
    let args = Args::parse();

    let addr = "0.0.0.0:50042".parse().unwrap();

    // Configure logging
    let env_filter = format!("noseyparker_scanner={},noseyparker={}", args.log_level, args.log_level);
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_ansi(args.color)
        .init();

    let mut callback_service = AppCallbackService::new();

    callback_service.add_handler(HandleInputEvent.get_handler());

    info!("AppCallback server listening on: {}", addr);

    // Create a gRPC server with the callback_service.
    Server::builder()
        .add_service(AppCallbackServer::new(callback_service))
        .serve(addr)
        .await?;

    Ok(())
}

/// Initialize MinIO bucket connection
async fn init_minio() -> Result<Bucket> {
    let access_key = env::var("MINIO_ACCESS_KEY").unwrap_or_else(|_| "minio".to_string());
    let secret_key = env::var("MINIO_SECRET_KEY").unwrap_or_else(|_| "minio123".to_string());
    let endpoint = env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://minio:9000".to_string());
    let bucket_name = env::var("MINIO_BUCKET").unwrap_or_else(|_| "files".to_string());

    let region = Region::Custom {
        region: "us-east-1".to_owned(),
        endpoint,
    };

    // Create credentials object
    let credentials = Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)
        .context("Failed to create credentials")?;

    // Create the bucket with path style access
    let bucket = Bucket::new(&bucket_name, region, credentials)
        .context("Failed to create bucket object")?
        .with_path_style();

    // Check if bucket exists, if not it will fail when we try to use it
    info!("Connected to MinIO bucket: {}", bucket_name);

    Ok(bucket)
}

/// Download a file from MinIO
async fn download_from_minio(bucket: &Bucket, object_id: &str) -> Result<NamedTempFile> {
    info!("Downloading object {} from MinIO", object_id);

    // Get max file size from environment or use default (200MB)
    let max_file_size_mb = std::env::var("MAX_FILE_SIZE_MB")
        .map(|s| s.parse::<i64>().unwrap_or(200))
        .unwrap_or(200);
    let max_file_size_bytes = max_file_size_mb * 1024 * 1024;

    debug!("Maximum file size limit: {} MB ({} bytes)", max_file_size_mb, max_file_size_bytes);

    // Create a temporary file
    let tmp_file = NamedTempFile::new().context("Failed to create temporary file")?;
    let tmp_path = tmp_file.path().to_owned();

    // Get object metadata to check size before downloading
    debug!("Getting object metadata for: {}", object_id);
    match bucket.head_object(object_id).await {
        Ok((metadata, _status_code)) => {
            let object_size = metadata.content_length.unwrap_or(0);
            debug!("Object {} size: {} bytes ({} MB)", object_id, object_size, object_size / (1024 * 1024));

            if object_size > max_file_size_bytes {
                error!("File {} is too large: {} bytes ({} MB) > {} MB limit",
                      object_id, object_size, object_size / (1024 * 1024), max_file_size_mb);
                anyhow::bail!("File size exceeds limit: {} MB > {} MB",
                            object_size / (1024 * 1024), max_file_size_mb);
            } else {
                info!("File {} size check passed: {} bytes ({} MB) <= {} MB limit",
                     object_id, object_size, object_size / (1024 * 1024), max_file_size_mb);
            }
        },
        Err(e) => {
            error!("Failed to get object metadata for {}: {}", object_id, e);
            anyhow::bail!("Failed to get object metadata: {}", e);
        }
    }

    // Download the object
    debug!("Requesting object: {}", object_id);
    let response_data = match bucket.get_object(object_id).await {
        Ok(data) => {
            debug!("Got response with status code: {}", data.status_code());
            data
        },
        Err(e) => {
            error!("Error getting object from MinIO: {}", e);
            anyhow::bail!("Failed to download object from MinIO: {}", e);
        }
    };

    // Check response status
    if response_data.status_code() != 200 {
        error!("Failed download with status code: {}", response_data.status_code());
        anyhow::bail!("Failed to download object: HTTP status {}", response_data.status_code());
    }

    let bytes = response_data.bytes();
    debug!("Downloaded {} bytes from MinIO", bytes.len());

    // Write response body to file
    std::fs::write(&tmp_path, bytes)
        .context("Failed to write downloaded data to temporary file")?;

    info!("Downloaded {} to temporary file: {}", object_id, tmp_path.display());

    Ok(tmp_file)
}

/// Enhanced scan request processor that handles zip files and git repositories
async fn process_scan_request(object_id: &str, snippet_length: usize) -> Result<ScanResults> {
    info!("Starting enhanced scan process for object: {}", object_id);

    // Initialize MinIO connection
    let bucket = init_minio().await?;
    
    // Download the file from MinIO
    let tmp_file = download_from_minio(&bucket, object_id).await?;
    let file_path = tmp_file.path();

    // Check DECOMPRESS_ZIPS environment variable (default: false)
    let decompress_zips = std::env::var("DECOMPRESS_ZIPS")
        .map(|s| s.to_lowercase() == "true")
        .unwrap_or(false);

    info!("DECOMPRESS_ZIPS setting: {}", decompress_zips);

    // Check if it's a zip file and if zip decompression is enabled
    if decompress_zips && is_zip_file(file_path)? {
        info!("Detected zip file and decompression enabled: {}", object_id);
        process_zip_file(file_path, snippet_length).await
    } else {
        info!("Processing as regular file: {}", object_id);
        process_regular_file(file_path, snippet_length).await
    }
}

/// Check if a file is a zip archive
fn is_zip_file(file_path: &std::path::Path) -> Result<bool> {
    let mut file = File::open(file_path)?;
    let mut buffer = [0; 4];
    
    // Read first 4 bytes to check for ZIP signature
    match file.read_exact(&mut buffer) {
        Ok(_) => {
            // ZIP file signature: 0x504B0304 (PK..) or 0x504B0506 (empty archive) or 0x504B0708 (spanned archive)
            Ok(buffer == [0x50, 0x4B, 0x03, 0x04] || 
               buffer == [0x50, 0x4B, 0x05, 0x06] ||
               buffer == [0x50, 0x4B, 0x07, 0x08])
        },
        Err(_) => Ok(false), // File too small to be a zip
    }
}

/// Process a zip file: extract, scan all contents, handle git repos
async fn process_zip_file(zip_path: &std::path::Path, snippet_length: usize) -> Result<ScanResults> {
    let scan_start = Instant::now();
    let mut all_matches = Vec::new();
    let mut total_bytes_scanned = 0u64;
    let mut total_files_scanned = 0u64;

    // Create temporary directory for extraction
    let temp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;
    let extract_path = temp_dir.path();
    
    info!("Extracting zip file to: {}", extract_path.display());
    
    // Extract zip file
    extract_zip_file(zip_path, extract_path)?;
    
    // Check if extracted content contains a git repository
    let git_repo_path = find_git_repository(extract_path)?;
    
    if let Some(git_path) = git_repo_path {
        info!("Found git repository at: {}", git_path.display());
        // Scan git repository with full history using input-enumerator
        let git_results = scan_git_repository_with_enumerator(&git_path, snippet_length).await?;
        all_matches.extend(git_results.matches);
        total_bytes_scanned += git_results.bytes_scanned;
        total_files_scanned += git_results.stats.blobs_scanned;
    } else {
        info!("No git repository found, scanning extracted files with filesystem enumerator");
        // Use FilesystemEnumerator to scan all extracted files
        let filesystem_results = scan_directory_with_enumerator(extract_path, snippet_length).await?;
        all_matches.extend(filesystem_results.matches);
        total_bytes_scanned += filesystem_results.bytes_scanned;
        total_files_scanned += filesystem_results.stats.blobs_scanned;
    }

    // Force cleanup
    drop(temp_dir); // This will automatically clean up the temporary directory
    force_memory_cleanup();

    let scan_duration = scan_start.elapsed();
    let all_matches_len = all_matches.len();
    
    Ok(ScanResults {
        scan_duration_ms: scan_duration.as_millis(),
        bytes_scanned: total_bytes_scanned,
        matches: all_matches,
        stats: ScanStats {
            blobs_seen: total_files_scanned,
            blobs_scanned: total_files_scanned,
            bytes_seen: total_bytes_scanned,
            bytes_scanned: total_bytes_scanned,
            matches_found: all_matches_len,
        },
        scan_type: "zip".to_string(), // Add this line
    })
}

/// Extract a zip file to the specified directory
fn extract_zip_file(zip_path: &std::path::Path, extract_to: &std::path::Path) -> Result<()> {
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;
    
    // Check total uncompressed size to prevent zip bombs
    let max_extract_size = std::env::var("MAX_EXTRACT_SIZE_MB")
        .map(|s| s.parse::<u64>().unwrap_or(1000))
        .unwrap_or(1000) * 1024 * 1024; // Default 1GB
    
    let mut total_size = 0u64;
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        total_size += file.size();
        if total_size > max_extract_size {
            anyhow::bail!("Zip file too large when extracted: {} bytes > {} bytes limit", 
                         total_size, max_extract_size);
        }
    }
    
    info!("Extracting {} files ({} bytes total)", archive.len(), total_size);
    
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => extract_to.join(path),
            None => continue, // Skip files with invalid names
        };

        if file.name().ends_with('/') {
            // Directory
            std::fs::create_dir_all(&outpath)?;
        } else {
            // File
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode))?;
            }
        }
    }
    
    Ok(())
}

/// Find a git repository in the extracted directory
fn find_git_repository(extract_path: &std::path::Path) -> Result<Option<std::path::PathBuf>> {
    info!("Searching for git repository in: {}", extract_path.display());
    
    // Look for .git directory
    for entry in WalkDir::new(extract_path).max_depth(3) {
        let entry = entry?;
        if entry.file_type().is_dir() && entry.file_name() == ".git" {
            let git_dir = entry.path();
            info!("Found .git directory at: {}", git_dir.display());
            
            // Check if it's a valid git directory by looking for essential files
            let head_file = git_dir.join("HEAD");
            let objects_dir = git_dir.join("objects");
            let refs_dir = git_dir.join("refs");
            
            debug!("Checking git directory structure:");
            debug!("  HEAD file exists: {}", head_file.exists());
            debug!("  objects dir exists: {}", objects_dir.exists());
            debug!("  refs dir exists: {}", refs_dir.exists());
            
            if head_file.exists() && objects_dir.exists() {
                if let Some(parent) = git_dir.parent() {
                    return Ok(Some(parent.to_path_buf()));
                }
            } else {
                warn!("Found .git directory but it appears incomplete");
            }
        }
    }
    
    debug!("No valid git repository found in extracted content");
    Ok(None)
}

/// Scan git repository with fallback handling for problematic repositories
async fn scan_git_repository_with_enumerator(git_path: &std::path::Path, snippet_length: usize) -> Result<ScanResults> {
    let scan_start = Instant::now();
    
    info!("Attempting to open git repository at: {}", git_path.display());
    
    // Try the standard approach first (isolated mode)
    let opts = gix::open::Options::isolated().open_path_as_is(true);
    
    let repo = match gix::open_opts(git_path, opts) {
        Err(gix::open::Error::NotARepository { .. }) => {
            // Standard approach failed, try alternatives
            info!("Standard git opening failed, trying alternatives...");
            
            // Try without isolated mode
            let opts2 = gix::open::Options::default().open_path_as_is(true);
            match gix::open_opts(git_path, opts2) {
                Ok(repo) => {
                    info!("Opened repository with non-isolated options");
                    repo
                },
                Err(_) => {
                    // Try gix::discover as final fallback
                    match gix::discover(git_path) {
                        Ok(repo) => {
                            info!("Opened repository with gix::discover");
                            repo
                        },
                        Err(e) => {
                            warn!("All git opening methods failed: {}", e);
                            return scan_directory_with_enumerator(git_path, snippet_length).await;
                        }
                    }
                }
            }
        },
        Err(err) => {
            error!("Failed to open git repository: {}", err);
            return scan_directory_with_enumerator(git_path, snippet_length).await;
        },
        Ok(repo) => {
            info!("Opened repository with standard method");
            repo
        }
    };

    info!("Successfully opened git repository, proceeding with enumeration...");
    
    // Create a gitignore for filtering
    let gitignore = match GitignoreBuilder::new("").build() {
        Ok(gitignore) => gitignore,
        Err(e) => {
            warn!("Failed to create gitignore builder: {}", e);
            return scan_directory_with_enumerator(git_path, snippet_length).await;
        }
    };
    
    // Create git enumerator using the working repo
    let git_enumerator = GitRepoWithMetadataEnumerator::new(git_path, repo, &gitignore);
    
    info!("Running git enumeration...");
    let git_result = match git_enumerator.run() {
        Ok(result) => result,
        Err(e) => {
            warn!("Git enumeration failed: {} - falling back to filesystem scan", e);
            return scan_directory_with_enumerator(git_path, snippet_length).await;
        }
    };
    
    info!("Found {} blobs in git repository using input-enumerator", git_result.blobs.len());
    
    let mut all_matches = Vec::new();
    let mut total_bytes_scanned = 0u64;
    
    // Scan each blob
    for (i, blob_metadata) in git_result.blobs.iter().enumerate() {
        if i % 100 == 0 && i > 0 {
            info!("Processing blob {}/{}", i + 1, git_result.blobs.len());
        }
        
        let blob_oid = blob_metadata.blob_oid;
        let mut blob_data_buffer = Vec::new();
        
        match git_result.repository.objects.find_blob(&blob_oid, &mut blob_data_buffer) {
            Ok(blob_data) => {
                let blob_id = BlobId::compute_from_bytes(blob_data.data);
                let blob = Blob::new(blob_id, blob_data.data.to_vec());
                let appearance = blob_metadata.first_seen.clone();
                
                // Extract file path from the first appearance
                let file_path = if !appearance.is_empty() {
                    Some(appearance[0].path.to_string())
                } else {
                    None
                };
                
                match scan_blob_with_matcher(&blob, snippet_length, &appearance, file_path) {
                    Ok(blob_result) => {
                        all_matches.extend(blob_result.matches);
                        total_bytes_scanned += blob_result.bytes_scanned;
                    },
                    Err(e) => {
                        warn!("Failed to scan git blob {}: {}", blob_oid, e);
                    }
                }
            },
            Err(e) => {
                warn!("Failed to find git blob {}: {}", blob_oid, e);
            }
        }
    }

    let scan_duration = scan_start.elapsed();
    let all_matches_len = all_matches.len();
    
    info!("Git enumeration complete: {} matches found in {} blobs", all_matches_len, git_result.blobs.len());
    
    Ok(ScanResults {
        scan_duration_ms: scan_duration.as_millis(),
        bytes_scanned: total_bytes_scanned,
        matches: all_matches,
        stats: ScanStats {
            blobs_seen: git_result.blobs.len() as u64,
            blobs_scanned: git_result.blobs.len() as u64,
            bytes_seen: total_bytes_scanned,
            bytes_scanned: total_bytes_scanned,
            matches_found: all_matches_len,
        },
        scan_type: "git_repo".to_string(),
    })
}

/// Proceed with the actual input_enumerator GitRepo when it works
async fn proceed_with_actual_git_scan(
    _repo: gix::Repository,  // This should be the correct input_enumerator type, but using gix for now
    git_path: &std::path::Path, 
    snippet_length: usize, 
    _scan_start: Instant
) -> Result<ScanResults> {
    info!("Proceeding with actual git scan");
    
    // For now, let's try to use the FilesystemEnumerator approach since the types don't match
    warn!("Type mismatch between gix::Repository and expected input_enumerator types");
    warn!("Using git-aware filesystem scanning as fallback");
    
    scan_directory_with_git_awareness(git_path, snippet_length).await
}

/// Git-aware filesystem scanning (skips .git directory)
async fn scan_directory_with_git_awareness(git_path: &std::path::Path, snippet_length: usize) -> Result<ScanResults> {
    let scan_start = Instant::now();
    let mut all_matches = Vec::new();
    let mut total_bytes_scanned = 0u64;
    let mut files_scanned = 0u64;

    info!("Scanning git repository as filesystem with git awareness: {}", git_path.display());

    // Skip .git directory when scanning filesystem to avoid scanning git internals
    for entry in WalkDir::new(git_path)
        .into_iter()
        .filter_entry(|e| {
            // Skip .git directory and its contents
            !e.path().components().any(|c| c.as_os_str() == ".git")
        })
    {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!("Error walking directory: {}", e);
                continue;
            }
        };

        if entry.file_type().is_file() {
            let file_path = entry.path();
            
            // Skip binary files and other non-scannable files
            if should_skip_file(file_path) {
                continue;
            }
            
            match scan_single_file(file_path, snippet_length).await {
                Ok(file_result) => {
                    all_matches.extend(file_result.matches);
                    total_bytes_scanned += file_result.bytes_scanned;
                    files_scanned += 1;
                },
                Err(e) => {
                    debug!("Failed to scan file {}: {}", file_path.display(), e);
                }
            }
        }
    }

    let scan_duration = scan_start.elapsed();
    let all_matches_len = all_matches.len();
    
    info!("Completed git-aware filesystem scan: {} files, {} bytes", files_scanned, total_bytes_scanned);
    
    Ok(ScanResults {
        scan_duration_ms: scan_duration.as_millis(),
        bytes_scanned: total_bytes_scanned,
        matches: all_matches,
        stats: ScanStats {
            blobs_seen: files_scanned,
            blobs_scanned: files_scanned,
            bytes_seen: total_bytes_scanned,
            bytes_scanned: total_bytes_scanned,
            matches_found: all_matches_len,
        },
        scan_type: "git_repo".to_string(), // Add this line
    })
}

/// Determine if a file should be skipped during scanning
fn should_skip_file(path: &std::path::Path) -> bool {
    // Get file extension
    let extension = path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();
    
    // Skip binary files and other non-text files
    let binary_extensions = [
        "exe", "dll", "so", "dylib", "bin", "out",
        "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg",
        "mp3", "mp4", "avi", "mov", "wav", "flac",
        "zip", "tar", "gz", "rar", "7z", "bz2",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "class", "jar", "war", "ear",
        "o", "obj", "a", "lib",
    ];
    
    if binary_extensions.contains(&extension.as_str()) {
        return true;
    }
    
    // Skip very large files (over 10MB)
    if let Ok(metadata) = std::fs::metadata(path) {
        let max_file_size = 10 * 1024 * 1024; // 10MB
        if metadata.len() > max_file_size {
            return true;
        }
    }
    
    false
}


/// Scan a directory using the FilesystemEnumerator from input-enumerator crate
async fn scan_directory_with_enumerator(dir_path: &std::path::Path, snippet_length: usize) -> Result<ScanResults> {
    let scan_start = Instant::now();
    let mut all_matches = Vec::new();
    let mut total_bytes_scanned = 0u64;
    let mut files_scanned = 0u64;

    info!("Scanning directory with FilesystemEnumerator: {}", dir_path.display());

    // Create a channel to receive enumerated files
    let (sender, receiver) = unbounded();

    // Configure filesystem enumerator
    let mut enumerator = FilesystemEnumerator::new(&[dir_path])?;
    
    // Configure max file size from environment
    let max_file_size_mb = std::env::var("MAX_FILE_SIZE_MB")
        .map(|s| s.parse::<u64>().unwrap_or(200))
        .unwrap_or(200);
    let max_file_size_bytes = Some(max_file_size_mb * 1024 * 1024);
    
    enumerator
        .max_filesize(max_file_size_bytes)
        .enumerate_git_history(false) // We handle git repos separately
        .collect_git_metadata(false)
        .threads(1); // Use single thread for simplicity in this context

    // Run enumeration in a separate task
    let enum_sender = sender.clone();
    let enum_task = tokio::task::spawn_blocking(move || {
        enumerator.run(enum_sender)
    });

    // Drop the sender so the receiver will eventually close
    drop(sender);

    // Process enumerated files
    while let Ok(found_input) = receiver.recv() {
        match found_input {
            FoundInput::File(file_result) => {
                // debug!("Scanning enumerated file: {}", file_result.path.display());
                
                let file_path_str = file_result.path.to_string_lossy().to_string();
                
                match scan_single_file_with_path(&file_result.path, snippet_length, Some(file_path_str)).await {
                    Ok(file_scan_result) => {
                        all_matches.extend(file_scan_result.matches);
                        total_bytes_scanned += file_scan_result.bytes_scanned;
                        files_scanned += 1;
                    },
                    Err(e) => {
                        warn!("Failed to scan file {}: {}", file_result.path.display(), e);
                    }
                }
            },
            FoundInput::Directory(_) => {
                // Directories are handled by the enumerator automatically
            },
            FoundInput::EnumeratorFile(enum_file) => {
                // This would be for other enumerator files, handle if needed
                debug!("Found enumerator file: {}", enum_file.path.display());
            }
        }
    }

    // Wait for enumeration to complete
    if let Err(e) = enum_task.await {
        error!("Enumeration task failed: {}", e);
    }

    let scan_duration = scan_start.elapsed();
    let all_matches_len = all_matches.len();
    
    info!("Completed directory scan: {} files, {} bytes", files_scanned, total_bytes_scanned);
    
    Ok(ScanResults {
        scan_duration_ms: scan_duration.as_millis(),
        bytes_scanned: total_bytes_scanned,
        matches: all_matches,
        stats: ScanStats {
            blobs_seen: files_scanned,
            blobs_scanned: files_scanned,
            bytes_seen: total_bytes_scanned,
            bytes_scanned: total_bytes_scanned,
            matches_found: all_matches_len,
        },
        scan_type: "zip".to_string(),
    })
}

/// Core blob scanning logic using NoseyParker matcher
fn scan_blob_with_matcher(
    blob: &Blob, 
    snippet_length: usize,
    appearance_info: &input_enumerator::blob_appearance::BlobAppearanceSet,
    file_path: Option<String>
) -> Result<ScanResults> {
    let scan_start = Instant::now();
    
    // Use the globally preloaded rules database
    let seen_blobs = BlobIdMap::new();
    let matcher_stats = Mutex::new(MatcherStats::default());
    let mut matcher = Matcher::new(&RULES_DATABASE, &seen_blobs, Some(&matcher_stats))
        .context("Failed to create matcher")?;

    // Create provenance from appearance info
    let provenance = if appearance_info.is_empty() {
        // Fixed: Use from_file instead of from_unknown which doesn't exist
        Provenance::from_file(PathBuf::from("unknown")).into()
    } else {
        // Use the first appearance for provenance
        let first_appearance = &appearance_info[0];
        // Fixed: Use from_git_repo_with_first_commit instead of from_git_commit
        // and don't double-wrap with Arc since commit_metadata is already Arc<CommitMetadata>
        Provenance::from_git_repo_with_first_commit(
            Arc::new(PathBuf::from(".")), // repo path placeholder
            first_appearance.commit_metadata.clone(), // Already Arc<CommitMetadata>
            first_appearance.path.clone()
        ).into()
    };

    // Scan the blob
    let scan_result = matcher.scan_blob(blob, &provenance)
        .context("Failed to scan blob")?;

    // Process results
    let noseyparker_matches = match scan_result {
        ScanResult::New(blob_matches) => {
            let max_end = blob_matches.iter()
                .map(|m| m.matching_input_offset_span.end)
                .max()
                .unwrap_or_default();

            if max_end > 0 {
                let loc_mapping = location::LocationMapping::new(&blob.bytes[0..max_end]);
                blob_matches.iter()
                    .map(|m| noseyparker::match_type::Match::convert(&loc_mapping, m, snippet_length))
                    .collect()
            } else {
                Vec::new()
            }
        },
        ScanResult::SeenSansMatches => Vec::new(),
        ScanResult::SeenWithMatches => Vec::new(),
    };

    // Extract git commit info from the first appearance if available
    let git_commit_info = if !appearance_info.is_empty() {
        let first_appearance = &appearance_info[0];
        let commit_meta = &first_appearance.commit_metadata;
        
        Some(GitCommitInfo {
            commit_id: commit_meta.commit_id.to_string(),
            author: commit_meta.author_name.to_string(),
            author_email: commit_meta.author_email.to_string(),
            commit_date: format!("{}", commit_meta.author_timestamp), // Use timestamp instead
            message: commit_meta.message.to_string(),
        })
    } else {
        None
    };

    // Convert to MatchInfo
    let matches: Vec<MatchInfo> = noseyparker_matches.into_iter()
        .map(|m| {
            let snippet = format!("{}[{}]{}",
                m.snippet.before,
                m.snippet.matching,
                m.snippet.after);

            let line = m.location.source_span.start.line.try_into().unwrap_or(0);
            let column = m.location.source_span.start.column.try_into().unwrap_or(0);

            MatchInfo {
                rule_name: m.rule_name.clone(),
                rule_type: "secret".to_string(),
                matched_content: m.snippet.matching.to_string(),
                location: MatchLocation { line, column },
                snippet,
                file_path: file_path.clone(),
                git_commit: git_commit_info.clone(),
            }
        })
        .collect();
    
    let matches_count = matches.len();
    let scan_duration = scan_start.elapsed();
    let blob_size = blob.len();

    // Explicitly drop large objects
    drop(matcher);

    Ok(ScanResults {
        scan_duration_ms: scan_duration.as_millis(),
        bytes_scanned: blob_size as u64,
        matches,
        stats: ScanStats {
            blobs_seen: 1,
            blobs_scanned: 1,
            bytes_seen: blob_size as u64,
            bytes_scanned: blob_size as u64,
            matches_found: matches_count,
        },
        scan_type: if git_commit_info.is_some() { "git_repo".to_string() } else { "zip".to_string() },
    })
}

/// Scan a single file with optional file path tracking
async fn scan_single_file_with_path(file_path: &std::path::Path, snippet_length: usize, tracked_path: Option<String>) -> Result<ScanResults> {
    process_regular_file_with_path(file_path, snippet_length, tracked_path).await
}

/// Process a regular file with path tracking
async fn process_regular_file_with_path(file_path: &std::path::Path, snippet_length: usize, tracked_path: Option<String>) -> Result<ScanResults> {
    let scan_start = Instant::now();
    
    // Get file size and system memory info before scanning
    let file_size = match std::fs::metadata(file_path) {
        Ok(metadata) => metadata.len(),
        Err(e) => {
            error!("Failed to get file metadata: {}", e);
            0
        }
    };

    debug!("Scanning regular file: {} ({} bytes)", file_path.display(), file_size);

    // Create a scope to ensure all scan-related variables are dropped
    let (matches, scan_duration, blob_size) = {
        // Prepare for scanning
        let seen_blobs = BlobIdMap::new();
        let matcher_stats = Mutex::new(MatcherStats::default());
        let mut matcher = Matcher::new(&RULES_DATABASE, &seen_blobs, Some(&matcher_stats))
            .context("Failed to create matcher")?;

        // Load the file as a blob
        let blob = Blob::from_file(file_path)
            .with_context(|| format!("Failed to load blob from {}", file_path.display()))?;

        let blob_size = blob.len();

        // Create a provenance for the file
        let provenance = Provenance::from_file(PathBuf::from(file_path)).into();

        // Scan the blob
        let scan_result = matcher.scan_blob(&blob, &provenance)
            .context("Failed to scan blob")?;

        // Process scan results
        let noseyparker_matches = match scan_result {
            ScanResult::New(blob_matches) => {
                let max_end = blob_matches.iter()
                    .map(|m| m.matching_input_offset_span.end)
                    .max()
                    .unwrap_or_default();

                if max_end > 0 {
                    let loc_mapping = location::LocationMapping::new(&blob.bytes[0..max_end]);
                    blob_matches.iter()
                        .map(|m| noseyparker::match_type::Match::convert(&loc_mapping, m, snippet_length))
                        .collect()
                } else {
                    Vec::new()
                }
            },
            ScanResult::SeenSansMatches => Vec::new(),
            ScanResult::SeenWithMatches => Vec::new(),
        };

        // Convert to MatchInfo with file path tracking
        let matches: Vec<MatchInfo> = noseyparker_matches.into_iter()
            .map(|m| {
                let snippet = format!("{}[{}]{}",
                    m.snippet.before,
                    m.snippet.matching,
                    m.snippet.after);

                let line = m.location.source_span.start.line.try_into().unwrap_or(0);
                let column = m.location.source_span.start.column.try_into().unwrap_or(0);

                MatchInfo {
                    rule_name: m.rule_name.clone(),
                    rule_type: "secret".to_string(),
                    matched_content: m.snippet.matching.to_string(),
                    location: MatchLocation { line, column },
                    snippet,
                    file_path: tracked_path.clone(),
                    git_commit: None, // No git commit for regular files
                }
            })
            .collect();

        let scan_duration = scan_start.elapsed();

        // Explicitly drop large objects
        drop(blob);
        drop(matcher);
        drop(seen_blobs);

        (matches, scan_duration, blob_size)
    };

    force_memory_cleanup();

    // Create scan stats
    let scan_stats = ScanStats {
        blobs_seen: 1,
        blobs_scanned: 1,
        bytes_seen: blob_size as u64,
        bytes_scanned: blob_size as u64,
        matches_found: matches.len(),
    };

    Ok(ScanResults {
        scan_duration_ms: scan_duration.as_millis(),
        bytes_scanned: blob_size as u64,
        matches,
        stats: scan_stats,
        scan_type: "regular".to_string(),
    })
}

/// Update the legacy function calls
async fn scan_single_file(file_path: &std::path::Path, snippet_length: usize) -> Result<ScanResults> {
    scan_single_file_with_path(file_path, snippet_length, None).await
}

/// Process a regular file (legacy function)
async fn process_regular_file(file_path: &std::path::Path, snippet_length: usize) -> Result<ScanResults> {
    process_regular_file_with_path(file_path, snippet_length, None).await
}
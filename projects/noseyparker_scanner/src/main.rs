// NoseyParker Scanner - Scan files for secrets using NoseyParker with Dapr pub/sub
// This version includes MinIO integration and Dapr pub/sub

use dapr_macros::topic;
use tonic::transport::Server;
use dapr::{appcallback::*, dapr::proto::runtime::v1::app_callback_server::AppCallbackServer};

use anyhow::{Context, Result};
use clap::Parser;
use dapr::client::{Client as DaprClient, TonicClient};
use dotenv::dotenv;
use indicatif::{HumanBytes, HumanCount};
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
use tracing::{debug, error, info};

use noseyparker::blob::Blob;
use noseyparker::blob_id_map::BlobIdMap;
use noseyparker::defaults::get_builtin_rules;
use noseyparker::location;
use noseyparker::matcher::{Matcher, ScanResult};
use noseyparker::matcher_stats::MatcherStats;
use noseyparker::provenance::Provenance;
use noseyparker::rules_database::RulesDatabase;
use noseyparker_rules::Rule;

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
}

// Use mimalloc for better performance
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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

// The callback handler
#[topic(pub_sub_name = "pubsub", topic = "noseyparker-input")]
async fn handle_input_event(input: NoseyParkerInput) {
    info!("Processing pub/sub event for object_id: {}", input.object_id);

    // Get snippet length from environment or use default
    let snippet_length = std::env::var("SNIPPET_LENGTH")
        .map(|s| s.parse::<usize>().unwrap_or(DEFAULT_SNIPPET_LENGTH))
        .unwrap_or(DEFAULT_SNIPPET_LENGTH);

    info!("Using snippet length: {} bytes", snippet_length);

    // Process the scan request
    match process_scan_request(&input.object_id, snippet_length).await {
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
            // Note: We're using the Dapr SDK's client-side publish method
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

    // Create a temporary file
    let tmp_file = NamedTempFile::new().context("Failed to create temporary file")?;
    let tmp_path = tmp_file.path().to_owned();

    debug!("Attempting to list objects in bucket first");
    match bucket.list("/".to_string(), None).await {
        Ok(list_response) => {
            debug!("Bucket contents:");
            if let Some(objects) = list_response.first() {
                for object in &objects.contents {
                    debug!("- {} (size: {} bytes)", object.key, object.size);
                }
            } else {
                debug!("No objects found in bucket");
            }
        },
        Err(e) => {
            debug!("Failed to list bucket contents: {}", e);
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

/// Process a scan request for the specified object
async fn process_scan_request(object_id: &str, snippet_length: usize) -> Result<ScanResults> {
    info!("Starting scan process for object: {}", object_id);

    // Initialize MinIO connection
    debug!("Initializing MinIO connection...");
    let bucket = match init_minio().await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to initialize MinIO connection: {}", e);
            anyhow::bail!("Failed to initialize MinIO connection: {}", e);
        }
    };

    // Download the file from MinIO
    debug!("Attempting to download object: {}", object_id);
    let tmp_file = match download_from_minio(&bucket, object_id).await {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to download object from MinIO: {}", e);
            anyhow::bail!("Failed to download file from MinIO: {}", e);
        }
    };

    let file_path = tmp_file.path();
    debug!("Temporary file path: {}", file_path.display());

    // Use the globally preloaded rules database
    debug!("Using pre-loaded rules database with {} rules", RULES_DATABASE.rules().len());

    // Prepare for scanning
    let seen_blobs = BlobIdMap::new();
    let matcher_stats = Mutex::new(MatcherStats::default());
    let matcher = Matcher::new(&RULES_DATABASE, &seen_blobs, Some(&matcher_stats))
        .context("Failed to create matcher")?;

    // Load the file as a blob
    info!("Loading file for scanning");
    let blob = Blob::from_file(file_path)
        .with_context(|| format!("Failed to load blob from {}", file_path.display()))?;

    debug!("File loaded, size: {} bytes", blob.len());

    // Create a provenance for the file
    let provenance = Provenance::from_file(PathBuf::from(file_path)).into();

    // Scan the blob
    info!("Scanning file for secrets...");
    let scan_start = Instant::now();

    let mut matcher = matcher;
    let scan_result = matcher.scan_blob(&blob, &provenance)
        .context("Failed to scan blob")?;


    // Process scan results
    let noseyparker_matches = match scan_result {
        ScanResult::New(blob_matches) => {
            debug!("Found {} raw matches", blob_matches.len());

            // Convert raw matches to processed matches
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
        ScanResult::SeenSansMatches => {
            debug!("No matches found (already seen)");
            Vec::new()
        },
        ScanResult::SeenWithMatches => {
            debug!("Matches found (already seen)");
            Vec::new()
        },
    };

    // Convert NoseyParker Match objects to our serializable MatchInfo objects
    let matches: Vec<MatchInfo> = noseyparker_matches.into_iter()
        .map(|m| {
            let rule_name = m.rule_name.clone();

            // Get the snippet content
            let snippet = format!("{}[{}]{}",
                m.snippet.before,
                m.snippet.matching,
                m.snippet.after);

            // Get line/column info from the location
            let line = m.location.source_span.start.line.try_into().unwrap_or(0);
            let column = m.location.source_span.start.column.try_into().unwrap_or(0);

            // Build our match info
            MatchInfo {
                rule_name,
                rule_type: "secret".to_string(), // Simplified for now
                matched_content: m.snippet.matching.to_string(),
                location: MatchLocation { line, column },
                snippet,
            }
        })
        .collect();

    let scan_duration = scan_start.elapsed();

    // Get statistics
    let _stats = matcher_stats.lock().unwrap(); // Prefix with underscore to indicate it's intentionally unused
    let scan_stats = ScanStats {
        blobs_seen: 1,  // We're always scanning 1 blob
        blobs_scanned: 1,  // We're always scanning 1 blob
        bytes_seen: blob.len() as u64,  // Use the actual blob size for reporting
        bytes_scanned: blob.len() as u64,  // Use the actual blob size for reporting
        matches_found: matches.len(),
    };

    // Create a human-readable summary
    let seen_bytes_per_sec = if scan_duration.as_secs_f64() > 0.0 {
        (blob.len() as f64 / scan_duration.as_secs_f64()) as u64
    } else {
        blob.len() as u64
    };

    info!(
        "Scan complete: Scanned {} from {} blobs in {:.3}s ({}/s); {} matches found",
        HumanBytes(blob.len() as u64),
        HumanCount(1),  // We're always scanning 1 blob
        scan_duration.as_secs_f64(),  // Format as seconds with decimal places
        HumanBytes(seen_bytes_per_sec),
        HumanCount(matches.len() as u64),
    );

    // Return the results
    Ok(ScanResults {
        scan_duration_ms: scan_duration.as_millis(),
        bytes_scanned: blob.len() as u64,  // Use the actual blob size for reporting
        matches,
        stats: scan_stats,
    })
}
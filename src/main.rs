use aws_sdk_ecr::Client;
use aws_sdk_ecr::primitives::{DateTime, DateTimeFormat};
use aws_sdk_ecr::types::builders::ImageIdentifierBuilder;
use aws_sdk_ecr::types::{FindingSeverity, ScanType};
use futures::future::join_all;
use std::collections::HashMap;
use std::env;

/// Iterate all repositories in the AWS account and fetch their scan findings.
/// Collects failures and returns error if any repository fails (partial failure tracking for CI).
async fn list_all_repositories(
    client: &aws_sdk_ecr::Client,
    scan_type: &ScanType,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = match client.describe_repositories().send().await {
        Ok(response) => response,
        Err(e) => {
            eprintln!("Error describing repositories: {}", e);
            return Err(e.into());
        }
    };

    // Track success/failure for partial failure reporting (CI monitoring).
    let mut succeeded = 0;
    let mut failed = 0;
    let mut failed_repos = Vec::new();

    for repo in response.repositories.unwrap_or_default() {
        let repository_name = repo.repository_name.unwrap_or_else(|| {
            eprintln!("Repository name not found, skipping");
            String::new()
        });

        if repository_name.is_empty() {
            continue;
        }

        // Process each repository; record failures but continue scanning others.
        if let Err(e) = list_images_in_repository(client, &repository_name, scan_type).await {
            eprintln!("ERROR: Repository '{}': {}", repository_name, e);
            failed_repos.push(repository_name);
            failed += 1;
        } else {
            succeeded += 1;
        }
    }

    // Return error if any repo failed; CI/monitoring can detect partial failures.
    if failed > 0 {
        eprintln!(
            "WARNING: {} of {} repositories failed to scan: {}",
            failed,
            succeeded + failed,
            failed_repos.join(", ")
        );
        return Err(format!("Partial failure: {} repositories skipped", failed).into());
    }

    Ok(())
}

/// Fetch and output scan findings for all images in a single repository.
/// Routes to Basic or Enhanced scan handler based on ScanType.
/// Basic: uses cached image_scan_findings_summary (fast, synchronous).
/// Enhanced: calls describe_image_scan_findings() concurrently for detailed data.
async fn list_images_in_repository(
    client: &aws_sdk_ecr::Client,
    repository_name: &str,
    scan_type: &ScanType,
) -> Result<(), aws_sdk_ecr::Error> {
    // Only Docker and OCI image manifests are supported; other formats are skipped with a warning.
    const SUPPORTED_MEDIA_TYPES: &[&str] = &[
        "application/vnd.docker.container.image.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
    ];

    let response = client
        .describe_images()
        .repository_name(repository_name)
        .send()
        .await?;

    let image_details = response.image_details.unwrap_or_default();

    if image_details.is_empty() {
        return Ok(());
    }

    if scan_type.as_str() == ScanType::Basic.as_str() {
        // Basic scan: findings already cached in image_scan_findings_summary.
        // Fast, synchronous iteration; no additional API calls needed.
        for image_detail in image_details {
            if let Some(media_type) = &image_detail.artifact_media_type {
                if !SUPPORTED_MEDIA_TYPES.contains(&media_type.as_str()) {
                    eprintln!("Unsupported image format: {}", media_type);
                    continue;
                }

                let repo_name = image_detail.repository_name.unwrap_or_default();
                let image_tags = image_detail.image_tags.unwrap_or_default();
                let image_digest = image_detail.image_digest.unwrap_or_default();
                let tags_str = image_tags.join(",");

                if let Some(findings) = image_detail.image_scan_findings_summary {
                    let scan_complete_date = findings.image_scan_completed_at;
                    let update_scan_date = findings.vulnerability_source_updated_at;
                    let severity_map = findings.finding_severity_counts.unwrap_or_default();
                    print_csv_row(
                        &repo_name,
                        &tags_str,
                        &image_digest,
                        scan_complete_date,
                        update_scan_date,
                        &severity_map,
                        false,
                    );
                } else {
                    print_csv_row(
                        &repo_name,
                        &tags_str,
                        &image_digest,
                        None,
                        None,
                        &HashMap::new(),
                        false,
                    );
                }
            }
        }
    } else {
        // Enhanced scan: must call describe_image_scan_findings() per image for detailed data.
        // Concurrent approach: build futures for all images, then join_all() to parallelize.
        // Build async tasks for each image's scan findings fetch.
        // filter_map skips unsupported formats; each Some(async move {...}) captures required data.
        let futures: Vec<_> = image_details
            .iter()
            .filter_map(|image_detail| {
                let media_type = image_detail.artifact_media_type.as_ref()?;
                if !SUPPORTED_MEDIA_TYPES.contains(&media_type.as_str()) {
                    eprintln!("Unsupported image format: {}", media_type);
                    return None;
                }

                let registry_id = image_detail.registry_id.clone()?;
                let repo_name = image_detail.repository_name.clone()?;
                let image_digest = image_detail.image_digest.clone()?;

                // Clone client for concurrent task; AWS SDK clients are cheaply cloneable.
                let client = client.clone();
                Some(async move {
                    let image_identifier = ImageIdentifierBuilder::default()
                        .image_digest(&image_digest)
                        .build();

                    let result = client
                        .describe_image_scan_findings()
                        .registry_id(registry_id)
                        .repository_name(&repo_name)
                        .image_id(image_identifier)
                        .send()
                        .await;

                    (repo_name, image_digest, result)
                })
            })
            .collect();

        // Concurrent await: all image scans run in parallel; bottleneck is slowest API call.
        let results = join_all(futures).await;

        // Zip original image_details with concurrent results; preserves ordering for CSV output.
        // On error, sets error_marker=true (prints -1 in critical column for visibility).
        for image_detail in image_details.iter().zip(results.iter()) {
            let (detail, (repo_name, image_digest, result)) = (image_detail.0, image_detail.1);
            let image_tags = detail.image_tags.as_deref().unwrap_or_default();
            let tags_str = image_tags.join(",");

            match result {
                Ok(response) => {
                    if let Some(findings) = &response.image_scan_findings {
                        let severity_map =
                            findings.finding_severity_counts.clone().unwrap_or_default();
                        let scan_complete_date = findings.image_scan_completed_at;
                        let update_scan_date = findings.vulnerability_source_updated_at;
                        print_csv_row(
                            repo_name,
                            &tags_str,
                            image_digest,
                            scan_complete_date,
                            update_scan_date,
                            &severity_map,
                            false,
                        );
                    } else {
                        print_csv_row(
                            repo_name,
                            &tags_str,
                            image_digest,
                            None,
                            None,
                            &HashMap::new(),
                            false,
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Error fetching scan findings for image {}: {}",
                        image_digest, e
                    );
                    // Partial failure: print row with critical=-1 (error marker for monitoring).
                    print_csv_row(
                        repo_name,
                        &tags_str,
                        image_digest,
                        None,
                        None,
                        &HashMap::new(),
                        true,
                    );
                }
            }
        }
    }
    Ok(())
}

/// Extract vulnerability counts by severity level from the findings map.
/// Returns tuple: (critical, high, medium, low, informational, undefined).
/// Missing severities default to 0 (no findings at that level).
fn get_severity_counts(
    severity_map: &HashMap<FindingSeverity, i32>,
) -> (i32, i32, i32, i32, i32, i32) {
    (
        *severity_map.get(&FindingSeverity::Critical).unwrap_or(&0),
        *severity_map.get(&FindingSeverity::High).unwrap_or(&0),
        *severity_map.get(&FindingSeverity::Medium).unwrap_or(&0),
        *severity_map.get(&FindingSeverity::Low).unwrap_or(&0),
        *severity_map
            .get(&FindingSeverity::Informational)
            .unwrap_or(&0),
        *severity_map.get(&FindingSeverity::Undefined).unwrap_or(&0),
    )
}

/// Escape CSV field for RFC 4180 compliance: quote if contains comma/quote/newline, escape quotes as "".
fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Format and print a single CSV row for one image's scan findings.
/// If error_marker=true, sets critical=-1 to flag partial failures in Enhanced scan.
/// Timestamps are formatted as ISO DateTime if present, otherwise empty.
fn print_csv_row(
    repo_name: &str,
    tags: &str,
    digest: &str,
    scan_complete_date: Option<DateTime>,
    update_scan_date: Option<DateTime>,
    severity_map: &HashMap<FindingSeverity, i32>,
    error_marker: bool,
) {
    let scan_date_str = scan_complete_date
        .and_then(|d| d.fmt(DateTimeFormat::DateTime).ok())
        .unwrap_or_default();
    let update_date_str = update_scan_date
        .and_then(|d| d.fmt(DateTimeFormat::DateTime).ok())
        .unwrap_or_default();

    let (critical, high, medium, low, informational, undefined) = get_severity_counts(severity_map);
    // Mark errors with -1 in critical column for easy identification in CSV output/monitoring.
    let critical = if error_marker { -1 } else { critical };

    let escaped_repo = escape_csv_field(repo_name);
    let escaped_tags = escape_csv_field(tags);
    let escaped_digest = escape_csv_field(digest);
    let escaped_scan_date = escape_csv_field(&scan_date_str);
    let escaped_update_date = escape_csv_field(&update_date_str);

    println!(
        "{},{},{},{},{},{},{},{},{},{},{}",
        escaped_repo,
        escaped_tags,
        escaped_digest,
        escaped_scan_date,
        escaped_update_date,
        critical,
        high,
        medium,
        low,
        informational,
        undefined
    );
}

/// Main entry: load AWS config, parse CLI args (--all, --version, --scan-type), determine scan mode.
/// Outputs CSV to stdout; errors/warnings to stderr.
/// AWS_PROFILE env var controls credential source.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load AWS credentials from environment (AWS_PROFILE env var, ~/.aws/credentials, etc.).
    let config = aws_config::load_from_env().await;
    let client = Client::new(&config);

    // Parse command-line arguments.
    let args: Vec<String> = env::args().collect();

    // Handle --version flag.
    let process_version = args.contains(&String::from("--version"));
    if process_version {
        let version = option_env!("CARGO_PKG_VERSION").unwrap_or("unknown");
        eprintln!("{} version v{}", args[0], version);
        return Ok(());
    }

    let process_all = args.contains(&String::from("--all"));
    let force_basic = args.contains(&String::from("--scan-type=basic"));
    let force_enhanced = args.contains(&String::from("--scan-type=enhanced"));

    if force_basic && force_enhanced {
        eprintln!("ERROR: Cannot specify both --scan-type=basic and --scan-type=enhanced");
        return Err("Invalid scan type arguments".into());
    }

    // Determine target: single repo (args[1]) or all repos (--all).
    let repository_name = if process_all {
        None
    } else if args.len() < 2 {
        eprintln!(
            "Usage: {} [--all | <repository_name> | --version] [--scan-type=auto|basic|enhanced]",
            args[0]
        );
        return Ok(());
    } else {
        Some(&args[1])
    };

    // Output CSV header to stdout.
    println!(
        "repository_name,image_tags,image_digest,image_scan_completed_date,vulnerability_source_updated_date,Critical,High,Medium,Low,Informational,Undefined"
    );

    // Determine scan type: explicit flag > registry config (auto-detect) > Basic default.
    let scan_type = if force_basic {
        eprintln!("INFO: Forcing Basic scan type");
        ScanType::Basic
    } else if force_enhanced {
        eprintln!("INFO: Forcing Enhanced scan type");
        ScanType::Enhanced
    } else {
        // Auto-detect from registry config; fallback to Basic if unconfigured.
        let response = client.get_registry_scanning_configuration().send().await?;
        response
            .scanning_configuration
            .and_then(|config| config.scan_type().cloned())
            .unwrap_or_else(|| {
                eprintln!(
                    "WARNING: No registry scanning configuration found, defaulting to Basic scan"
                );
                ScanType::Basic
            })
    };

    // Route to single-repo or all-repos handler.
    if let Some(repo) = repository_name {
        match list_images_in_repository(&client, repo, &scan_type).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error listing images for repository '{}': {}", repo, e);
                return Err(e.into());
            }
        }
    } else {
        list_all_repositories(&client, &scan_type).await?;
    }

    Ok(())
}

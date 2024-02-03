use aws_sdk_ecr::primitives::{DateTime, DateTimeFormat};
use aws_sdk_ecr::types::FindingSeverity;
use aws_sdk_ecr::Client;
use std::env;

async fn list_all_repositories(
    client: &aws_sdk_ecr::Client, // Client for interacting with AWS ECR
) -> Result<(), Box<dyn std::error::Error>> { // Result indicating success or failure with an error type
    // List all repositories
    let response = match client.describe_repositories().send().await {
        Ok(response) => response, // If successful, store the response
        Err(e) => {
            eprintln!("Error describing repositories: {}", e);
            return Err(e.into()); // Convert the error to a boxed trait object and return it
        }
    };

    // Iterate through each repository
    for repo in response.repositories.unwrap_or_default() {
        // Extract the repository name
        let repository_name = match repo.repository_name {
            Some(name) => name.to_string(), // If found, convert it to a String
            None => {
                eprintln!("Repository name not found");
                continue; // Continue to the next repository if name is not found
            }
        };

        // List images in the current repository
        match list_images_in_repository(client, &repository_name).await {
            Ok(_) => {} // No need to do anything if successful
            Err(e) => {
                eprintln!(
                    "Error listing images for repository '{}': {}",
                    repository_name, e
                );
                return Err(e.into()); // Convert the error to a boxed trait object and return it
            }
        }
    }

    Ok(())
}


// Function to list images in a repository
async fn list_images_in_repository(
    client: &aws_sdk_ecr::Client, // Client for interacting with AWS ECR
    repository_name: &str, // Name of the repository to list images from
) -> Result<(), aws_sdk_ecr::Error> { // Result indicating success or failure with the AWS ECR error type
    // Create a request to describe images in the repository
    let request = client.describe_images().repository_name(repository_name);
    // Send the request and await the response, handling any potential errors
    let response = request.send().await?;
    // Default date to use if specific dates are not available
    let default_date = DateTime::from_secs(0);

    // Iterate through each image detail in the response
    for image_detail in response.image_details.unwrap_or_default() {
        if let Some(media_type) = image_detail.artifact_media_type {
            // Check if the image is in the expected format
            if media_type == "application/vnd.docker.container.image.v1+json" {
                // Extract necessary information about the image
                let repository_name = image_detail.repository_name.unwrap_or_default();
                let image_tag = image_detail.image_tags.unwrap_or_default();
                let image_digest = image_detail.image_digest.unwrap_or_default();
                // Print basic image information
                print!(
                    "{};{};{}",
                    repository_name,
                    image_tag.first().map_or("", |t| t.as_str()), // Use the first tag if available
                    image_digest
                );

                // Check if image scan findings are available
                if let Some(findings) = image_detail.image_scan_findings_summary {
                    // Extract and format relevant scan and vulnerability update dates
                    let scan_complete_date =
                        findings.image_scan_completed_at.unwrap_or(default_date);
                    let update_scan_date = findings
                        .vulnerability_source_updated_at
                        .unwrap_or(default_date);
                    // Extract and print severity counts for different vulnerability levels
                    let severity_map = findings.finding_severity_counts.unwrap_or_default();
                    println!(
                        ";{};{};{};{};{};{};{};{}",
                        scan_complete_date
                            .fmt(DateTimeFormat::DateTime)
                            .unwrap_or_default(),
                        update_scan_date
                            .fmt(DateTimeFormat::DateTime)
                            .unwrap_or_default(),
                        severity_map.get(&FindingSeverity::Critical).unwrap_or(&0),
                        severity_map.get(&FindingSeverity::High).unwrap_or(&0),
                        severity_map.get(&FindingSeverity::Medium).unwrap_or(&0),
                        severity_map.get(&FindingSeverity::Low).unwrap_or(&0),
                        severity_map
                            .get(&FindingSeverity::Informational)
                            .unwrap_or(&0),
                        severity_map.get(&FindingSeverity::Undefined).unwrap_or(&0)
                    );
                } else {
                    // If no scan findings are available, print placeholders for severity counts
                    println!(";;;0;0;0;0;0;0");
                }
            }
        }
    }
    Ok(())
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up AWS credentials and region
    let config = aws_config::load_from_env().await;
    let client = Client::new(&config);

    // Retrieve command-line arguments
    let args: Vec<String> = env::args().collect();

    // Check version
    let process_version = args.contains(&String::from("--version"));
    if process_version {
        let version = option_env!("CARGO_PKG_VERSION").unwrap_or("unknown");
        eprintln!("{} version v{}", args[0], version);
        return Ok(());
    }

    // Check if the user wants to process all repositories
    let process_all = args.contains(&String::from("--all"));
    
    // Check if repository name argument is provided
    let repository_name = if process_all {
        None
    } else if args.len() < 2 {
        eprintln!("Usage: {} [--all | <repository_name> | --version]", args[0]);
        return Ok(());
    } else {
        Some(&args[1])
    };

    // Print headers
    println!(
        "repository_name;image_tags;image_digest;image_scan_completed_date;vulnerability_source_updated_date;Critical;High;Medium;Low;Informational;Undefined"
    );

    // Check if a repository name is provided and list images in that repository
    if let Some(repo) = repository_name {
        match list_images_in_repository(&client, repo).await {
            Ok(_) => {} // No need to do anything if successful
            Err(e) => {
                eprintln!("Error listing images for repository '{}': {}", repo, e);
                return Err(e.into()); // Convert the error to a boxed trait object and return it
            }
        }
    } else {
        // If no repository name is provided, list all repositories
        match list_all_repositories(&client).await {
            Ok(_) => {} // No need to do anything if successful
            Err(e) => {
                eprintln!("Error listing all repositories: {}", e);
                return Err(e); // Return the error as is
            }
        }
    }

    Ok(()) 
}

use anyhow::Result;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::utils;

const GIT_PATHS: &[&str] = &[
    "/.git/HEAD",
    "/.git/config",
    "/.git/description",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.git/logs/refs/heads/master",
    "/.git/logs/refs/heads/main",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.git/COMMIT_EDITMSG",
    "/.git/FETCH_HEAD",
    "/.git/ORIG_HEAD",
    "/.git/packed-refs",
    "/.git/objects/",
    "/.git/refs/",
    "/.git/hooks/",
    "/.git/info/",
    "/.git/info/exclude",
    "/.gitignore",
    "/.gitmodules",
    "/.gitattributes",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitExposure {
    pub url: String,
    pub status_code: u16,
    pub content: String,
    pub exposure_type: String,
    pub severity: String,
}

pub async fn check(subdomains: &[String]) -> Result<Vec<GitExposure>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()?;
    
    let found = Arc::new(Mutex::new(Vec::new()));
    let total = subdomains.len() * GIT_PATHS.len();
    let pb = utils::create_progress_bar(total as u64, "Checking .git exposure");
    
    for subdomain in subdomains {
        let urls: Vec<String> = GIT_PATHS.iter()
            .map(|path| format!("https://{}{}", subdomain, path))
            .chain(GIT_PATHS.iter().map(|path| format!("http://{}{}", subdomain, path)))
            .collect();
        
        let _results: Vec<_> = stream::iter(urls)
            .map(|url| {
                let client = client.clone();
                let found = found.clone();
                let pb = pb.clone();
                
                async move {
                    let resp = client.get(&url).send().await;
                    
                    if let Ok(resp) = resp {
                        let status = resp.status().as_u16();
                        
                        if status == 200 {
                            let body = resp.text().await.unwrap_or_default();
                            
                            // Check if response looks like actual git content
                            if is_git_content(&url, &body) {
                                let (exposure_type, severity) = classify_git_exposure(&url, &body);
                                
                                let exposure = GitExposure {
                                    url: url.clone(),
                                    status_code: status,
                                    content: truncate_content(&body, 200),
                                    exposure_type,
                                    severity,
                                };
                                
                                let mut found = found.lock().await;
                                found.push(exposure);
                            }
                        }
                    }
                    
                    pb.inc(1);
                }
            })
            .buffer_unordered(20)
            .collect()
            .await;
    }
    
    pb.finish_with_message("Done");
    
    let found = Arc::try_unwrap(found).unwrap().into_inner();
    Ok(found)
}

fn is_git_content(url: &str, body: &str) -> bool {
    let url_lower = url.to_lowercase();
    
    if url_lower.ends_with("/head") || url_lower.ends_with("/head/") {
        return body.contains("ref: refs/") || body.starts_with("ref:");
    }
    
    if url_lower.ends_with("/config") {
        return body.contains("[core]") || body.contains("[remote") || body.contains("[branch");
    }
    
    if url_lower.ends_with("/description") {
        return body.contains("Unnamed repository") || body.contains("edit this file");
    }
    
    if url_lower.ends_with("/packed-refs") {
        return body.contains("refs/");
    }
    
    if url_lower.contains("/logs/") {
        return body.contains("commit") || body.contains("merge");
    }
    
    if url_lower.contains("/refs/") {
        return body.len() == 40 || body.len() == 41; // SHA hash
    }
    
    if url_lower.ends_with("/index") {
        return body.starts_with("DIRC") || body.contains("TREE");
    }
    
    // For other paths, check for common non-git responses
    if body.contains("<!DOCTYPE") || body.contains("<html") {
        return false; // HTML page, not git content
    }
    
    if body.contains("404") || body.contains("Not Found") || body.contains("Forbidden") {
        return false;
    }
    
    true
}

fn classify_git_exposure(url: &str, body: &str) -> (String, String) {
    let url_lower = url.to_lowercase();
    
    if url_lower.ends_with("/head") || url_lower.ends_with("/head/") {
        if body.contains("ref: refs/heads/") {
            return ("Git HEAD Reference".to_string(), "HIGH".to_string());
        }
    }
    
    if url_lower.ends_with("/config") {
        if body.contains("[remote") {
            // Can contain remote URLs with credentials
            return ("Git Config with Remote".to_string(), "CRITICAL".to_string());
        }
        return ("Git Configuration".to_string(), "HIGH".to_string());
    }
    
    if url_lower.ends_with("/description") {
        return ("Git Description".to_string(), "LOW".to_string());
    }
    
    if url_lower.contains("/logs/") {
        return ("Git Log Exposure".to_string(), "MEDIUM".to_string());
    }
    
    if url_lower.contains("/refs/") {
        return ("Git References".to_string(), "MEDIUM".to_string());
    }
    
    if url_lower.ends_with("/packed-refs") {
        return ("Git Packed References".to_string(), "MEDIUM".to_string());
    }
    
    if url_lower.ends_with("/index") {
        return ("Git Index File".to_string(), "HIGH".to_string());
    }
    
    if url_lower.contains("/objects/") {
        return ("Git Objects Exposure".to_string(), "CRITICAL".to_string());
    }
    
    if url_lower.contains("/hooks/") {
        return ("Git Hooks Exposure".to_string(), "HIGH".to_string());
    }
    
    ("Git Exposure Detected".to_string(), "MEDIUM".to_string())
}

fn truncate_content(content: &str, max_len: usize) -> String {
    if content.len() <= max_len {
        content.to_string()
    } else {
        format!("{}...", &content[..max_len])
    }
}
use anyhow::Result;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::utils;

const BACKUP_EXTENSIONS: &[&str] = &[
    ".bak", ".old", ".backup", ".orig", ".copy", ".tmp",
    ".swp", ".swo", "~", ".save", ".saved",
    ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".rar", ".7z",
    ".sql", ".sqlite", ".db", ".mdb",
    ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
    ".config", ".conf", ".cfg", ".ini", ".properties",
    ".yml", ".yaml", ".json", ".xml", ".toml",
    ".log", ".dump", ".export",
    ".pem", ".key", ".crt", ".cer", ".p12", ".pfx",
    ".htpasswd", ".htaccess",
    ".DS_Store", ".gitignore", ".svn",
];

const CONFIG_PATHS: &[&str] = &[
    "/config", "/conf", "/cfg", "/settings", "/admin",
    "/backup", "/backups", "/bak", "/old", "/temp", "/tmp",
    "/db", "/database", "/sql", "/data",
    "/logs", "/log", "/debug",
    "/test", "/testing", "/dev", "/development", "/staging",
    "/.env", "/wp-config.php", "/config.php", "/configuration.php",
    "/web.config", "/appsettings.json", "/config.json", "/config.yml",
    "/settings.json", "/application.yml", "/application.properties",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.git/config", "/.svn/entries", "/.hg/dirstate",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    "/elmah.axd", "/trace.axd",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub url: String,
    pub status_code: u16,
    pub content_length: u64,
    pub content_type: String,
    pub finding_type: String,
}

pub async fn fuzz(subdomains: &[String], wordlist_path: Option<&Path>) -> Result<Vec<FuzzResult>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()?;
    
    let mut paths: Vec<String> = Vec::new();
    
    // Add config paths
    for path in CONFIG_PATHS {
        paths.push(path.to_string());
    }
    
    // Add backup extensions for common files
    let base_files = &["index", "backup", "database", "db", "dump", "export", "www", "public", "html", "site"];
    for base in base_files {
        for ext in BACKUP_EXTENSIONS {
            paths.push(format!("/{}{}", base, ext));
        }
    }
    
    // Add custom wordlist if provided
    if let Some(wordlist) = wordlist_path {
        let custom = std::fs::read_to_string(wordlist)?;
        for line in custom.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                paths.push(if line.starts_with('/') {
                    line.to_string()
                } else {
                    format!("/{}", line)
                });
            }
        }
    }
    
    let found = Arc::new(Mutex::new(Vec::new()));
    let total = subdomains.len() * paths.len();
    let pb = utils::create_progress_bar(total as u64, "Fuzzing for files");
    
    for subdomain in subdomains {
        let urls: Vec<String> = paths.iter()
            .map(|path| format!("https://{}{}", subdomain, path))
            .collect();
        
        let _results: Vec<_> = stream::iter(urls)
            .map(|url| {
                let client = client.clone();
                let found = found.clone();
                let pb = pb.clone();
                let url_clone = url.clone();
                
                async move {
                    let resp = client.get(&url).send().await;
                    
                    if let Ok(resp) = resp {
                        let status = resp.status().as_u16();
                        let content_length = resp.content_length().unwrap_or(0);
                        let content_type = resp.headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("unknown")
                            .to_string();
                        
                        // Only report interesting responses (not 404, not 0 length)
                        if status != 404 && status != 403 && content_length > 0 {
                            let finding_type = classify_finding(&url_clone, status, &content_type);
                            
                            if !finding_type.is_empty() {
                                let result = FuzzResult {
                                    url: url_clone,
                                    status_code: status,
                                    content_length,
                                    content_type,
                                    finding_type,
                                };
                                
                                let mut found = found.lock().await;
                                found.push(result);
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

fn classify_finding(url: &str, status: u16, _content_type: &str) -> String {
    let url_lower = url.to_lowercase();
    
    if url_lower.contains(".env") && status == 200 {
        return "Exposed Environment File".to_string();
    }
    
    if url_lower.contains(".git") && status == 200 {
        return "Exposed Git Repository".to_string();
    }
    
    if url_lower.contains(".svn") && status == 200 {
        return "Exposed SVN Repository".to_string();
    }
    
    if url_lower.contains("wp-config") || url_lower.contains("config.php") {
        return "Exposed Configuration File".to_string();
    }
    
    if url_lower.contains("phpinfo") || url_lower.contains("info.php") {
        return "PHP Info Exposure".to_string();
    }
    
    if url_lower.contains(".sql") || url_lower.contains("database") || url_lower.contains("dump") {
        return "Potential Database Dump".to_string();
    }
    
    if url_lower.contains(".bak") || url_lower.contains(".backup") || url_lower.contains(".old") {
        return "Backup File".to_string();
    }
    
    if url_lower.contains(".tar") || url_lower.contains(".zip") || url_lower.contains(".rar") {
        return "Archive File".to_string();
    }
    
    if url_lower.contains(".pem") || url_lower.contains(".key") || url_lower.contains(".crt") {
        return "Exposed Certificate/Key".to_string();
    }
    
    if url_lower.contains(".log") || url_lower.contains("debug") || url_lower.contains("trace") {
        return "Log/Debug File".to_string();
    }
    
    if url_lower.contains("phpmyadmin") || url_lower.contains("adminer") {
        return "Database Admin Panel".to_string();
    }
    
    if url_lower.contains("server-status") || url_lower.contains("server-info") {
        return "Server Status Page".to_string();
    }
    
    if url_lower.contains("elmah") || url_lower.contains("trace.axd") {
        return ".NET Error Log".to_string();
    }
    
    if url_lower.contains("robots.txt") && status == 200 {
        return "Robots.txt".to_string();
    }
    
    if url_lower.contains(".htpasswd") && status == 200 {
        return "Exposed htpasswd".to_string();
    }
    
    if url_lower.contains(".htaccess") && status == 200 {
        return "Exposed htaccess".to_string();
    }
    
    String::new()
}
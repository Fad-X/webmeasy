use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Command;

/// Result from httpx probing a host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpxResult {
    pub url: String,
    pub final_url: String,
    pub status_code: u16,
    pub title: String,
    pub tech: Vec<String>,
    pub content_length: u64,
    pub webserver: String,
    pub content_type: String,
    pub online: bool,
}

/// Parse httpx JSONL output into structured results
pub fn parse_httpx_output(stdout: &str) -> Vec<HttpxResult> {
    let mut results = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // httpx -json outputs JSONL
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            let url = val["url"].as_str().unwrap_or("").to_string();
            let final_url = val["final_url"].as_str().unwrap_or(&url).to_string();
            let status_code = val["status_code"].as_i64().unwrap_or(0) as u16;
            let title = val["title"].as_str().unwrap_or("").to_string();
            let tech: Vec<String> = val["tech"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|t| t.as_str()).map(String::from).collect())
                .unwrap_or_default();
            let content_length = val["content_length"].as_u64().unwrap_or(0);
            let webserver = val["webserver"].as_str().unwrap_or("").to_string();
            let content_type = val["content_type"]
                .as_str()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();

            if !url.is_empty() {
                results.push(HttpxResult {
                    url,
                    final_url,
                    status_code,
                    title,
                    tech,
                    content_length,
                    webserver,
                    content_type,
                    online: true,
                });
            }
        }
    }
    results
}

/// Run httpx against a list of targets and return parsed results.
pub async fn probe(targets: &[String]) -> Result<Vec<HttpxResult>> {
    println!("    [~] Probing targets with httpx (protocol, status, technologies)...");

    // Write targets to a temp file for httpx -l
    let tmp_path = std::env::temp_dir().join(format!("webmeasy_targets_{}.txt", std::process::id()));
    let content = targets.join("\n") + "\n";
    std::fs::write(&tmp_path, &content)?;

    let output = Command::new("httpx")
        .args([
            "-l",
            tmp_path.to_str().unwrap(),
            "-json",
            "-silent",
            "-title",
            "-tech-detect",
            "-web-server",
            "-content-length",
            "-content-type",
            "-status-code",
            "-follow-redirects",
            "-threads",
            "25",
        ])
        .output();

    let _ = std::fs::remove_file(&tmp_path);

    match output {
        Ok(out) => {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let results = parse_httpx_output(&stdout);
                println!("    [+] httpx found {} live hosts", results.len());
                Ok(results)
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                anyhow::bail!("httpx failed: {}", stderr);
            }
        }
        Err(e) => {
            anyhow::bail!(
                "httpx not found: {}. Install it from https://github.com/projectdiscovery/httpx",
                e
            );
        }
    }
}

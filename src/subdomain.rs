use anyhow::Result;
use std::path::Path;
use std::process::Command;

/// Subdomain enumeration via subfinder (passive: CT logs, search engines, APIs, etc.)
/// Optionally merges results from a custom wordlist.
pub async fn enumerate(domain: &str, wordlist_path: Option<&Path>) -> Result<Vec<String>> {
    println!("    [~] Running subfinder (CT logs, search engines, DNS datasets, APIs)...");
    
    let mut cmd = Command::new("subfinder");
    cmd.args(&["-d", domain, "-silent", "-all", "-recursive"]);
    
    if let Some(wordlist) = wordlist_path {
        cmd.args(&["-w", wordlist.to_str().unwrap()]);
    }
    
    match cmd.output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut subdomains: Vec<String> = stdout
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect();
            
            println!("    [+] subfinder returned {} subdomains", subdomains.len());
            subdomains.sort();
            subdomains.dedup();
            Ok(subdomains)
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("subfinder exited with error: {}", stderr);
        }
        Err(e) => {
            anyhow::bail!("subfinder not found: {}. Run with --install-deps or install manually", e);
        }
    }
}

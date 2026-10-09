use anyhow::Result;
use std::process::Command;

use crate::utils;

pub async fn enumerate(domain: &str, wordlist_path: Option<&std::path::Path>) -> Result<Vec<String>> {
    println!("    [~] Running subfinder for passive subdomain enumeration...");
    
    let mut cmd = Command::new("subfinder");
    cmd.args(&[
        "-d", domain,
        "-silent",
        "-all",
    ]);
    
    if let Some(wordlist) = wordlist_path {
        cmd.args(&["-w", wordlist.to_str().unwrap()]);
    }
    
    let output = cmd.output();
    
    match output {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let subdomains: Vec<String> = stdout
                    .lines()
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect();
                
                // Also run active DNS brute-force with resolvers
                let brute_results = active_bruteforce(domain).await?;
                
                let mut all_subdomains = subdomains;
                all_subdomains.extend(brute_results);
                all_subdomains.sort();
                all_subdomains.dedup();
                
                Ok(all_subdomains)
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("    [!] subfinder failed: {}", stderr);
                // Fallback to active brute-force only
                active_bruteforce(domain).await
            }
        }
        Err(e) => {
            println!("    [!] subfinder not found: {}. Falling back to active brute-force.", e);
            active_bruteforce(domain).await
        }
    }
}

async fn active_bruteforce(domain: &str) -> Result<Vec<String>> {
    let wordlist = include_str!("../wordlists/subdomains.txt");
    let candidates: Vec<String> = wordlist
        .lines()
        .map(|line| format!("{}.{}", line.trim(), domain))
        .collect();
    
    let resolver = trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf()?;
    let mut found = Vec::new();
    
    let pb = utils::create_progress_bar(candidates.len() as u64, "Active DNS brute-force");
    
    use futures::stream::{self, StreamExt};
    
    stream::iter(candidates)
        .map(|subdomain| {
            let resolver = resolver.clone();
            let pb = pb.clone();
            async move {
                let result = resolver.lookup_ip(&subdomain).await;
                pb.inc(1);
                if result.is_ok() {
                    Some(subdomain)
                } else {
                    None
                }
            }
        })
        .buffer_unordered(100)
        .filter_map(|r| async { r })
        .for_each(|sub| {
            found.push(sub);
            futures::future::ready(())
        })
        .await;
    
    pb.finish_with_message("Done");
    Ok(found)
}
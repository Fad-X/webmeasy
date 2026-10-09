use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiResult {
    pub target: String,
    pub template_id: String,
    pub severity: String,
    pub name: String,
    pub description: String,
}

pub async fn scan(subdomains: &[String], templates_path: Option<&Path>) -> Result<Vec<NucleiResult>> {
    let mut results = Vec::new();
    
    let pb = crate::utils::create_progress_bar(subdomains.len() as u64, "Scanning with Nuclei");
    
    for target in subdomains {
        let mut cmd = Command::new("nuclei");
        cmd.args(&[
            "-target", target,
            "-json",
            "-silent",
            "-no-color",
        ]);
        
        if let Some(templates) = templates_path {
            cmd.args(&["-t", templates.to_str().unwrap()]);
        }
        
        let output = cmd.output();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if let Ok(result) = serde_json::from_str::<NucleiResult>(line) {
                            results.push(result);
                        }
                    }
                }
            }
            Err(_) => {
                // Nuclei not installed or failed to run
                pb.println(format!("    [!] Failed to run nuclei on {}", target));
            }
        }
        
        pb.inc(1);
    }
    
    pb.finish_with_message("Done");
    
    if results.is_empty() {
        println!("    [!] No vulnerabilities found (or nuclei not installed)");
    }
    
    Ok(results)
}
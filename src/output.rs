use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::nuclei::NucleiResult;
use crate::fuzzer::FuzzResult;
use crate::git_check::GitExposure;

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub target: String,
    pub subdomains: Vec<String>,
    pub nuclei_results: Vec<NucleiResult>,
    pub fuzz_results: Vec<FuzzResult>,
    pub git_exposures: Vec<GitExposure>,
    pub summary: Summary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Summary {
    pub total_subdomains: usize,
    pub total_vulnerabilities: usize,
    pub total_fuzz_findings: usize,
    pub total_git_exposures: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
}

pub struct Output {
    subdomains: Vec<String>,
    nuclei_results: Vec<NucleiResult>,
    fuzz_results: Vec<FuzzResult>,
    git_exposures: Vec<GitExposure>,
    output_path: Option<PathBuf>,
}

impl Output {
    pub fn new(output_path: Option<PathBuf>) -> Self {
        Self {
            subdomains: Vec::new(),
            nuclei_results: Vec::new(),
            fuzz_results: Vec::new(),
            git_exposures: Vec::new(),
            output_path,
        }
    }
    
    pub fn add_subdomains(&mut self, subdomains: Vec<String>) {
        self.subdomains = subdomains;
    }
    
    pub fn add_nuclei_results(&mut self, results: Vec<NucleiResult>) {
        self.nuclei_results = results;
    }
    
    pub fn add_fuzz_results(&mut self, results: Vec<FuzzResult>) {
        self.fuzz_results = results;
    }
    
    pub fn add_git_results(&mut self, results: Vec<GitExposure>) {
        self.git_exposures = results;
    }
    
    pub fn generate_report(&self) -> Result<()> {
        let critical = self.nuclei_results.iter().filter(|r| r.severity == "critical").count()
            + self.git_exposures.iter().filter(|e| e.severity == "CRITICAL").count();
        
        let high = self.nuclei_results.iter().filter(|r| r.severity == "high").count()
            + self.git_exposures.iter().filter(|e| e.severity == "HIGH").count();
        
        // Print summary to console
        self.print_summary(critical, high);
        
        // Print detailed findings
        self.print_findings();
        
        // Save JSON report if output path specified
        if let Some(path) = &self.output_path {
            let report = Report {
                target: String::new(),
                subdomains: self.subdomains.clone(),
                nuclei_results: self.nuclei_results.clone(),
                fuzz_results: self.fuzz_results.clone(),
                git_exposures: self.git_exposures.clone(),
                summary: Summary {
                    total_subdomains: self.subdomains.len(),
                    total_vulnerabilities: self.nuclei_results.len(),
                    total_fuzz_findings: self.fuzz_results.len(),
                    total_git_exposures: self.git_exposures.len(),
                    critical_findings: critical,
                    high_findings: high,
                },
            };
            
            let json = serde_json::to_string_pretty(&report)?;
            std::fs::write(path, json)?;
        }
        
        Ok(())
    }
    
    fn print_summary(&self, critical: usize, high: usize) {
        println!("\n{}", "════════════════════════════════════════════════════════════════".bright_cyan());
        println!("{}", "                        SCAN SUMMARY                          ".bright_cyan().bold());
        println!("{}", "════════════════════════════════════════════════════════════════".bright_cyan());
        
        println!("  {:<30} {}", "Subdomains Found:", self.subdomains.len().to_string().bright_white().bold());
        println!("  {:<30} {}", "Vulnerabilities:", self.nuclei_results.len().to_string().bright_white().bold());
        println!("  {:<30} {}", "Fuzz Findings:", self.fuzz_results.len().to_string().bright_white().bold());
        println!("  {:<30} {}", "Git Exposures:", self.git_exposures.len().to_string().bright_white().bold());
        println!("  {:<30} {}", "Critical Findings:", critical.to_string().bright_red().bold());
        println!("  {:<30} {}", "High Findings:", high.to_string().bright_yellow().bold());
        
        println!("{}", "════════════════════════════════════════════════════════════════".bright_cyan());
    }
    
    fn print_findings(&self) {
        if !self.nuclei_results.is_empty() {
            println!("\n{}", "[*] Nuclei Vulnerability Scan Results:".bright_yellow().bold());
            for result in &self.nuclei_results {
                let severity_color = match result.severity.as_str() {
                    "critical" => result.severity.bright_red().bold(),
                    "high" => result.severity.bright_red(),
                    "medium" => result.severity.bright_yellow(),
                    "low" => result.severity.bright_blue(),
                    _ => result.severity.bright_white(),
                };
                println!("    {} [{}] {} - {}", 
                    result.target.bright_white(),
                    severity_color,
                    result.name.bright_cyan(),
                    result.description.dimmed()
                );
            }
        }
        
        if !self.fuzz_results.is_empty() {
            println!("\n{}", "[*] Fuzzing Results:".bright_yellow().bold());
            for result in &self.fuzz_results {
                let status_color = match result.status_code {
                    200 => result.status_code.to_string().bright_green(),
                    301..=302 => result.status_code.to_string().bright_cyan(),
                    _ => result.status_code.to_string().bright_yellow(),
                };
                println!("    {} [{}] {} ({}) - {}", 
                    result.url.bright_white(),
                    status_color,
                    result.finding_type.bright_magenta(),
                    format!("{} bytes", result.content_length).dimmed(),
                    result.content_type.dimmed()
                );
            }
        }
        
        if !self.git_exposures.is_empty() {
            println!("\n{}", "[*] Git Exposure Results:".bright_yellow().bold());
            for exposure in &self.git_exposures {
                let severity_color = match exposure.severity.as_str() {
                    "CRITICAL" => exposure.severity.bright_red().bold(),
                    "HIGH" => exposure.severity.bright_red(),
                    "MEDIUM" => exposure.severity.bright_yellow(),
                    "LOW" => exposure.severity.bright_blue(),
                    _ => exposure.severity.bright_white(),
                };
                println!("    {} [{}] {}", 
                    exposure.url.bright_white(),
                    severity_color,
                    exposure.exposure_type.bright_magenta()
                );
                if !exposure.content.is_empty() {
                    println!("      Content: {}", exposure.content.dimmed());
                }
            }
        }
    }
}
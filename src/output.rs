use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::fuzzer::FuzzResult;
use crate::git_check::GitExposure;
use crate::httpx::HttpxResult;
use crate::nuclei::NucleiResult;
use crate::report::{self, ReportData};

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub target: String,
    pub scan_date: String,
    pub subdomains: Vec<String>,
    pub httpx_results: Vec<HttpxResult>,
    pub nuclei_results: Vec<NucleiResult>,
    pub fuzz_results: Vec<FuzzResult>,
    pub git_exposures: Vec<GitExposure>,
    pub summary: Summary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Summary {
    pub total_subdomains: usize,
    pub total_live_hosts: usize,
    pub total_vulnerabilities: usize,
    pub total_fuzz_findings: usize,
    pub total_git_exposures: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
}

pub struct Output {
    domain: String,
    subdomains: Vec<String>,
    httpx_results: Vec<HttpxResult>,
    nuclei_results: Vec<NucleiResult>,
    fuzz_results: Vec<FuzzResult>,
    git_exposures: Vec<GitExposure>,
    json_path: Option<PathBuf>,
    pdf_path: Option<PathBuf>,
}

impl Output {
    pub fn new(json_path: Option<PathBuf>, pdf_path: Option<PathBuf>) -> Self {
        Self {
            domain: String::new(),
            subdomains: Vec::new(),
            httpx_results: Vec::new(),
            nuclei_results: Vec::new(),
            fuzz_results: Vec::new(),
            git_exposures: Vec::new(),
            json_path,
            pdf_path,
        }
    }

    pub fn set_domain(&mut self, domain: &str) {
        self.domain = domain.to_string();
    }

    pub fn add_subdomains(&mut self, subdomains: Vec<String>) {
        self.subdomains = subdomains;
    }

    pub fn add_httpx(&mut self, results: Vec<HttpxResult>) {
        self.httpx_results = results;
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
        let critical = self.nuclei_results.iter().filter(|r| r.severity.eq_ignore_ascii_case("critical")).count()
            + self.git_exposures.iter().filter(|e| e.severity.eq_ignore_ascii_case("critical")).count();

        let high = self.nuclei_results.iter().filter(|r| r.severity.eq_ignore_ascii_case("high")).count()
            + self.git_exposures.iter().filter(|e| e.severity.eq_ignore_ascii_case("high")).count();

        self.print_summary(critical, high);
        self.print_findings();

        // JSON
        if let Some(path) = &self.json_path {
            let report = Report {
                target: self.domain.clone(),
                scan_date: chrono_now(),
                subdomains: self.subdomains.clone(),
                httpx_results: self.httpx_results.clone(),
                nuclei_results: self.nuclei_results.clone(),
                fuzz_results: self.fuzz_results.clone(),
                git_exposures: self.git_exposures.clone(),
                summary: Summary {
                    total_subdomains: self.subdomains.len(),
                    total_live_hosts: self.httpx_results.len(),
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

        // PDF
        if let Some(path) = &self.pdf_path {
            let data = ReportData {
                domain: self.domain.clone(),
                scan_date: chrono_now(),
                subdomains: self.subdomains.clone(),
                httpx: self.httpx_results.clone(),
                nuclei: self.nuclei_results.clone(),
                fuzz: self.fuzz_results.clone(),
                git: self.git_exposures.clone(),
            };
            report::generate_pdf(&data, path)?;
        }

        Ok(())
    }

    fn print_summary(&self, critical: usize, high: usize) {
        println!(
            "\n{}",
            "════════════════════════════════════════════════════════════════".bright_cyan()
        );
        println!(
            "{}",
            "                        SCAN SUMMARY                          "
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "════════════════════════════════════════════════════════════════".bright_cyan()
        );

        println!(
            "  {:<30} {}",
            "Subdomains Found:",
            self.subdomains.len().to_string().bright_white().bold()
        );
        println!(
            "  {:<30} {}",
            "Live Hosts:",
            self.httpx_results.len().to_string().bright_white().bold()
        );
        println!(
            "  {:<30} {}",
            "Vulnerabilities:",
            self.nuclei_results.len().to_string().bright_white().bold()
        );
        println!(
            "  {:<30} {}",
            "Fuzz Findings:",
            self.fuzz_results.len().to_string().bright_white().bold()
        );
        println!(
            "  {:<30} {}",
            "Git Exposures:",
            self.git_exposures.len().to_string().bright_white().bold()
        );
        println!(
            "  {:<30} {}",
            "Critical Findings:",
            critical.to_string().bright_red().bold()
        );
        println!(
            "  {:<30} {}",
            "High Findings:",
            high.to_string().bright_yellow().bold()
        );

        println!(
            "{}",
            "════════════════════════════════════════════════════════════════".bright_cyan()
        );
    }

    fn print_findings(&self) {
        if !self.httpx_results.is_empty() {
            println!(
                "\n{}",
                "[*] Live Hosts:".bright_yellow().bold()
            );
            for h in &self.httpx_results {
                let tech = if h.tech.is_empty() {
                    String::new()
                } else {
                    format!(" | {}", h.tech.join(", ").bright_magenta())
                };
                println!(
                    "    {} [{}] {}{}",
                    h.url.bright_white(),
                    format!("{}", h.status_code).bright_cyan(),
                    h.title.bright_green(),
                    tech
                );
            }
        }

        if !self.nuclei_results.is_empty() {
            println!(
                "\n{}",
                "[*] Nuclei Vulnerability Scan Results:".bright_yellow().bold()
            );
            for result in &self.nuclei_results {
                let severity_color = match result.severity.to_lowercase().as_str() {
                    "critical" => result.severity.bright_red().bold(),
                    "high" => result.severity.bright_red(),
                    "medium" => result.severity.bright_yellow(),
                    "low" => result.severity.bright_blue(),
                    _ => result.severity.bright_white(),
                };
                println!(
                    "    {} [{}] {} - {}",
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
                println!(
                    "    {} [{}] {} ({}) - {}",
                    result.url.bright_white(),
                    status_color,
                    result.finding_type.bright_magenta(),
                    format!("{} bytes", result.content_length).dimmed(),
                    result.content_type.dimmed()
                );
            }
        }

        if !self.git_exposures.is_empty() {
            println!(
                "\n{}",
                "[*] Git Exposure Results:".bright_yellow().bold()
            );
            for exposure in &self.git_exposures {
                let severity_color = match exposure.severity.as_str() {
                    "CRITICAL" => exposure.severity.bright_red().bold(),
                    "HIGH" => exposure.severity.bright_red(),
                    "MEDIUM" => exposure.severity.bright_yellow(),
                    "LOW" => exposure.severity.bright_blue(),
                    _ => exposure.severity.bright_white(),
                };
                println!(
                    "    {} [{}] {}",
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

fn chrono_now() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

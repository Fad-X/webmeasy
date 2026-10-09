use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "webmeasy")]
#[command(about = "Web Application Enumeration Tool for External Attack Surface Mapping")]
#[command(version)]
pub struct Args {
    /// Target domain to enumerate
    #[arg(short, long)]
    pub domain: String,

    /// Enable subdomain enumeration (via subfinder)
    #[arg(short, long)]
    pub subdomains: bool,

    /// Probe live hosts with httpx (protocol, status, technologies)
    #[arg(short, long)]
    pub probe: bool,

    /// Run Nuclei vulnerability scan
    #[arg(short, long)]
    pub nuclei: bool,

    /// Fuzz for backup files and configurations
    #[arg(short, long)]
    pub fuzz: bool,

    /// Check for exposed .git directories
    #[arg(short, long)]
    pub git: bool,

    /// Run all enumeration modules
    #[arg(short, long)]
    pub all: bool,

    /// Custom wordlist path for subdomain enumeration
    #[arg(short, long)]
    pub wordlist: Option<PathBuf>,

    /// Custom Nuclei templates directory
    #[arg(long)]
    pub nuclei_templates: Option<PathBuf>,

    /// JSON output file path
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// PDF output file path
    #[arg(long)]
    pub pdf: Option<PathBuf>,

    /// Install missing dependencies (subfinder, httpx, nuclei) via go install
    #[arg(long)]
    pub install_deps: bool,
}

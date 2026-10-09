use clap::Parser;
use colored::*;

mod cli;
mod subdomain;
mod nuclei;
mod fuzzer;
mod git_check;
mod output;
mod utils;

use cli::Args;
use output::Output;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    println!("{}", "
 ██╗    ██╗███████╗██████╗ ███╗   ███╗███████╗ █████╗ ███████╗██╗   ██╗
 ██║    ██║██╔════╝██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝
 ██║ █╗ ██║█████╗  ██████╔╝██╔████╔██║█████╗  ███████║███████╗ ╚████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝  ██╔══██║╚════██║  ╚██╔╝╝
 ╚███╔███╔╝███████╗██████╔╝██║ ╚═╝ ██║███████╗██║  ██║███████║   ██║   
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ".bright_cyan());
    
    println!("{}", "Web Application Enumeration Tool v0.1.0".bright_white().bold());
    println!("{}", "External Attack Surface Mapper".bright_white());
    println!();
    
    let mut output = Output::new(args.output.clone());
    
    // Subdomain enumeration
    if args.subdomains || args.all {
        println!("{}", "[*] Starting subdomain enumeration...".bright_yellow().bold());
        let subdomains = subdomain::enumerate(&args.domain, args.wordlist.as_deref()).await?;
        
        if subdomains.is_empty() {
            println!("{}", "[!] No subdomains found".bright_red());
        } else {
            println!("{}", format!("[+] Found {} subdomains", subdomains.len()).bright_green().bold());
            for sub in &subdomains {
                println!("    {}", sub.bright_white());
            }
            output.add_subdomains(subdomains.clone());
            
            // Run nuclei on discovered subdomains if requested
            if args.nuclei || args.all {
                println!("\n{}", "[*] Running Nuclei vulnerability scan...".bright_yellow().bold());
                let nuclei_results = nuclei::scan(&subdomains, args.nuclei_templates.as_deref()).await?;
                output.add_nuclei_results(nuclei_results);
            }
            
            // Fuzz for backup files and configs
            if args.fuzz || args.all {
                println!("\n{}", "[*] Fuzzing for backup files and configurations...".bright_yellow().bold());
                let fuzz_results = fuzzer::fuzz(&subdomains, args.wordlist.as_deref()).await?;
                output.add_fuzz_results(fuzz_results);
            }
            
            // Check for exposed .git
            if args.git || args.all {
                println!("\n{}", "[*] Checking for exposed .git directories...".bright_yellow().bold());
                let git_results = git_check::check(&subdomains).await?;
                output.add_git_results(git_results);
            }
        }
    }
    
    // Generate report
    output.generate_report()?;
    
    if let Some(path) = &args.output {
        println!("\n{}", format!("[+] Report saved to: {}", path.display()).bright_green().bold());
    }
    
    println!("\n{}", "[*] Enumeration complete!".bright_cyan().bold());
    
    Ok(())
}
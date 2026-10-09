use clap::Parser;
use colored::*;

mod cli;
mod deps;
mod fuzzer;
mod git_check;
mod httpx;
mod nuclei;
mod output;
mod report;
mod subdomain;
mod utils;

use cli::Args;
use output::Output;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!(
        "{}",
        r#"
 ██╗    ██╗███████╗██████╗ ███╗   ███╗███████╗ █████╗ ███████╗██╗   ██╗
 ██║    ██║██╔════╝██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝
 ██║ █╗ ██║█████╗  ██████╔╝██╔████╔██║█████╗  ███████║███████╗ ╚████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝  ██╔══██║╚════██║  ╚██╔╝╝
 ╚███╔███╔╝███████╗██████╔╝██║ ╚═╝ ██║███████╗██║  ██║███████║   ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   "#
            .bright_cyan()
    );

    println!(
        "{}",
        "Web Application Enumeration Tool v0.2.0"
            .bright_white()
            .bold()
    );
    println!("{}", "External Attack Surface Mapper".bright_white());
    println!();

    // ---- dependency check / install ----
    if args.install_deps {
        println!("{}", "[*] Installing missing dependencies...".bright_yellow().bold());
        let installed = deps::install_missing()?;
        if installed.is_empty() {
            println!("{}", "[✓] Nothing to install".bright_green());
        }
        return Ok(());
    }

    println!("{}", "[*] Checking dependencies...".bright_yellow().bold());
    let deps_ok = deps::ensure_tools()?;

    let mut output = Output::new(args.output.clone(), args.pdf.clone());
    output.set_domain(&args.domain);

    // ---- subdomain enumeration ----
    if args.subdomains || args.all {
        println!(
            "{}",
            "[*] Starting subdomain enumeration...".bright_yellow().bold()
        );
        let subdomains = subdomain::enumerate(&args.domain, args.wordlist.as_deref()).await?;

        if subdomains.is_empty() {
            println!("{}", "[!] No subdomains found".bright_red());
        } else {
            println!(
                "{}",
                format!("[+] Found {} subdomains", subdomains.len())
                    .bright_green()
                    .bold()
            );
            for sub in &subdomains {
                println!("    {}", sub.bright_white());
            }
            output.add_subdomains(subdomains.clone());

            // ---- httpx probing ----
            if deps_ok && (args.all || args.probe || args.nuclei || args.fuzz || args.git) {
                println!(
                    "\n{}",
                    "[*] Probing live hosts with httpx...".bright_yellow().bold()
                );
                match httpx::probe(&subdomains).await {
                    Ok(hosts) => {
                        for h in &hosts {
                            let tech_str = if h.tech.is_empty() {
                                String::new()
                            } else {
                                format!(" | {}", h.tech.join(", ").bright_magenta())
                            };
                            println!(
                                "    {} [{}] {}{}",
                                h.url.bright_white(),
                                format!("{}", h.status_code).bright_cyan(),
                                h.title.bright_green(),
                                tech_str
                            );
                        }
                        output.add_httpx(hosts);
                    }
                    Err(e) => {
                        println!("    [!] httpx skipped: {}", e.to_string().yellow());
                    }
                }
            }

            // ---- nuclei ----
            if args.nuclei || args.all {
                println!(
                    "\n{}",
                    "[*] Running Nuclei vulnerability scan...".bright_yellow().bold()
                );
                if deps_ok {
                    match nuclei::scan(&subdomains, args.nuclei_templates.as_deref()).await {
                        Ok(r) => output.add_nuclei_results(r),
                        Err(e) => println!("    [!] nuclei skipped: {}", e.to_string().yellow()),
                    }
                } else {
                    println!("{}", "    [!] nuclei unavailable (dependency missing)".yellow());
                }
            }

            // ---- fuzzing ----
            if args.fuzz || args.all {
                println!(
                    "\n{}",
                    "[*] Fuzzing for backup files and configurations...".bright_yellow().bold()
                );
                match fuzzer::fuzz(&subdomains, args.wordlist.as_deref()).await {
                    Ok(r) => output.add_fuzz_results(r),
                    Err(e) => println!("    [!] fuzzer skipped: {}", e.to_string().yellow()),
                }
            }

            // ---- git check ----
            if args.git || args.all {
                println!(
                    "\n{}",
                    "[*] Checking for exposed .git directories...".bright_yellow().bold()
                );
                match git_check::check(&subdomains).await {
                    Ok(r) => output.add_git_results(r),
                    Err(e) => println!("    [!] git check skipped: {}", e.to_string().yellow()),
                }
            }
        }
    }

    // ---- report ----
    output.generate_report()?;

    if let Some(path) = &args.output {
        println!(
            "\n{}",
            format!("[+] JSON report saved to: {}", path.display()).bright_green().bold()
        );
    }
    if let Some(path) = &args.pdf {
        println!(
            "{}",
            format!("[+] PDF report saved to: {}", path.display()).bright_green().bold()
        );
    }

    println!(
        "\n{}",
        "[*] Enumeration complete!".bright_cyan().bold()
    );

    Ok(())
}

use anyhow::Result;
use std::process::Command;

const TOOLS: &[(&str, &str)] = &[
    ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
];

/// Check if a tool exists on PATH
pub fn is_installed(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Install missing tools via `go install`. Returns list of newly installed tools.
pub fn install_missing() -> Result<Vec<String>> {
    if !is_installed("go") {
        anyhow::bail!(
            "Go is not installed. Install it from https://go.dev/dl/ then re-run with --install-deps"
        );
    }
    
    let mut installed = Vec::new();
    
    for (tool, pkg) in TOOLS {
        if is_installed(tool) {
            println!("    [✓] {} already installed", tool);
            continue;
        }
        
        println!("    [~] Installing {}...", tool);
        let status = Command::new("go")
            .args(["install", "-v", pkg])
            .status()?;
        
        if status.success() {
            println!("    [✓] {} installed", tool);
            installed.push(tool.to_string());
        } else {
            println!("    [!] Failed to install {}", tool);
        }
    }
    
    // Ensure $HOME/go/bin is on PATH for this session
    let go_bin = dirs_home().join("go").join("bin");
    if let Some(path) = std::env::var_os("PATH") {
        let mut paths: Vec<_> = std::env::split_paths(&path).collect();
        if !paths.contains(&go_bin) {
            paths.insert(0, go_bin);
            if let Ok(new_path) = std::env::join_paths(paths) {
                std::env::set_var("PATH", new_path);
            }
        }
    }
    
    Ok(installed)
}

/// Prompt the user to install missing tools interactively. Returns true if all present after.
pub fn ensure_tools() -> Result<bool> {
    let missing: Vec<&str> = TOOLS
        .iter()
        .map(|(tool, _)| *tool)
        .filter(|t| !is_installed(t))
        .collect();
    
    if missing.is_empty() {
        println!("    [✓] All dependencies present: subfinder, httpx, nuclei");
        return Ok(true);
    }
    
    println!("\n    [!] Missing tools: {}", missing.join(", "));
    println!("    [?] Install them now via `go install`? [Y/n] ");
    
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let answer = input.trim().to_lowercase();
    
    if answer.is_empty() || answer == "y" || answer == "yes" {
        install_missing()?;
        // Re-check
        let still_missing: Vec<&str> = TOOLS
            .iter()
            .map(|(tool, _)| *tool)
            .filter(|t| !is_installed(t))
            .collect();
        if still_missing.is_empty() {
            return Ok(true);
        }
        println!("    [!] Still missing: {}", still_missing.join(", "));
    } else {
        println!("    [!] Some features will be unavailable. Install manually:");
        for (_tool, pkg) in TOOLS.iter().filter(|(t, _)| missing.contains(t)) {
            println!("        go install {}", pkg);
        }
    }
    
    Ok(false)
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/root"))
}

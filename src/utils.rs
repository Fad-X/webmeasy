use indicatif::{ProgressBar, ProgressStyle};

pub fn create_progress_bar(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(&format!("    [{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos}}/{{len}} {}", message))
            .unwrap()
            .progress_chars("█▓░"),
    );
    pb
}
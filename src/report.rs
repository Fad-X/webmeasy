use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::fuzzer::FuzzResult;
use crate::git_check::GitExposure;
use crate::httpx::HttpxResult;
use crate::nuclei::NucleiResult;

// ---------------------------------------------------------------------------
// Embedded PDF builder (no external crates — minimal PDF 1.4 writer)
// ---------------------------------------------------------------------------

const PAGE_W: f32 = 595.28; // A4 width in points
const PAGE_H: f32 = 841.89; // A4 height in points
const MARGIN: f32 = 50.0;

struct PdfWriter {
    pages: Vec<String>,
}

impl PdfWriter {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
        }
    }

    fn add_page(&mut self, content: &str) {
        self.pages.push(content.to_string());
    }

    fn build(&self, title: &str, author: &str) -> Vec<u8> {
        let mut body = String::new();
        let mut offsets: Vec<usize> = Vec::new();
        // header
        body.push_str("%PDF-1.4\n%\u{E2}\u{E3}\u{CF}\u{D3}\n");

        let mut objs: Vec<String> = Vec::new();

        // obj 1: Catalog
        objs.push("<< /Type /Catalog /Pages 2 0 R >>".into());
        // obj 2: Pages (filled later)
        let pages_obj_idx = 1; // placeholder
        let _ = pages_obj_idx;

        // obj 3: F1 Helvetica
        objs.push(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".into(),
        );
        // obj 4: F2 Helvetica-Bold
        objs.push(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>".into(),
        );
        // obj 5: F3 Courier
        objs.push(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>".into(),
        );

        // We'll collect content stream objects and page objects starting at obj 6
        let mut content_stream_objs: Vec<String> = Vec::new();
        let mut page_objs: Vec<String> = Vec::new();

        for page_content in &self.pages {
            let stream = format!(
                "<< /Length {} >>\nstream\n{}\nendstream",
                page_content.len(),
                page_content
            );
            content_stream_objs.push(stream);
        }

        // page objects reference their content stream
        // After header objs (1-5), content streams start at 6
        let first_content_obj = 6usize;
        for i in 0..self.pages.len() {
            let cs_obj = first_content_obj + i;
            let page_obj = format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {} 0 R >>",
                PAGE_W, PAGE_H, cs_obj
            );
            page_objs.push(page_obj);
        }

        // Now assemble all objects
        // obj 1 catalog, obj 2 pages, 3 F1, 4 F2, 5 F3
        // then content streams (one per page), then page objects
        let pages_kids: Vec<String> = (0..self.pages.len())
            .map(|i| format!("{} 0 R", first_content_obj + self.pages.len() + i))
            .collect();

        let pages_dict = format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            pages_kids.join(" "),
            self.pages.len()
        );
        // rebuild objs properly
        objs.clear();
        objs.push("<< /Type /Catalog /Pages 2 0 R >>".into());
        objs.push(pages_dict);
        objs.push(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".into(),
        );
        objs.push(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>".into(),
        );
        objs.push(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>".into(),
        );
        for cs in &content_stream_objs {
            objs.push(cs.clone());
        }
        for p in &page_objs {
            objs.push(p.clone());
        }

        // metadata (info dict)
        let info = format!("<< /Title ({}) /Author ({}) /Creator (webmeasy v0.2.0) /Producer (webmeasy) >>",
            escape_pdf(title), escape_pdf(author));

        // write xref
        for (i, obj) in objs.iter().enumerate() {
            offsets.push(body.len());
            body.push_str(&format!("{} 0 obj\n{}\nendobj\n", i + 1, obj));
        }
        // info object
        let info_num = objs.len() + 1;
        offsets.push(body.len());
        body.push_str(&format!("{} 0 obj\n{}\nendobj\n", info_num, info));

        let xref_start = body.len();
        let total_objs = objs.len() + 1; // + info
        body.push_str(&format!("xref\n0 {}\n", total_objs + 1));
        body.push_str("0000000000 65535 f \n");
        for off in &offsets {
            body.push_str(&format!("{:010} 00000 n \n", off));
        }
        body.push_str(&format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info {} 0 R >>\nstartxref\n{}\n%%EOF\n",
            total_objs + 1,
            info_num,
            xref_start
        ));

        body.into_bytes()
    }
}

fn escape_pdf(s: &str) -> String {
    s.replace('\\', "\\\\").replace('(', "\\(").replace(')', "\\)")
}

// ---------------------------------------------------------------------------
// Report data
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportData {
    pub domain: String,
    pub scan_date: String,
    pub subdomains: Vec<String>,
    pub httpx: Vec<HttpxResult>,
    pub nuclei: Vec<NucleiResult>,
    pub fuzz: Vec<FuzzResult>,
    pub git: Vec<GitExposure>,
}

// ---------------------------------------------------------------------------
// Content builder
// ---------------------------------------------------------------------------

struct Cursor {
    y: f32,
    content: String,
    pages: Vec<String>,
    page_num: usize,
}

impl Cursor {
    fn new() -> Self {
        Self {
            y: PAGE_H - MARGIN,
            content: String::new(),
            pages: Vec::new(),
            page_num: 1,
        }
    }

    fn need_space(&mut self, h: f32) {
        if self.y - h < MARGIN {
            self.pages.push(self.content.clone());
            self.content.clear();
            self.page_num += 1;
            self.y = PAGE_H - MARGIN;
            // page number footer
            let pn = format!("BT /F1 8 Tf 250 30 Td (page {}) Tj ET", self.page_num);
            // actually footer is drawn at end; skip here
            let _ = pn;
        }
    }

    fn text(&mut self, x: f32, text: &str, font: &str, size: f32, gray: f32) {
        self.need_space(size + 4.0);
        let esc = escape_pdf(text);
        self.content.push_str(&format!(
            "BT /{} {} Tf {} {} {} g {} {} Td ({}) Tj ET\n",
            font, size, gray, gray, gray, x, self.y, esc
        ));
        self.y -= size + 4.0;
    }

    fn line(&mut self) {
        self.need_space(8.0);
        self.content.push_str(&format!(
            "0.6 w 0.6 g {} {} m {} {} l S\n",
            MARGIN, self.y, PAGE_W - MARGIN, self.y
        ));
        self.y -= 12.0;
    }

    fn spacer(&mut self, h: f32) {
        self.y -= h;
        if self.y < MARGIN {
            self.pages.push(self.content.clone());
            self.content.clear();
            self.page_num += 1;
            self.y = PAGE_H - MARGIN;
        }
    }

    fn heading(&mut self, text: &str) {
        self.spacer(16.0);
        self.text(MARGIN, text, "F2", 16.0, 0.1);
        self.line();
    }

    fn sub_heading(&mut self, text: &str) {
        self.spacer(8.0);
        self.text(MARGIN, text, "F2", 12.0, 0.2);
    }

    fn body(&mut self, text: &str) {
        self.text(MARGIN + 10.0, text, "F1", 10.0, 0.3);
    }

    fn mono(&mut self, text: &str) {
        self.text(MARGIN + 10.0, text, "F3", 8.5, 0.3);
    }

    fn finish(mut self) -> Vec<String> {
        if !self.content.is_empty() {
            self.pages.push(self.content);
        }
        self.pages
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn generate_pdf(data: &ReportData, path: &Path) -> Result<()> {
    let mut pdf = PdfWriter::new();
    let pages = build_content(data);
    for p in pages {
        pdf.add_page(&p);
    }
    let bytes = pdf.build(&format!("webmeasy Report – {}", data.domain), "webmeasy");
    std::fs::write(path, bytes)?;
    Ok(())
}

fn build_content(data: &ReportData) -> Vec<String> {
    let mut c = Cursor::new();

    // ---- Cover ----
    c.spacer(200.0);
    c.text(MARGIN, "webmeasy", "F2", 42.0, 0.0);
    c.text(MARGIN, "External Attack Surface Report", "F1", 18.0, 0.3);
    c.spacer(30.0);
    c.text(MARGIN, &format!("Target:  {}", data.domain), "F2", 14.0, 0.15);
    c.text(MARGIN, &format!("Date:    {}", data.scan_date.split('T').next().unwrap_or(&data.scan_date)), "F1", 12.0, 0.35);
    c.spacer(40.0);
    c.line();
    c.spacer(20.0);
    c.text(MARGIN, "Modules: subfinder  |  httpx  |  nuclei  |  backup fuzzer  |  .git detector", "F1", 10.0, 0.45);

    // ---- Executive Summary ----
    c.heading("1  Executive Summary");
    c.body(&format!("Subdomains discovered ........ {}", data.subdomains.len()));
    c.body(&format!("Live hosts (httpx) ........... {}", data.httpx.len()));
    c.body(&format!("Nuclei findings .............. {}", data.nuclei.len()));
    c.body(&format!("Backup / config findings ..... {}", data.fuzz.len()));
    c.body(&format!(".git exposures ............... {}", data.git.len()));
    c.spacer(8.0);

    let critical = data.nuclei.iter().filter(|r| r.severity.eq_ignore_ascii_case("critical")).count()
        + data.git.iter().filter(|e| e.severity.eq_ignore_ascii_case("critical")).count();
    let high = data.nuclei.iter().filter(|r| r.severity.eq_ignore_ascii_case("high")).count()
        + data.git.iter().filter(|e| e.severity.eq_ignore_ascii_case("high")).count();
    c.body(&format!("Critical findings ............ {}", critical));
    c.body(&format!("High findings ................ {}", high));

    // ---- Live Hosts ----
    if !data.httpx.is_empty() {
        c.heading("2  Live Hosts & Web Technologies");
        let mut hosts = data.httpx.clone();
        hosts.sort_by(|a, b| a.url.cmp(&b.url));
        for h in &hosts {
            c.sub_heading(&h.url);
            c.mono(&format!("  status {}  |  {} bytes  |  server: {}", h.status_code, h.content_length, if h.webserver.is_empty() { "-" } else { &h.webserver }));
            if !h.title.is_empty() {
                c.mono(&format!("  title  {}", h.title));
            }
            if !h.tech.is_empty() {
                c.mono(&format!("  tech   {}", h.tech.join(", ")));
            }
        }
    }

    // ---- Subdomains ----
    if !data.subdomains.is_empty() {
        c.heading("3  Discovered Subdomains");
        let mut subs = data.subdomains.clone();
        subs.sort();
        for s in &subs {
            c.mono(s);
        }
    }

    // ---- Nuclei ----
    if !data.nuclei.is_empty() {
        c.heading("4  Nuclei Vulnerability Findings");
        let mut findings = data.nuclei.clone();
        findings.sort_by(|a, b| {
            sev_rank(&b.severity).cmp(&sev_rank(&a.severity)).then(a.target.cmp(&b.target))
        });
        for f in &findings {
            c.sub_heading(&format!("[{}] {} – {}", f.severity.to_uppercase(), f.name, f.target));
            if !f.description.is_empty() {
                c.body(&f.description);
            }
            c.mono(&format!("  template: {}", f.template_id));
        }
    }

    // ---- Fuzz ----
    if !data.fuzz.is_empty() {
        c.heading("5  Backup & Configuration Findings");
        let mut findings = data.fuzz.clone();
        findings.sort_by(|a, b| a.url.cmp(&b.url));
        for f in &findings {
            c.sub_heading(&format!("[{}] {}", f.finding_type, f.url));
            c.mono(&format!("  status {}  |  {} bytes  |  {}", f.status_code, f.content_length, f.content_type));
        }
    }

    // ---- Git ----
    if !data.git.is_empty() {
        c.heading("6  Exposed Git / SVN Repositories");
        let mut findings = data.git.clone();
        findings.sort_by(|a, b| {
            sev_rank(&b.severity).cmp(&sev_rank(&a.severity)).then(a.url.cmp(&b.url))
        });
        for f in &findings {
            c.sub_heading(&format!("[{}] {} – {}", f.severity, f.exposure_type, f.url));
            if !f.content.is_empty() {
                c.mono(&format!("  snippet: {}", f.content.chars().take(120).collect::<String>()));
            }
        }
    }

    // ---- Footer on every page ----
    // We'll inject page numbers after finish
    c.finish()
}

fn sev_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

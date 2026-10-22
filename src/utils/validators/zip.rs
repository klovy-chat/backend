// zip.rs
// Ochrona dokumentów: zip bomb, traversal, makra Office, CSV jako tekst.
// Zakres:
//  - docx/xlsx/pptx (OOXML), pdf, csv
//  - zip bomb / traversal / vba; czat ZIP nadal nieprzyjmowany
// Domyślnie czat nie przyjmuje ZIP — zostaw zamknięte.
// Przy zmianach: file_type.rs.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use zip::read::ZipArchive;

const MAX_ZIP_DECLARED_UNCOMPRESSED: u64 = 32 * 1024 * 1024;

const MAX_ZIP_ENTRIES: usize = 512;

const MAX_ZIP_COMPRESSION_RATIO: u64 = 80;

const PDF_EOF_SCAN_BYTES: u64 = 4096;

const MAX_PDF_OBJECT_MARKERS: usize = 5_000;

const PDF_DANGEROUS_PATTERNS: &[&[u8]] = &[b"/JavaScript", b"/Launch", b"/OpenAction"];

pub fn validate_upload_document(path: &Path, ext: &str) -> bool {
    match ext.to_ascii_lowercase().as_str() {
        "docx" => validate_office_zip(path, "docx"),
        "xlsx" => validate_office_zip(path, "xlsx"),
        "pptx" => validate_office_zip(path, "pptx"),
        "pdf" => validate_pdf_document(path),
        "csv" => validate_csv_document(path),
        _ => true,
    }
}

pub async fn validate_upload_document_async(path: std::path::PathBuf, ext: String) -> bool {
    tokio::task::spawn_blocking(move || validate_upload_document(&path, &ext))
        .await
        .unwrap_or(false)
}

fn validate_office_zip(path: &Path, kind: &str) -> bool {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(_) => return false,
    };

    if archive.len() > MAX_ZIP_ENTRIES {
        return false;
    }

    let mut declared_uncompressed: u64 = 0;
    let mut declared_compressed: u64 = 0;
    let mut has_content_types = false;
    let mut has_kind_root = false;

    for index in 0..archive.len() {
        let entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(_) => return false,
        };

        let name = entry.name();
        if name.contains("..") || name.starts_with('/') || name.contains('\\') {
            return false;
        }

        if office_entry_forbidden(name) {
            return false;
        }

        if name == "[Content_Types].xml" {
            has_content_types = true;
        }
        match kind {
            "docx" if name.starts_with("word/") => has_kind_root = true,
            "xlsx" if name.starts_with("xl/") => has_kind_root = true,
            "pptx" if name.starts_with("ppt/") => has_kind_root = true,
            _ => {}
        }

        let uncompressed = entry.size();
        let compressed = entry.compressed_size();
        declared_uncompressed = declared_uncompressed.saturating_add(uncompressed);
        declared_compressed = declared_compressed.saturating_add(compressed);

        if declared_uncompressed > MAX_ZIP_DECLARED_UNCOMPRESSED {
            return false;
        }
    }

    if declared_compressed > 0 {
        let ratio = declared_uncompressed.saturating_div(declared_compressed.max(1));
        if ratio > MAX_ZIP_COMPRESSION_RATIO {
            return false;
        }
    }

    has_content_types && has_kind_root
}

fn office_entry_forbidden(name: &str) -> bool {
    let n = name.replace('\\', "/").to_ascii_lowercase();
    if n.contains("vbaproject") || n.contains("vbadata") || n.contains("macrosheets/") {
        return true;
    }
    let ext = n.rsplit('.').next().unwrap_or("");
    matches!(
        ext,
        "exe"
            | "dll"
            | "bat"
            | "cmd"
            | "ps1"
            | "js"
            | "vbs"
            | "hta"
            | "jar"
            | "scr"
            | "com"
            | "msi"
            | "lnk"
            | "wsf"
    )
}

fn validate_csv_document(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut body = Vec::new();
    if file.read_to_end(&mut body).is_err() {
        return false;
    }
    if body.is_empty() || body.len() as u64 > crate::utils::upload::MAX_ATTACHMENT_BYTES {
        return false;
    }
    if body.contains(&0) {
        return false;
    }
    let without_bom = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&body[..]);
    let trimmed = without_bom
        .iter()
        .copied()
        .skip_while(|b| b.is_ascii_whitespace());
    let start: Vec<u8> = trimmed.take(8).collect();
    if start.starts_with(b"<") || start.starts_with(b"%PDF") || start.starts_with(b"PK") {
        return false;
    }
    true
}

fn validate_pdf_document(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let len = match file.metadata() {
        Ok(meta) => meta.len(),
        Err(_) => return false,
    };

    if len < 8 || len > crate::utils::upload::MAX_HTTP_BODY_BYTES as u64 {
        return false;
    }

    let mut header = [0u8; 8];
    if file.read_exact(&mut header).is_err() {
        return false;
    }
    if !header.starts_with(b"%PDF-") {
        return false;
    }

    let scan_len = PDF_EOF_SCAN_BYTES.min(len);
    let start = len.saturating_sub(scan_len);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return false;
    }

    let mut tail = vec![0u8; scan_len as usize];
    if file.read_exact(&mut tail).is_err() {
        return false;
    }
    if !tail.windows(5).any(|window| window == b"%%EOF") {
        return false;
    }

    if file.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }

    let mut body = Vec::new();
    if file.read_to_end(&mut body).is_err() {
        return false;
    }

    for pattern in PDF_DANGEROUS_PATTERNS {
        if contains_ascii_insensitive(&body, pattern) {
            return false;
        }
    }

    let object_markers = body
        .windows(4)
        .filter(|window| *window == b" obj" || *window == b"endobj")
        .count();
    object_markers <= MAX_PDF_OBJECT_MARKERS
}

fn contains_ascii_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

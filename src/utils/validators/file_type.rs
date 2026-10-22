// file_type.rs
// Magic bytes vs rozszerzenie (sync + async).
// Zakres:
//  - nie ufaj nazwie pliku
//  - magic bytes vs rozszerzenie; nie ufaj nazwie
//  - mp3/aac/mov/heic/pptx/csv: MIME + magic
// Nowy typ: magic + FE attachments.ts + MIME allowlista.
// Przy zmianach: controllers messages/auth, attachments.ts.

use std::fs::File;
use std::io::Read;
use std::path::Path;

fn detect_image_type(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"\xff\xd8\xff") {
        return Some("jpeg");
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("png");
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some("webp");
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("gif");
    }
    None
}

fn read_header(path: &Path) -> Option<Vec<u8>> {
    let mut file = File::open(path).ok()?;
    let mut buf = [0u8; 8192];
    let n = file.read(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

fn is_ftyp(data: &[u8]) -> bool {
    data.len() >= 12 && &data[4..8] == b"ftyp"
}

/// Koniec boxa ftyp (nie skanuj następnych atomów jako brandów).
fn ftyp_box_end(data: &[u8]) -> usize {
    if !is_ftyp(data) {
        return 0;
    }
    let size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    match size {
        // size 0/1 nie występuje w prawdziwym ftyp — nie skanuj następnych atomów.
        0 | 1 => 16.min(data.len()),
        n if n < 16 => 0,
        n => n.min(data.len()).min(64),
    }
}

fn ftyp_brands(data: &[u8]) -> Vec<[u8; 4]> {
    let end = ftyp_box_end(data);
    if end < 12 {
        return Vec::new();
    }
    let mut brands = Vec::new();
    let mut major = [0u8; 4];
    major.copy_from_slice(&data[8..12]);
    brands.push(major);
    let mut offset = 16;
    while offset + 4 <= end {
        let mut brand = [0u8; 4];
        brand.copy_from_slice(&data[offset..offset + 4]);
        brands.push(brand);
        offset += 4;
    }
    brands
}

fn ftyp_has_any(data: &[u8], wanted: &[&[u8; 4]]) -> bool {
    let brands = ftyp_brands(data);
    brands
        .iter()
        .any(|brand| wanted.iter().any(|w| brand == *w))
}

fn is_avif_container(data: &[u8]) -> bool {
    ftyp_has_any(data, &[b"avif", b"avis"])
}

fn is_heif_container(data: &[u8]) -> bool {
    if is_avif_container(data) {
        return false;
    }
    const HEIF: [&[u8; 4]; 7] = [
        b"heic", b"heix", b"heif", b"heis", b"heim", b"hevc", b"hevx",
    ];
    ftyp_has_any(data, &HEIF)
}

fn is_quicktime_or_mp4(data: &[u8]) -> bool {
    is_ftyp(data)
}

fn is_mp3(data: &[u8]) -> bool {
    if data.starts_with(b"ID3") {
        return true;
    }
    if data.len() < 2 || data[0] != 0xFF {
        return false;
    }
    // MPEG audio sync (11 bits) + warstwa ≠ 00.
    let second = data[1];
    (second & 0xE0) == 0xE0 && (second & 0x06) != 0
}

fn is_adts_aac(data: &[u8]) -> bool {
    if data.len() < 2 || data[0] != 0xFF {
        return false;
    }
    // ADTS: 12 bitów sync (0xFFF), warstwa 00.
    let second = data[1];
    (second & 0xF6) == 0xF0
}

fn skip_text_prefix(data: &[u8]) -> &[u8] {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let start = data
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(data.len());
    &data[start..]
}

fn detect_audio_type(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"OggS") {
        return Some("ogg");
    }
    if data.starts_with(b"\x1a\x45\xdf\xa3") {
        return Some("webm");
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WAVE" {
        return Some("wav");
    }
    if is_mp3(data) {
        return Some("mp3");
    }
    if is_adts_aac(data) {
        return Some("aac");
    }
    if is_ftyp(data) {
        return Some("mp4");
    }
    None
}

pub fn mp4_has_video_track(data: &[u8]) -> bool {
    const VIDEO_CODEC_MARKERS: &[&[u8]] = &[b"avc1", b"hvc1", b"hev1", b"vp09", b"mp4v", b"av01"];
    VIDEO_CODEC_MARKERS
        .iter()
        .any(|marker| data.windows(marker.len()).any(|window| window == *marker))
}

pub fn webm_has_video_track(data: &[u8]) -> bool {
    const VIDEO_CODEC_MARKERS: &[&[u8]] = &[b"V_VP8", b"V_VP9", b"V_AV1", b"V_MPEG", b"V_THEORA"];
    VIDEO_CODEC_MARKERS
        .iter()
        .any(|marker| data.windows(marker.len()).any(|window| window == *marker))
}

fn normalize_mime_type(mime: &str) -> String {
    mime.trim()
        .to_ascii_lowercase()
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

pub fn mime_allowed_for_extension(ext: &str, mime: &str) -> bool {
    let ext = ext.to_ascii_lowercase();
    let mime = normalize_mime_type(mime);
    if mime.is_empty() {
        return false;
    }

    match ext.as_str() {
        "pdf" => mime == "application/pdf",
        "jpg" | "jpeg" => mime == "image/jpeg",
        "png" => mime == "image/png",
        "webp" => mime == "image/webp",
        "heic" => matches!(mime.as_str(), "image/heic" | "image/heif"),
        "heif" => matches!(mime.as_str(), "image/heif" | "image/heic"),
        "docx" => mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => {
            mime == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        "txt" => mime == "text/plain",
        "csv" => matches!(mime.as_str(), "text/csv" | "text/plain" | "application/csv"),
        "webm" => mime == "audio/webm" || mime == "video/webm",
        "ogg" => mime == "audio/ogg" || mime == "video/ogg" || mime == "application/ogg",
        "wav" => {
            matches!(
                mime.as_str(),
                "audio/wav" | "audio/x-wav" | "audio/wave" | "audio/vnd.wave"
            )
        }
        "mp3" => matches!(mime.as_str(), "audio/mpeg" | "audio/mp3"),
        "aac" => matches!(mime.as_str(), "audio/aac" | "audio/mp4" | "audio/x-m4a"),
        "mov" => matches!(mime.as_str(), "video/quicktime" | "video/mp4"),
        "mp4" => {
            matches!(
                mime.as_str(),
                "audio/mp4"
                    | "audio/aac"
                    | "audio/x-m4a"
                    | "video/mp4"
                    | "video/quicktime"
                    | "application/mp4"
            )
        }
        "m4a" => {
            matches!(mime.as_str(), "audio/mp4" | "audio/aac" | "audio/x-m4a")
        }
        _ => false,
    }
}

pub fn resolve_upload_content_type(ext: &str, client_mime: Option<&str>, data: &[u8]) -> String {
    if let Some(mime) = client_mime {
        if mime_allowed_for_extension(ext, mime) {
            return normalize_mime_type(mime);
        }
    }

    match ext.to_ascii_lowercase().as_str() {
        "webm" if webm_has_video_track(data) => "video/webm".to_string(),
        "mp4" if mp4_has_video_track(data) => "video/mp4".to_string(),
        "mp4" => "audio/mp4".to_string(),
        "m4a" => "audio/mp4".to_string(),
        "aac" if is_ftyp(data) => "audio/mp4".to_string(),
        "aac" => "audio/aac".to_string(),
        "mp3" => "audio/mpeg".to_string(),
        "mov" => "video/quicktime".to_string(),
        other => crate::utils::storage::content_type_for_ext(other).to_string(),
    }
}

pub fn magic_matches(ext: &str, data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    match ext.to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => detect_image_type(data) == Some("jpeg"),
        "png" => detect_image_type(data) == Some("png"),
        "webp" => detect_image_type(data) == Some("webp"),
        "gif" => detect_image_type(data) == Some("gif"),
        "heic" | "heif" => is_heif_container(data),
        "pdf" => data.starts_with(b"%PDF"),
        "txt" | "csv" => {
            let body = skip_text_prefix(data);
            !data.contains(&0)
                && !body.starts_with(b"%PDF")
                && !body.starts_with(b"PK\x03\x04")
                && !is_ftyp(data)
                && !body.starts_with(b"<")
        }
        "docx" | "xlsx" | "pptx" => data.starts_with(b"PK\x03\x04"),
        "mp3" => detect_audio_type(data) == Some("mp3"),
        "aac" => {
            if detect_audio_type(data) == Some("aac") {
                true
            } else if is_ftyp(data) && !mp4_has_video_track(data) && !is_heif_container(data) {
                true
            } else {
                false
            }
        }
        "webm" | "ogg" | "wav" => detect_audio_type(data) == Some(ext),
        "mp4" => detect_audio_type(data) == Some("mp4") && !is_heif_container(data),
        "m4a" => {
            detect_audio_type(data) == Some("mp4")
                && !is_heif_container(data)
                && !mp4_has_video_track(data)
        }
        "mov" => is_quicktime_or_mp4(data) && !is_heif_container(data),
        _ => false,
    }
}

pub fn validate_file_magic(path: &Path, ext: &str) -> bool {
    let Some(data) = read_header(path) else {
        return false;
    };
    if ext.eq_ignore_ascii_case("m4a") && mp4_has_video_track(&data) {
        return false;
    }
    if ext.eq_ignore_ascii_case("aac") && is_ftyp(&data) && mp4_has_video_track(&data) {
        return false;
    }
    magic_matches(ext, &data)
}

pub async fn validate_file_magic_async(path: std::path::PathBuf, ext: String) -> bool {
    tokio::task::spawn_blocking(move || validate_file_magic(&path, &ext))
        .await
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mp3_accepts_id3_and_frame_sync() {
        assert!(magic_matches("mp3", b"ID3\x04\x00\x00"));
        assert!(magic_matches("mp3", &[0xFF, 0xFB, 0x90, 0x00]));
        assert!(!magic_matches("mp3", b"%PDF-1.4"));
        assert!(!magic_matches("mp3", &[0xFF, 0xF1, 0x50, 0x80]));
    }

    #[test]
    fn aac_accepts_adts_not_video_ftyp() {
        assert!(magic_matches("aac", &[0xFF, 0xF1, 0x50, 0x80]));
        assert!(!magic_matches("aac", &[0xFF, 0xFB, 0x90, 0x00]));
        let mut ftyp = vec![0u8; 32];
        ftyp[4..8].copy_from_slice(b"ftyp");
        ftyp[8..12].copy_from_slice(b"isom");
        assert!(magic_matches("aac", &ftyp));
        ftyp.extend_from_slice(b"avc1");
        assert!(!validate_file_magic_from_bytes("aac", &ftyp));
    }

    fn validate_file_magic_from_bytes(ext: &str, data: &[u8]) -> bool {
        if ext.eq_ignore_ascii_case("m4a") && mp4_has_video_track(data) {
            return false;
        }
        if ext.eq_ignore_ascii_case("aac") && is_ftyp(data) && mp4_has_video_track(data) {
            return false;
        }
        magic_matches(ext, data)
    }

    #[test]
    fn heic_requires_heif_brand() {
        let mut heic = vec![0u8; 24];
        heic[0..4].copy_from_slice(&24u32.to_be_bytes());
        heic[4..8].copy_from_slice(b"ftyp");
        heic[8..12].copy_from_slice(b"heic");
        assert!(magic_matches("heic", &heic));
        assert!(magic_matches("heif", &heic));
        heic[8..12].copy_from_slice(b"isom");
        assert!(!magic_matches("heic", &heic));
    }

    #[test]
    fn heic_rejects_avif_and_mif1_only() {
        let mut avif = vec![0u8; 24];
        avif[0..4].copy_from_slice(&24u32.to_be_bytes());
        avif[4..8].copy_from_slice(b"ftyp");
        avif[8..12].copy_from_slice(b"avif");
        avif[16..20].copy_from_slice(b"mif1");
        assert!(!magic_matches("heic", &avif));

        let mut mif1 = vec![0u8; 20];
        mif1[0..4].copy_from_slice(&20u32.to_be_bytes());
        mif1[4..8].copy_from_slice(b"ftyp");
        mif1[8..12].copy_from_slice(b"mif1");
        assert!(!magic_matches("heic", &mif1));
    }

    #[test]
    fn heic_does_not_treat_later_box_type_as_brand() {
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(&20u32.to_be_bytes());
        data[4..8].copy_from_slice(b"ftyp");
        data[8..12].copy_from_slice(b"isom");
        data[16..20].copy_from_slice(b"mp41");
        data[20..24].copy_from_slice(&8u32.to_be_bytes());
        data[24..28].copy_from_slice(b"heic");
        assert!(!magic_matches("heic", &data));
        assert!(magic_matches("mp4", &data));

        // size=0 nie może skanować atomów po major brand
        let mut zero_size = vec![0u8; 40];
        zero_size[4..8].copy_from_slice(b"ftyp");
        zero_size[8..12].copy_from_slice(b"isom");
        zero_size[24..28].copy_from_slice(b"heic");
        assert!(!magic_matches("heic", &zero_size));
    }

    #[test]
    fn m4a_rejects_video_markers() {
        let mut audio = vec![0u8; 24];
        audio[0..4].copy_from_slice(&24u32.to_be_bytes());
        audio[4..8].copy_from_slice(b"ftyp");
        audio[8..12].copy_from_slice(b"M4A ");
        assert!(magic_matches("m4a", &audio));
        audio.extend_from_slice(b"avc1");
        assert!(!magic_matches("m4a", &audio));
    }

    #[test]
    fn csv_rejects_binaries_and_html() {
        assert!(magic_matches("csv", b"name,email\nalice,a@b.c"));
        assert!(magic_matches("csv", b"\xEF\xBB\xBFname,email"));
        assert!(!magic_matches("csv", b"%PDF-1.7"));
        assert!(!magic_matches("csv", b"PK\x03\x04"));
        assert!(!magic_matches("csv", b"<script>"));
        assert!(!magic_matches("csv", b"\xEF\xBB\xBF<script>"));
        assert!(!magic_matches("csv", b"a\0b"));
    }

    #[test]
    fn office_zip_magic() {
        assert!(magic_matches("pptx", b"PK\x03\x04rest"));
        assert!(!magic_matches("pptx", b"%PDF"));
    }
}

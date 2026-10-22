// images.rs
// Resize/WebP awatarów i miniaturek.
// Zakres:
//  - limity pikseli
//  - resize/WebP avatar i thumbs; limity pikseli
// Nowe wymiary: tu + FE crop + upload bytes.
// Przy zmianach: controllers auth/channels, constants/upload.ts.

use std::io::Cursor;
use std::path::Path;

use image::imageops::FilterType;
use image::GenericImageView;

#[derive(Debug)]
pub enum ImageReencodeError {
    DecodeFailed,
    DimensionTooLarge,
    EncodeFailed,
    IoFailed,
}

impl std::fmt::Display for ImageReencodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecodeFailed => write!(f, "Failed to decode image"),
            Self::DimensionTooLarge => write!(f, "Image dimensions too large"),
            Self::EncodeFailed => write!(f, "Failed to encode image"),
            Self::IoFailed => write!(f, "Failed to read or write image file"),
        }
    }
}

impl std::error::Error for ImageReencodeError {}

impl ImageReencodeError {
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::DimensionTooLarge => {
                "Image dimensions too large. Maximum size is 4096×4096 pixels."
            }
            _ => "Invalid image file.",
        }
    }
}

pub fn reencode_error_message(err: &ImageReencodeError) -> &'static str {
    err.user_message()
}

#[derive(Debug, Clone)]
pub struct EncodedImageVariants {
    pub full: Vec<u8>,
    pub thumb: Vec<u8>,
}

fn read_image_dimensions(bytes: &[u8]) -> Result<(u32, u32), ImageReencodeError> {
    image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| ImageReencodeError::DecodeFailed)?
        .into_dimensions()
        .map_err(|_| ImageReencodeError::DecodeFailed)
}

fn ensure_source_dimensions_ok(width: u32, height: u32) -> Result<(), ImageReencodeError> {
    let max = crate::utils::upload::MAX_IMAGE_DIMENSION;
    if width == 0 || height == 0 || width > max || height > max {
        return Err(ImageReencodeError::DimensionTooLarge);
    }
    Ok(())
}

fn resize_to_max_edge(img: image::DynamicImage, max_edge: u32) -> image::DynamicImage {
    let (width, height) = img.dimensions();
    if width <= max_edge && height <= max_edge {
        return img;
    }
    img.resize(max_edge, max_edge, FilterType::Triangle)
}

fn encode_lossy_webp(
    img: &image::DynamicImage,
    quality: f32,
) -> Result<Vec<u8>, ImageReencodeError> {
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();
    let encoder = webp::Encoder::from_rgba(rgba.as_raw(), width, height);
    let encoded = encoder.encode(quality);
    if encoded.is_empty() {
        return Err(ImageReencodeError::EncodeFailed);
    }
    Ok(encoded.to_vec())
}

pub fn reencode_upload_to_webp_variants(
    source: &Path,
) -> Result<EncodedImageVariants, ImageReencodeError> {
    let bytes = std::fs::read(source).map_err(|_| ImageReencodeError::IoFailed)?;
    let (width, height) = read_image_dimensions(&bytes)?;
    ensure_source_dimensions_ok(width, height)?;
    let img = image::load_from_memory(&bytes).map_err(|_| ImageReencodeError::DecodeFailed)?;

    let full_img = resize_to_max_edge(img, crate::utils::upload::MAX_CHAT_IMAGE_EDGE);
    let thumb_img = resize_to_max_edge(full_img.clone(), crate::utils::upload::MAX_CHAT_THUMB_EDGE);

    let full = encode_lossy_webp(&full_img, crate::utils::upload::CHAT_IMAGE_WEBP_QUALITY)?;
    let thumb = encode_lossy_webp(&thumb_img, crate::utils::upload::CHAT_THUMB_WEBP_QUALITY)?;

    Ok(EncodedImageVariants { full, thumb })
}

pub async fn reencode_upload_to_webp_variants_async(
    source: std::path::PathBuf,
) -> Result<EncodedImageVariants, ImageReencodeError> {
    tokio::task::spawn_blocking(move || reencode_upload_to_webp_variants(&source))
        .await
        .map_err(|_| ImageReencodeError::IoFailed)?
}

pub fn reencode_upload_to_webp(source: &Path) -> Result<Vec<u8>, ImageReencodeError> {
    reencode_upload_to_webp_max_edge(source, crate::utils::upload::MAX_AVATAR_EDGE)
}

pub fn reencode_upload_to_webp_max_edge(
    source: &Path,
    max_edge: u32,
) -> Result<Vec<u8>, ImageReencodeError> {
    let bytes = std::fs::read(source).map_err(|_| ImageReencodeError::IoFailed)?;
    let (width, height) = read_image_dimensions(&bytes)?;
    ensure_source_dimensions_ok(width, height)?;
    let img = image::load_from_memory(&bytes).map_err(|_| ImageReencodeError::DecodeFailed)?;
    let resized = resize_to_max_edge(img, max_edge);
    encode_lossy_webp(&resized, crate::utils::upload::AVATAR_WEBP_QUALITY)
}

pub async fn reencode_upload_to_webp_async(
    source: std::path::PathBuf,
) -> Result<Vec<u8>, ImageReencodeError> {
    tokio::task::spawn_blocking(move || reencode_upload_to_webp(&source))
        .await
        .map_err(|_| ImageReencodeError::IoFailed)?
}

pub async fn reencode_upload_to_webp_max_edge_async(
    source: std::path::PathBuf,
    max_edge: u32,
) -> Result<Vec<u8>, ImageReencodeError> {
    tokio::task::spawn_blocking(move || reencode_upload_to_webp_max_edge(&source, max_edge))
        .await
        .map_err(|_| ImageReencodeError::IoFailed)?
}

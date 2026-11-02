//! Uploaded images are never stored as sent. They are fully decoded within size limits and
//! re-encoded as a PNG of at most `LOGO_SIZE` pixels, so nothing from the original file
//! (scripts, appended data, extra frames, metadata) survives.
//!
//! Only raster formats are accepted. Decoding one costs at most a fixed amount of work per
//! pixel, and the pixels are capped, so no upload can cost more than a large photo. Drawing an
//! SVG has no such bound: its cost depends on path lengths, stroke geometry, references and
//! more, and the renderer cannot be stopped part way. The web interface turns an SVG into a PNG
//! in the uploader's own browser before sending it, so the server never draws one.

use std::io::Cursor;

use image::imageops::FilterType;
use image::{DynamicImage, ImageFormat, ImageReader, Limits};

pub const MAX_DIMENSION: u32 = 4096;
/// The longest side of a stored logo.
pub const LOGO_SIZE: u32 = 512;
const MAX_DECODE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImageError {
    #[error("the file is not a PNG, JPEG, GIF or WebP image")]
    UnknownType,
    #[error("SVG files are not accepted; convert the logo to PNG first")]
    Svg,
    #[error("the image could not be read: {0}")]
    Corrupt(String),
    #[error("the image is larger than {MAX_DIMENSION} by {MAX_DIMENSION} pixels")]
    TooLarge,
}

/// Checks that `data` is a sound image and returns it re-encoded as a PNG logo.
pub fn normalise_logo(data: &[u8]) -> Result<Vec<u8>, ImageError> {
    let Some(format) = raster_format(data) else {
        if looks_like_svg(data) {
            return Err(ImageError::Svg);
        }
        return Err(ImageError::UnknownType);
    };
    encode_png(fit(decode_raster(data, format)?))
}

fn raster_format(data: &[u8]) -> Option<ImageFormat> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(ImageFormat::Png);
    }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(ImageFormat::Jpeg);
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some(ImageFormat::Gif);
    }
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some(ImageFormat::WebP);
    }
    None
}

/// Only the first frame of an animation is decoded.
fn decode_raster(data: &[u8], format: ImageFormat) -> Result<DynamicImage, ImageError> {
    let mut reader = ImageReader::with_format(Cursor::new(data), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_BYTES);
    reader.limits(limits);
    match reader.decode() {
        Ok(image) if image.width() == 0 || image.height() == 0 => Err(ImageError::Corrupt("the image is empty".into())),
        Ok(image) => Ok(image),
        Err(image::ImageError::Limits(_)) => Err(ImageError::TooLarge),
        Err(error) => Err(ImageError::Corrupt(error.to_string())),
    }
}

/// Shrinks to fit `LOGO_SIZE`; smaller images keep their size.
fn fit(image: DynamicImage) -> DynamicImage {
    if image.width() <= LOGO_SIZE && image.height() <= LOGO_SIZE {
        return image;
    }
    image.resize(LOGO_SIZE, LOGO_SIZE, FilterType::Lanczos3)
}

fn encode_png(image: DynamicImage) -> Result<Vec<u8>, ImageError> {
    let mut out = Cursor::new(Vec::new());
    image
        .to_rgba8()
        .write_to(&mut out, ImageFormat::Png)
        .map_err(|e| ImageError::Corrupt(e.to_string()))?;
    Ok(out.into_inner())
}

/// Recognised only to explain the refusal; nothing else reads the document.
fn looks_like_svg(data: &[u8]) -> bool {
    let head = &data[..data.len().min(4096)];
    let text = String::from_utf8_lossy(head);
    let start = text.trim_start_matches('\u{feff}').trim_start();
    start.starts_with('<') && start.contains("<svg")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn encode(format: ImageFormat, width: u32, height: u32) -> anyhow::Result<Vec<u8>> {
        let image = image::RgbaImage::from_pixel(width, height, image::Rgba([30, 44, 67, 255]));
        let mut out = Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(image)
            .write_to(&mut out, format)
            .context("encode")?;
        Ok(out.into_inner())
    }

    fn decoded(png: &[u8]) -> anyhow::Result<DynamicImage> {
        assert!(png.starts_with(b"\x89PNG"), "output is always a PNG");
        image::load_from_memory_with_format(png, ImageFormat::Png).context("valid png")
    }

    #[test]
    fn raster_images_come_back_as_png() -> anyhow::Result<()> {
        for format in [ImageFormat::Png, ImageFormat::Gif, ImageFormat::WebP, ImageFormat::Jpeg] {
            let out = normalise_logo(&encode(format, 16, 12)?).context("logo")?;
            let image = decoded(&out)?;
            assert_eq!((image.width(), image.height()), (16, 12), "{format:?}");
        }
        Ok(())
    }

    #[test]
    fn large_images_are_shrunk_to_fit() -> anyhow::Result<()> {
        let image = decoded(&normalise_logo(&encode(ImageFormat::Png, 2000, 1000)?).context("logo")?)?;
        assert_eq!((image.width(), image.height()), (LOGO_SIZE, LOGO_SIZE / 2));
        Ok(())
    }

    #[test]
    fn the_largest_accepted_image_is_still_decoded() -> anyhow::Result<()> {
        let image =
            decoded(&normalise_logo(&encode(ImageFormat::Png, MAX_DIMENSION, MAX_DIMENSION)?).context("logo")?)?;
        assert_eq!((image.width(), image.height()), (LOGO_SIZE, LOGO_SIZE));
        Ok(())
    }

    #[test]
    fn appended_data_does_not_survive() -> anyhow::Result<()> {
        let mut polyglot = encode(ImageFormat::Png, 8, 8)?;
        polyglot.extend_from_slice(b"PK\x03\x04<html><script>alert(1)</script>");
        let out = normalise_logo(&polyglot).context("the image part is valid")?;
        assert!(
            !out.windows(7).any(|w| w == b"<script"),
            "only the re-encoded pixels are kept"
        );
        Ok(())
    }

    #[test]
    fn magic_bytes_alone_are_not_enough() -> anyhow::Result<()> {
        assert!(matches!(
            normalise_logo(b"\x89PNG\r\n\x1a\nthis is not really a png"),
            Err(ImageError::Corrupt(_))
        ));
        let mut truncated = encode(ImageFormat::Png, 64, 64)?;
        truncated.truncate(truncated.len() / 2);
        assert!(matches!(normalise_logo(&truncated), Err(ImageError::Corrupt(_))));
        Ok(())
    }

    #[test]
    fn oversized_images_are_refused_before_decoding_them() -> anyhow::Result<()> {
        assert_eq!(
            normalise_logo(&encode(ImageFormat::Png, MAX_DIMENSION + 1, 1)?),
            Err(ImageError::TooLarge)
        );
        Ok(())
    }

    #[test]
    fn other_files_are_refused() {
        assert_eq!(normalise_logo(b""), Err(ImageError::UnknownType));
        assert_eq!(normalise_logo(b"MZ\x90\0binary"), Err(ImageError::UnknownType));
        assert_eq!(normalise_logo(b"\x1f\x8b\x08\0svgz"), Err(ImageError::UnknownType));
    }

    /// The ninth audit's file: one stroked path of 40,000 segments drawn through 250 `<use>`
    /// copies, which took about 20 s of CPU to render.
    fn stroked_path_bomb() -> String {
        let mut d = String::from("M0 0");
        for i in 0..40_000 {
            d.push_str(if i % 2 == 0 { " L512 1" } else { " L0 2" });
        }
        let mut svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><defs><path id="p" d="{d}" fill="none" stroke="black" stroke-width="40" stroke-linejoin="round" stroke-linecap="round"/></defs>"#
        );
        for _ in 0..250 {
            svg.push_str(r##"<use href="#p"/>"##);
        }
        svg.push_str("</svg>");
        svg
    }

    #[test]
    fn svgs_are_refused_without_being_drawn() {
        let plain = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 10"><rect width="20" height="10" fill="#1E2C43"/></svg>"##;
        let with_prolog = "\u{feff}<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"/>";
        let bomb = stroked_path_bomb();
        assert!(bomb.len() < 512 * 1024, "the audit's file fits the upload limit");
        for svg in [plain, with_prolog, &bomb] {
            assert_eq!(normalise_logo(svg.as_bytes()), Err(ImageError::Svg));
        }
    }

    #[test]
    fn an_svg_is_recognised_from_its_start_alone() {
        let mut long = String::from("<svg xmlns=\"http://www.w3.org/2000/svg\">");
        long.push_str(&"<g/>".repeat(1_000_000));
        assert!(looks_like_svg(long.as_bytes()));
        assert!(!looks_like_svg(b"<html><body>no</body></html>"));
        assert!(!looks_like_svg(b"plain text that mentions <svg later"));
    }
}

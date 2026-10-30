//! Uploaded images are never stored as sent. Raster images are fully decoded and SVGs are
//! rendered, both within size limits, and the result is re-encoded as a PNG of at most
//! `LOGO_SIZE` pixels. Nothing from the original file (scripts, appended data, extra frames,
//! external references) survives.

use std::io::Cursor;

use image::imageops::FilterType;
use image::{DynamicImage, ImageFormat, ImageReader, Limits};
use resvg::{tiny_skia, usvg};

pub const MAX_DIMENSION: u32 = 4096;
/// The longest side of a stored logo.
pub const LOGO_SIZE: u32 = 512;
const MAX_DECODE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SVG_ELEMENTS: usize = 10_000;
const MAX_SVG_USES: usize = 256;
const MAX_SVG_DEPTH: usize = 64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImageError {
    #[error("the file is not a PNG, JPEG, GIF, WebP or SVG image")]
    UnknownType,
    #[error("the image could not be read: {0}")]
    Corrupt(String),
    #[error("the image is larger than {MAX_DIMENSION} by {MAX_DIMENSION} pixels")]
    TooLarge,
    #[error("the SVG is not allowed: {0}")]
    UnsafeSvg(String),
}

/// Checks that `data` is a sound image and returns it re-encoded as a PNG logo.
pub fn normalise_logo(data: &[u8]) -> Result<Vec<u8>, ImageError> {
    let image = match raster_format(data) {
        Some(format) => decode_raster(data, format)?,
        None if looks_like_svg(data) => render_svg(data)?,
        None => return Err(ImageError::UnknownType),
    };
    encode_png(fit(image))
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

fn looks_like_svg(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok_and(|text| {
        let start = text.trim_start_matches('\u{feff}').trim_start();
        start.starts_with('<') && start.contains("<svg")
    })
}

const SVG_NAMESPACE: &str = "http://www.w3.org/2000/svg";

/// Parses with DTDs refused (no entity expansion), bounds the document's size and nesting, and
/// rejects anything that is not plain SVG. Rendering never loads files or URLs either way.
fn check_svg(text: &str) -> Result<(), ImageError> {
    let document = roxmltree::Document::parse(text).map_err(|e| ImageError::UnsafeSvg(e.to_string()))?;
    let root = document.root_element();
    if root.tag_name().name() != "svg" || root.tag_name().namespace() != Some(SVG_NAMESPACE) {
        return Err(ImageError::UnsafeSvg("the root element is not an SVG element".into()));
    }
    let mut elements = 0;
    let mut uses = 0;
    for node in document.descendants().filter(|n| n.is_element()) {
        elements += 1;
        if node.tag_name().name() == "use" {
            uses += 1;
        }
        if node.tag_name().namespace() != Some(SVG_NAMESPACE) {
            return Err(ImageError::UnsafeSvg(format!(
                "<{}> is not an SVG element",
                node.tag_name().name()
            )));
        }
        if node.ancestors().count() > MAX_SVG_DEPTH {
            return Err(ImageError::UnsafeSvg("the document is nested too deeply".into()));
        }
    }
    if elements > MAX_SVG_ELEMENTS || uses > MAX_SVG_USES {
        return Err(ImageError::UnsafeSvg("the document has too many elements".into()));
    }
    Ok(())
}

fn render_svg(data: &[u8]) -> Result<DynamicImage, ImageError> {
    let text = std::str::from_utf8(data).map_err(|_| ImageError::UnsafeSvg("it is not UTF-8".into()))?;
    check_svg(text)?;
    let options = usvg::Options {
        // The defaults would read `<image href>` targets from the local filesystem.
        image_href_resolver: usvg::ImageHrefResolver {
            resolve_data: Box::new(|_, _, _| None),
            resolve_string: Box::new(|_, _| None),
        },
        ..usvg::Options::default()
    };
    let tree = usvg::Tree::from_str(text, &options).map_err(|e| ImageError::UnsafeSvg(e.to_string()))?;
    let size = tree.size();
    let scale = LOGO_SIZE as f32 / size.width().max(size.height());
    let width = ((size.width() * scale).round() as u32).clamp(1, LOGO_SIZE);
    let height = ((size.height() * scale).round() as u32).clamp(1, LOGO_SIZE);
    let mut pixmap = tiny_skia::Pixmap::new(width, height).ok_or(ImageError::TooLarge)?;
    resvg::render(
        &tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    let rgba = image::RgbaImage::from_raw(width, height, pixmap.take_demultiplied())
        .ok_or_else(|| ImageError::Corrupt("the rendered image has the wrong size".into()))?;
    Ok(DynamicImage::ImageRgba8(rgba))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(format: ImageFormat, width: u32, height: u32) -> Vec<u8> {
        let image = image::RgbaImage::from_pixel(width, height, image::Rgba([30, 44, 67, 255]));
        let mut out = Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(image)
            .write_to(&mut out, format)
            .expect("encode");
        out.into_inner()
    }

    fn decoded(png: &[u8]) -> DynamicImage {
        assert!(png.starts_with(b"\x89PNG"), "output is always a PNG");
        image::load_from_memory_with_format(png, ImageFormat::Png).expect("valid png")
    }

    #[test]
    fn raster_images_come_back_as_png() {
        for format in [ImageFormat::Png, ImageFormat::Gif, ImageFormat::WebP, ImageFormat::Jpeg] {
            let out = normalise_logo(&encode(format, 16, 12)).expect("logo");
            let image = decoded(&out);
            assert_eq!((image.width(), image.height()), (16, 12), "{format:?}");
        }
    }

    #[test]
    fn large_images_are_shrunk_to_fit() {
        let image = decoded(&normalise_logo(&encode(ImageFormat::Png, 2000, 1000)).expect("logo"));
        assert_eq!((image.width(), image.height()), (LOGO_SIZE, LOGO_SIZE / 2));
    }

    #[test]
    fn appended_data_does_not_survive() {
        let mut polyglot = encode(ImageFormat::Png, 8, 8);
        polyglot.extend_from_slice(b"PK\x03\x04<html><script>alert(1)</script>");
        let out = normalise_logo(&polyglot).expect("the image part is valid");
        assert!(
            !out.windows(7).any(|w| w == b"<script"),
            "only the re-encoded pixels are kept"
        );
    }

    #[test]
    fn magic_bytes_alone_are_not_enough() {
        assert!(matches!(
            normalise_logo(b"\x89PNG\r\n\x1a\nthis is not really a png"),
            Err(ImageError::Corrupt(_))
        ));
        let mut truncated = encode(ImageFormat::Png, 64, 64);
        truncated.truncate(truncated.len() / 2);
        assert!(matches!(normalise_logo(&truncated), Err(ImageError::Corrupt(_))));
    }

    #[test]
    fn oversized_images_are_refused_before_decoding_them() {
        assert_eq!(
            normalise_logo(&encode(ImageFormat::Png, MAX_DIMENSION + 1, 1)),
            Err(ImageError::TooLarge)
        );
    }

    #[test]
    fn other_files_are_refused() {
        assert_eq!(normalise_logo(b""), Err(ImageError::UnknownType));
        assert_eq!(normalise_logo(b"MZ\x90\0binary"), Err(ImageError::UnknownType));
        assert_eq!(normalise_logo(b"\x1f\x8b\x08\0svgz"), Err(ImageError::UnknownType));
    }

    #[test]
    fn svgs_are_rendered_to_png() {
        let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 10">
          <rect width="20" height="10" fill="#1E2C43"/></svg>"##;
        let image = decoded(&normalise_logo(svg.as_bytes()).expect("logo"));
        assert_eq!((image.width(), image.height()), (LOGO_SIZE, LOGO_SIZE / 2));
        let pixel = image.to_rgba8().get_pixel(10, 10).0;
        assert_eq!(pixel, [0x1E, 0x2C, 0x43, 255]);
    }

    #[test]
    fn scripts_and_external_references_cannot_survive_rendering() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">
          <script>alert(1)</script>
          <image href="file:///etc/passwd" width="10" height="10"/>
          <image xlink:href="/etc/hostname" width="10" height="10"/>
          <animate attributeName="href" values="javascript:alert(1)"/>
          <rect width="10" height="10" fill="red"/></svg>"#;
        let out = normalise_logo(svg.as_bytes()).expect("renders");
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("script") && !text.contains("passwd"));
    }

    #[test]
    fn hostile_svg_documents_are_refused() {
        let billion_laughs = r#"<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&b;</text></svg>"#;
        let foreign = r#"<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject></svg>"#;
        let no_namespace = "<svg viewBox=\"0 0 1 1\"><rect/></svg>";
        let deep = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg">{}{}</svg>"#,
            "<g>".repeat(MAX_SVG_DEPTH + 1),
            "</g>".repeat(MAX_SVG_DEPTH + 1)
        );
        let mut use_bomb =
            String::from(r#"<svg xmlns="http://www.w3.org/2000/svg"><defs><rect id="l0" width="1" height="1"/>"#);
        for level in 1..=9 {
            use_bomb.push_str(&format!(r#"<g id="l{level}">"#));
            for _ in 0..40 {
                use_bomb.push_str(&format!(r##"<use href="#l{}"/>"##, level - 1));
            }
            use_bomb.push_str("</g>");
        }
        use_bomb.push_str(r##"</defs><use href="#l9"/></svg>"##);
        for attack in [billion_laughs, foreign, no_namespace, &deep, &use_bomb] {
            assert!(
                matches!(normalise_logo(attack.as_bytes()), Err(ImageError::UnsafeSvg(_))),
                "{}",
                &attack[..attack.len().min(80)]
            );
        }
    }
}

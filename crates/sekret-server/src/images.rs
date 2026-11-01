//! Uploaded images are never stored as sent. Raster images are fully decoded and SVGs are
//! rendered, both within size limits, and the result is re-encoded as a PNG of at most
//! `LOGO_SIZE` pixels. Nothing from the original file (scripts, appended data, extra frames,
//! external references) survives.

use std::collections::HashMap;
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
/// Elements once every `<use>`, mask, clip path, pattern and marker is expanded in place.
const MAX_SVG_EXPANDED: u64 = 20_000;
/// References followed through references, such as a mask whose content is clipped.
const MAX_REFERENCE_DEPTH: usize = 8;

/// Rendering work allowed for one SVG, in units of roughly one full-canvas path fill. Masks,
/// clip paths, patterns and gradients are charged once per use, as resvg renders them, so
/// nesting them cannot multiply the work past this.
const RENDER_BUDGET: u64 = 20_000;
const PATH_COST: u64 = 1;
const DASH_COST: u64 = 8;
/// Dashes the whole drawing may be cut into. Each dash is stroked as a path of its own, and one
/// path can otherwise ask for a million.
const MAX_DASHES: f64 = 100_000.0;
const GRADIENT_COST: u64 = 40;
/// An offscreen canvas, composited back: isolated groups, clip paths, masks, patterns and images.
const LAYER_COST: u64 = 30;

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
        if is_filter_element(node.tag_name().name()) {
            return Err(ImageError::UnsafeSvg("filters are not allowed".into()));
        }
        if node.ancestors().count() > MAX_SVG_DEPTH {
            return Err(ImageError::UnsafeSvg("the document is nested too deeply".into()));
        }
    }
    if elements > MAX_SVG_ELEMENTS || uses > MAX_SVG_USES {
        return Err(ImageError::UnsafeSvg("the document has too many elements".into()));
    }
    let mut ids: HashMap<&str, Vec<roxmltree::Node>> = HashMap::new();
    for node in document.descendants().filter(|n| n.is_element()) {
        if let Some(id) = node.attribute("id") {
            ids.entry(id).or_default().push(node);
        }
    }
    check_stylesheets(&document, &ids)?;
    Expansion {
        ids,
        seen: HashMap::new(),
    }
    .size(root, 0)?;
    Ok(())
}

/// The ids named by `url(#id)` in an attribute or stylesheet, in any letter case of `url`.
fn url_targets(value: &str) -> Vec<&str> {
    let lower = value.to_ascii_lowercase();
    lower
        .match_indices("url(")
        .filter_map(|(at, _)| {
            let rest = value.get(at + 4..)?;
            let inner = rest.split(')').next()?.trim().trim_matches(['"', '\'']);
            inner.trim().strip_prefix('#')
        })
        .collect()
}

/// Everything an element draws in by reference: `href`s and `url(#id)` paints, masks, clip
/// paths and markers, whether set as attributes or in its `style`.
fn references<'a>(node: roxmltree::Node<'a, '_>) -> Vec<&'a str> {
    let mut out = Vec::new();
    for attribute in node.attributes() {
        let value = attribute.value();
        if attribute.name() == "href" {
            out.extend(value.trim().strip_prefix('#'));
            continue;
        }
        out.extend(url_targets(value));
    }
    out
}

/// Selectors cannot be matched here, so a stylesheet may only point at gradients, which draw
/// nothing by reference themselves.
fn check_stylesheets(
    document: &roxmltree::Document,
    ids: &HashMap<&str, Vec<roxmltree::Node>>,
) -> Result<(), ImageError> {
    let sheets = document
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "style");
    for sheet in sheets {
        let text: String = sheet.descendants().filter_map(|n| n.text()).collect();
        for id in url_targets(&text) {
            let gradients_only = ids.get(id).is_none_or(|targets| {
                targets
                    .iter()
                    .all(|t| matches!(t.tag_name().name(), "linearGradient" | "radialGradient"))
            });
            if !gradients_only {
                return Err(ImageError::UnsafeSvg("a stylesheet may only refer to gradients".into()));
            }
        }
    }
    Ok(())
}

enum Visit {
    Open,
    /// The element's size with everything it refers to, and the longest chain of references below it.
    Done(u64, usize),
}

/// Counts the elements a renderer expands the document into, following every reference. Each
/// element is sized once, so a reference fan-out cannot make this check itself slow.
struct Expansion<'a, 'input> {
    ids: HashMap<&'a str, Vec<roxmltree::Node<'a, 'input>>>,
    seen: HashMap<roxmltree::NodeId, Visit>,
}

impl<'a, 'input> Expansion<'a, 'input> {
    fn size(&mut self, node: roxmltree::Node<'a, 'input>, hops: usize) -> Result<(u64, usize), ImageError> {
        let too_deep = || ImageError::UnsafeSvg("references are nested too deeply".into());
        if hops > MAX_REFERENCE_DEPTH {
            return Err(too_deep());
        }
        match self.seen.get(&node.id()) {
            Some(Visit::Done(size, below)) if hops + below <= MAX_REFERENCE_DEPTH => return Ok((*size, *below)),
            Some(Visit::Done(..)) => return Err(too_deep()),
            Some(Visit::Open) => return Err(ImageError::UnsafeSvg("an element refers to itself".into())),
            None => {}
        }
        self.seen.insert(node.id(), Visit::Open);
        let mut size: u64 = 1;
        let mut below = 0;
        for child in node.children().filter(|c| c.is_element()) {
            let (child_size, child_below) = self.size(child, hops)?;
            size = size.saturating_add(child_size);
            below = below.max(child_below);
        }
        for id in references(node) {
            let targets = self.ids.get(id).cloned().unwrap_or_default();
            for target in targets {
                let (target_size, target_below) = self.size(target, hops + 1)?;
                size = size.saturating_add(target_size);
                below = below.max(target_below + 1);
            }
        }
        if size > MAX_SVG_EXPANDED {
            return Err(ImageError::UnsafeSvg(
                "the document expands to too many elements".into(),
            ));
        }
        self.seen.insert(node.id(), Visit::Done(size, below));
        Ok((size, below))
    }
}

/// Filters can take minutes to render from a few bytes, and a logo has no need of them.
fn is_filter_element(name: &str) -> bool {
    name == "filter" || name.starts_with("fe")
}

/// Walks the tree the way resvg renders it, stopping as soon as `budget` is spent. The walk
/// uses its own stack and never costs more than the budget, however deep the nesting.
fn within_render_budget(root: &usvg::Group, budget: u64) -> bool {
    let mut dashed = 0.0;
    let mut left = budget;
    let mut spend = |cost: u64| match left.checked_sub(cost) {
        Some(rest) => {
            left = rest;
            true
        }
        None => false,
    };
    let mut groups = vec![root];
    while let Some(group) = groups.pop() {
        if !spend(PATH_COST) || (group.should_isolate() && !spend(LAYER_COST)) {
            return false;
        }
        let mut clip = group.clip_path();
        while let Some(c) = clip {
            if !spend(LAYER_COST) {
                return false;
            }
            groups.push(c.root());
            clip = c.clip_path();
        }
        let mut mask = group.mask();
        while let Some(m) = mask {
            if !spend(LAYER_COST) {
                return false;
            }
            groups.push(m.root());
            mask = m.mask();
        }
        for node in group.children() {
            match node {
                usvg::Node::Group(child) => groups.push(child),
                usvg::Node::Path(path) => {
                    if !spend(PATH_COST) {
                        return false;
                    }
                    let paints = path
                        .fill()
                        .map(usvg::Fill::paint)
                        .into_iter()
                        .chain(path.stroke().map(usvg::Stroke::paint));
                    for paint in paints {
                        let cost = match paint {
                            usvg::Paint::Color(_) => 0,
                            usvg::Paint::LinearGradient(_) | usvg::Paint::RadialGradient(_) => GRADIENT_COST,
                            usvg::Paint::Pattern(pattern) => {
                                groups.push(pattern.root());
                                LAYER_COST
                            }
                        };
                        if !spend(cost) {
                            return false;
                        }
                    }
                    if let Some(dashes) = path.stroke().and_then(usvg::Stroke::dasharray) {
                        if !spend(DASH_COST) {
                            return false;
                        }
                        dashed += expected_dashes(path.data(), dashes);
                        if dashed.is_nan() || dashed > MAX_DASHES {
                            return false;
                        }
                    }
                }
                usvg::Node::Image(image) => {
                    if !spend(LAYER_COST) {
                        return false;
                    }
                    if let usvg::ImageKind::SVG(tree) = image.kind() {
                        groups.push(tree.root());
                    }
                }
                usvg::Node::Text(text) => groups.push(text.flattened()),
            }
        }
    }
    true
}

/// How many dashes tiny-skia cuts `path` into: its length over the dash pattern's length, times
/// the dashes in one pattern, plus one per contour. The length is measured along the control
/// points, which is never shorter than the curve. Dashing happens before the transform, so the
/// path's own coordinates are the right ones. Anything not finite counts as too many.
fn expected_dashes(path: &tiny_skia::Path, dasharray: &[f32]) -> f64 {
    let interval: f64 = dasharray.iter().map(|d| f64::from(*d)).sum();
    if !interval.is_finite() || dasharray.iter().any(|d| !d.is_finite() || *d < 0.0) {
        return f64::INFINITY;
    }
    if interval <= 0.0 {
        return 0.0;
    }
    let mut length = 0.0;
    let mut contours = 0.0;
    let mut start = tiny_skia::Point::zero();
    let mut at = start;
    let mut step = |from: tiny_skia::Point, to: tiny_skia::Point| {
        length += f64::from(from.distance(to));
        to
    };
    for segment in path.segments() {
        at = match segment {
            tiny_skia::PathSegment::MoveTo(p) => {
                contours += 1.0;
                start = p;
                p
            }
            tiny_skia::PathSegment::LineTo(p) => step(at, p),
            tiny_skia::PathSegment::QuadTo(c, p) => {
                let c = step(at, c);
                step(c, p)
            }
            tiny_skia::PathSegment::CubicTo(c1, c2, p) => {
                let c1 = step(at, c1);
                let c2 = step(c1, c2);
                step(c2, p)
            }
            tiny_skia::PathSegment::Close => step(at, start),
        };
    }
    let per_pattern = (dasharray.len() / 2).max(1) as f64;
    length / interval * per_pattern + contours
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
    // Also catches CSS filter functions, which need no `<filter>` element.
    if !tree.filters().is_empty() {
        return Err(ImageError::UnsafeSvg("filters are not allowed".into()));
    }
    if !within_render_budget(tree.root(), RENDER_BUDGET) {
        return Err(ImageError::UnsafeSvg("the drawing is too complex".into()));
    }
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

    #[test]
    fn svgs_are_rendered_to_png() -> anyhow::Result<()> {
        let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 10">
          <rect width="20" height="10" fill="#1E2C43"/></svg>"##;
        let image = decoded(&normalise_logo(svg.as_bytes()).context("logo")?)?;
        assert_eq!((image.width(), image.height()), (LOGO_SIZE, LOGO_SIZE / 2));
        let pixel = image.to_rgba8().get_pixel(10, 10).0;
        assert_eq!(pixel, [0x1E, 0x2C, 0x43, 255]);
        Ok(())
    }

    #[test]
    fn scripts_and_external_references_cannot_survive_rendering() -> anyhow::Result<()> {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">
          <script>alert(1)</script>
          <image href="file:///etc/passwd" width="10" height="10"/>
          <image xlink:href="/etc/hostname" width="10" height="10"/>
          <animate attributeName="href" values="javascript:alert(1)"/>
          <rect width="10" height="10" fill="red"/></svg>"#;
        let out = normalise_logo(svg.as_bytes()).context("renders")?;
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("script") && !text.contains("passwd"));
        Ok(())
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

    const HEAD: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">"#;

    /// Refused, and quickly: each of these took seconds to minutes to render before. The bound is
    /// loose because CI runners are slow; the budget tests count the work itself.
    fn refused_quickly(attack: &str) {
        let started = std::time::Instant::now();
        let result = normalise_logo(attack.as_bytes());
        assert!(
            matches!(result, Err(ImageError::UnsafeSvg(_))),
            "{result:?}: {}",
            &attack[..attack.len().min(120)]
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "took {:?}",
            started.elapsed()
        );
    }

    fn nested_references(element: &str, attribute: &str, levels: usize, fan: usize) -> String {
        let mut svg = format!(r#"{HEAD}<{element} id="r0"><rect width="100" height="100" fill="white"/></{element}>"#);
        for level in 1..levels {
            svg.push_str(&format!(r#"<{element} id="r{level}">"#));
            for _ in 0..fan {
                svg.push_str(&format!(
                    r##"<rect width="100" height="100" fill="white" {attribute}="url(#r{})"/>"##,
                    level - 1
                ));
            }
            svg.push_str(&format!("</{element}>"));
        }
        svg.push_str(&format!(
            r##"<rect width="100" height="100" {attribute}="url(#r{})"/></svg>"##,
            levels - 1
        ));
        svg
    }

    #[test]
    fn filters_are_refused_however_they_are_written() {
        let morphology = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><filter id="f"><feMorphology radius="50"/></filter><rect width="100" height="100" filter="url(#f)"/></svg>"##;
        let combined = format!(
            r##"{HEAD}<defs><filter id="f" x="-1000%" y="-1000%" width="2100%" height="2100%"><feGaussianBlur stdDeviation="50"/><feMorphology operator="dilate" radius="50"/><feTurbulence baseFrequency="0.9" numOctaves="10"/></filter></defs><rect width="100" height="100" filter="url(#f)"/></svg>"##
        );
        let turbulence = format!(
            r##"{HEAD}<filter id="f"><feTurbulence baseFrequency="0.9" numOctaves="10"/></filter><rect width="100" height="100" filter="url(#f)"/></svg>"##
        );
        let unused = format!(r#"{HEAD}<filter id="f"><feFlood/></filter><rect width="100" height="100"/></svg>"#);
        let css_attribute = format!(r#"{HEAD}<rect width="100" height="100" style="filter:blur(50)"/></svg>"#);
        let css_sheet =
            format!(r#"{HEAD}<style>rect{{filter:blur(50px)}}</style><rect width="100" height="100"/></svg>"#);
        let presentation = format!(r#"{HEAD}<rect width="100" height="100" filter="blur(50)"/></svg>"#);
        for attack in [
            morphology,
            &combined,
            &turbulence,
            &unused,
            &css_attribute,
            &css_sheet,
            &presentation,
        ] {
            refused_quickly(attack);
        }
    }

    #[test]
    fn nested_masks_clips_and_patterns_are_refused() {
        refused_quickly(&nested_references("mask", "mask", 18, 2));
        refused_quickly(&nested_references("clipPath", "clip-path", 30, 2));
        refused_quickly(&nested_references("pattern", "fill", 30, 2));
        refused_quickly(&nested_references("mask", "mask", 8, 3));
        refused_quickly(&nested_references("mask", "mask", 2, 9000));
        let through_use = format!(
            r##"{HEAD}<mask id="a"><rect id="x" width="1" height="1" mask="url(#b)"/></mask><mask id="b"><use href="#x"/></mask><rect width="100" height="100" mask="url(#a)"/></svg>"##
        );
        refused_quickly(&through_use);
        let in_a_stylesheet = format!(
            r##"{HEAD}<style>.m{{mask:url(#m)}}</style><mask id="m"><rect class="m" width="100" height="100"/></mask><rect class="m" width="100" height="100"/></svg>"##
        );
        refused_quickly(&in_a_stylesheet);
    }

    #[test]
    fn many_layers_or_gradient_fills_are_refused() {
        let opacity = format!(
            "{HEAD}{}</svg>",
            r#"<g opacity="0.5"><rect width="100" height="100"/></g>"#.repeat(4500)
        );
        let gradients = format!(
            r#"{HEAD}<radialGradient id="g"><stop offset="0"/><stop offset="1" stop-color="red"/></radialGradient>{}</svg>"#,
            r##"<rect width="100" height="100" fill="url(#g)"/>"##.repeat(5000)
        );
        let masks = format!(
            r#"{HEAD}<mask id="m"><rect width="100" height="100" fill="white"/></mask>{}</svg>"#,
            r##"<rect width="100" height="100" mask="url(#m)"/>"##.repeat(9000)
        );
        for attack in [&opacity, &gradients, &masks] {
            refused_quickly(attack);
        }
    }

    /// The audit's file: 2,221 dashed lines that each cut into a million dashes took about 100 s
    /// of CPU while the flat dash charge let it through.
    fn dash_bomb() -> String {
        let mut svg =
            String::from(r#"<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">"#);
        for i in 0..2221 {
            let y = (i % 512) as f32 + 0.5;
            svg.push_str(&format!(
                r##"<path d="M0 {y}H1000000" stroke="black" stroke-dasharray="0.5"/>"##
            ));
        }
        svg.push_str("</svg>");
        svg
    }

    #[test]
    fn dashes_are_charged_by_how_many_there_will_be() -> anyhow::Result<()> {
        let line = |d: &str| -> anyhow::Result<tiny_skia::Path> {
            let svg = format!(r#"{HEAD}<path d="{d}" stroke="black"/></svg>"#);
            let tree = usvg::Tree::from_str(&svg, &usvg::Options::default()).context("parse")?;
            let Some(usvg::Node::Path(path)) = tree.root().children().first() else {
                anyhow::bail!("no path");
            };
            Ok(path.data().clone())
        };
        let long = line("M0 0H1000000")?;
        let dashes = expected_dashes(&long, &[0.5, 0.5]);
        assert!((999_000.0..1_001_000.0).contains(&dashes), "{dashes}");
        assert!(dashes > MAX_DASHES, "one such line is already over the whole budget");
        let short = line("M0 0H100V100")?;
        let dashes = expected_dashes(&short, &[5.0, 5.0, 2.0, 3.0]);
        assert!((27.0..=28.5).contains(&dashes), "{dashes}");
        let curve = line("M0 0C0 100 100 100 100 0")?;
        assert!(
            expected_dashes(&curve, &[1.0, 1.0]) >= 100.0,
            "a curve is never undercounted"
        );
        assert_eq!(expected_dashes(&short, &[f32::NAN, 1.0]), f64::INFINITY);
        Ok(())
    }

    #[test]
    fn a_line_cut_into_millions_of_dashes_is_refused() {
        refused_quickly(&dash_bomb());
        refused_quickly(&format!(
            r#"{HEAD}<path d="M0 0H1000000" stroke="black" stroke-dasharray="0.5"/></svg>"#
        ));
        // Many modest lines add up across the drawing.
        refused_quickly(&format!(
            "{HEAD}{}</svg>",
            r#"<path d="M0 0H10000" stroke="black" stroke-dasharray="0.5"/>"#.repeat(20)
        ));
    }

    #[test]
    fn ordinary_dashed_outlines_still_render() -> anyhow::Result<()> {
        let svg = format!(
            r#"{HEAD}<circle cx="50" cy="50" r="40" fill="none" stroke="black" stroke-dasharray="4 2"/>
            <rect x="10" y="10" width="80" height="80" fill="none" stroke="red" stroke-dasharray="1"/></svg>"#
        );
        let image = decoded(&normalise_logo(svg.as_bytes()).context("logo")?)?;
        assert_eq!((image.width(), image.height()), (LOGO_SIZE, LOGO_SIZE));
        Ok(())
    }

    #[test]
    fn ordinary_logos_with_gradients_masks_and_stylesheets_still_render() -> anyhow::Result<()> {
        let svg = format!(
            r##"{HEAD}<style>.a{{fill:url(#g)}}</style>
            <defs><linearGradient id="g"><stop offset="0" stop-color="#1E2C43"/><stop offset="1" stop-color="#2A9D8F"/></linearGradient>
            <clipPath id="c"><circle cx="50" cy="50" r="45"/></clipPath>
            <mask id="m"><rect width="100" height="100" fill="white"/></mask></defs>
            <g clip-path="url(#c)" mask="url(#m)" opacity="0.9"><rect class="a" width="100" height="100"/></g></svg>"##
        );
        let image = decoded(&normalise_logo(svg.as_bytes()).context("logo")?)?;
        assert_eq!((image.width(), image.height()), (LOGO_SIZE, LOGO_SIZE));
        Ok(())
    }
}

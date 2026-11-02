/** The longest side of a logo drawn from an SVG; the server keeps logos at most this size anyway. */
export const SVG_LOGO_SIZE = 512;

const CANNOT_DRAW = "That SVG could not be drawn. Save the logo as a PNG instead.";

/** The SVG's width over its height, from its viewBox or its width and height, or square when it has neither. */
export function svgAspect(text: string): number {
  const root = text.match(/<svg\b[^>]*>/i)?.[0] ?? "";
  const viewBox = /viewBox\s*=\s*["']([^"']+)["']/i.exec(root)?.[1].trim().split(/[\s,]+/).map(Number);
  if (viewBox && viewBox.length === 4 && viewBox[2] > 0 && viewBox[3] > 0) return viewBox[2] / viewBox[3];
  const size = (name: string) => Number(new RegExp(`\\s${name}\\s*=\\s*["']\\s*([\\d.]+)`, "i").exec(root)?.[1]);
  const width = size("width");
  const height = size("height");
  if (width > 0 && height > 0) return width / height;
  return 1;
}

/** Canvas size for an aspect ratio, with the longer side at `limit`. */
export function fitWithin(aspect: number, limit = SVG_LOGO_SIZE): { width: number; height: number } {
  const safe = Number.isFinite(aspect) && aspect > 0 ? aspect : 1;
  if (safe >= 1) return { width: limit, height: Math.max(1, Math.round(limit / safe)) };
  return { width: Math.max(1, Math.round(limit * safe)), height: limit };
}

/**
 * Draws an SVG into a PNG in the browser, since the server takes only raster logos. The SVG is
 * loaded as an image, so it can neither run scripts nor fetch anything.
 */
export async function svgToPng(bytes: Uint8Array): Promise<Uint8Array> {
  const text = new TextDecoder().decode(bytes);
  const { width, height } = fitWithin(svgAspect(text));
  const url = URL.createObjectURL(new Blob([bytes.slice().buffer], { type: "image/svg+xml" }));
  try {
    const image = new Image(width, height);
    image.src = url;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d");
    context?.drawImage(image, 0, 0, width, height);
    const blob = context ? await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png")) : null;
    if (!blob) throw new Error(CANNOT_DRAW);
    return new Uint8Array(await blob.arrayBuffer());
  } catch {
    throw new Error(CANNOT_DRAW);
  } finally {
    URL.revokeObjectURL(url);
  }
}

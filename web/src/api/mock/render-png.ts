import { sniffImage } from "@/lib/images";

const LOGO_SIZE = 512;

/**
 * Re-encodes an uploaded image as a PNG of at most 512px, as the server does. Returns undefined
 * where there is no canvas (unit tests), leaving the caller to keep the original bytes.
 */
export async function renderPng(bytes: Uint8Array): Promise<Uint8Array | undefined> {
  const type = sniffImage(bytes)?.type;
  if (!type || typeof document === "undefined" || typeof URL.createObjectURL !== "function") return undefined;
  const url = URL.createObjectURL(new Blob([bytes.slice().buffer], { type }));
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    const width = image.naturalWidth || LOGO_SIZE;
    const height = image.naturalHeight || LOGO_SIZE;
    const scale = Math.min(1, LOGO_SIZE / Math.max(width, height));
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(width * scale));
    canvas.height = Math.max(1, Math.round(height * scale));
    canvas.getContext("2d")?.drawImage(image, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png"));
    return blob ? new Uint8Array(await blob.arrayBuffer()) : undefined;
  } catch {
    return undefined;
  } finally {
    URL.revokeObjectURL(url);
  }
}

// A real 48x48 RGBA PNG: a white disc on teal. Kept as base64 so the fixture lives in source.
export const LOGO_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAgUlEQVR4nO3YwRGAIBQDURqwbwuwX21BPsHFYTOTo5J3hHZc5/3nNnqAAHqAAHqAAHqAAHqAAHqAgPQP32RJQCXLAEaCAxLBAMl8DpgRAeT4KkKAAAECBAjo/mgWorJjX0AaUd2w930ggRg92ztxBZI8z3chugLoCqArgK4AugLoPhP8iC+M1/dWAAAAAElFTkSuQmCC";

export const LOGO_PNG = Buffer.from(LOGO_PNG_BASE64, "base64");

/** The PNG cut off after its header: it looks right to a quick check but cannot be decoded. */
export const TRUNCATED_PNG = LOGO_PNG.subarray(0, 40);

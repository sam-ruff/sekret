import { describe, expect, it } from "vitest";
import { checkLogoFile, MAX_LOGO_BYTES, sniffImage, svgProblem, validateImage } from "./images";
import { fitWithin, svgAspect } from "./svg-to-png";

const PNG = Uint8Array.from(
  atob(
    "iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAgUlEQVR4nO3YwRGAIBQDURqwbwuwX21BPsHFYTOTo5J3hHZc5/3nNnqAAHqAAHqAAHqAAHqAAHqAgPQP32RJQCXLAEaCAxLBAMl8DpgRAeT4KkKAAAECBAjo/mgWorJjX0AaUd2w930ggRg92ztxBZI8z3chugLoCqArgK4AugLoPhP8iC+M1/dWAAAAAElFTkSuQmCC",
  ),
  (c) => c.charCodeAt(0),
);

const bytes = (...values: number[]) => Uint8Array.from(values);
const text = (value: string) => new TextEncoder().encode(value);

function pngWithSize(width: number, height: number): Uint8Array {
  const copy = PNG.slice();
  new DataView(copy.buffer).setUint32(16, width);
  new DataView(copy.buffer).setUint32(20, height);
  return copy;
}

const gif = (w: number, h: number) => bytes(...text("GIF89a"), w & 0xff, w >> 8, h & 0xff, h >> 8, 0, 0);
const jpeg = (w: number, h: number) =>
  bytes(0xff, 0xd8, 0xff, 0xe0, 0, 4, 0, 0, 0xff, 0xc0, 0, 11, 8, h >> 8, h & 0xff, w >> 8, w & 0xff, 3, 0, 0);
const webpX = (w: number, h: number) =>
  bytes(...text("RIFF"), 0, 0, 0, 0, ...text("WEBPVP8X"), 10, 0, 0, 0, 0, 0, 0, 0, (w - 1) & 0xff, (w - 1) >> 8, 0, (h - 1) & 0xff, (h - 1) >> 8, 0);

describe("sniffImage", () => {
  it("reads type and size from the magic bytes and headers", () => {
    expect(sniffImage(PNG)).toEqual({ type: "image/png", width: 48, height: 48 });
    expect(sniffImage(gif(16, 9))).toEqual({ type: "image/gif", width: 16, height: 9 });
    expect(sniffImage(jpeg(640, 480))).toEqual({ type: "image/jpeg", width: 640, height: 480 });
    expect(sniffImage(webpX(300, 200))).toEqual({ type: "image/webp", width: 300, height: 200 });
    expect(sniffImage(text('﻿  <?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>'))?.type).toBe("image/svg+xml");
  });

  it("does not trust file names or content types, only content", () => {
    expect(sniffImage(text("hello"))).toBeUndefined();
    expect(sniffImage(text('{"svg": 1}'))).toBeUndefined();
    expect(sniffImage(bytes(0x4d, 0x5a, 0x90, 0))).toBeUndefined();
    expect(sniffImage(new Uint8Array())).toBeUndefined();
  });
});

describe("checkLogoFile", () => {
  it("accepts a real image", () => {
    expect(checkLogoFile(PNG)).toEqual({ ok: true, type: "image/png" });
  });

  it("refuses large files, other files and oversized images", () => {
    const big = new Uint8Array(MAX_LOGO_BYTES + 1);
    big.set(PNG);
    expect(checkLogoFile(big)).toEqual({ ok: false, message: "Logos can be at most 512 KiB." });
    expect(checkLogoFile(text("hello"))).toMatchObject({ ok: false, message: expect.stringContaining("Choose a PNG") });
    expect(checkLogoFile(pngWithSize(5000, 10))).toMatchObject({ ok: false, message: expect.stringContaining("4096") });
  });
});

describe("validateImage", () => {
  it("passes a complete PNG and refuses every SVG, as the server does", () => {
    expect(validateImage(PNG)).toEqual({ ok: true, type: "image/png" });
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect/></svg>';
    expect(validateImage(text(svg))).toEqual({ ok: false, message: "SVG files are not accepted; convert the logo to PNG first" });
  });

  it("refuses magic bytes without a readable image", () => {
    expect(validateImage(PNG.subarray(0, 40))).toMatchObject({ ok: false, message: expect.stringContaining("could not be read") });
    expect(validateImage(bytes(0x89, ...text("PNG\r\n\x1a\n")))).toMatchObject({ ok: false });
    expect(validateImage(pngWithSize(0, 10))).toMatchObject({ ok: false, message: expect.stringContaining("empty") });
    expect(validateImage(pngWithSize(4097, 1))).toMatchObject({ ok: false, message: expect.stringContaining("larger than 4096") });
  });

  it("names unknown files the way the server does", () => {
    expect(validateImage(text("hello"))).toEqual({ ok: false, message: "the file is not a PNG, JPEG, GIF or WebP image" });
  });
});

describe("svgProblem", () => {
  it("lets a plain SVG through to be drawn in the browser", () => {
    expect(svgProblem(text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect/></svg>'))).toBeUndefined();
  });

  it("refuses a document type, whose entities could expand without limit, and a missing namespace", () => {
    expect(svgProblem(text('<!DOCTYPE svg [<!ENTITY a "a">]><svg xmlns="http://www.w3.org/2000/svg"/>'))).toContain("document type");
    expect(svgProblem(text('<svg viewBox="0 0 1 1"><rect/></svg>'))).toContain("no SVG namespace");
  });
});

describe("svg logo size", () => {
  it("keeps the SVG's shape within 512 pixels", () => {
    expect(fitWithin(svgAspect('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 100">'))).toEqual({ width: 512, height: 256 });
    expect(fitWithin(svgAspect('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="40">'))).toEqual({ width: 128, height: 512 });
    expect(fitWithin(svgAspect('<svg xmlns="http://www.w3.org/2000/svg">'))).toEqual({ width: 512, height: 512 });
    expect(fitWithin(svgAspect('<svg viewBox="0 0 0 0" width="0">'))).toEqual({ width: 512, height: 512 });
  });
});

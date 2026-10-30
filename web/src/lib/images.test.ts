import { describe, expect, it } from "vitest";
import { checkLogoFile, MAX_LOGO_BYTES, sniffImage, validateImage } from "./images";

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
  it("passes a complete PNG and a clean SVG", () => {
    expect(validateImage(PNG)).toEqual({ ok: true, type: "image/png" });
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><defs><linearGradient id="g"/></defs><rect fill="url(#g)"/><use href="#g"/></svg>';
    expect(validateImage(text(svg))).toEqual({ ok: true, type: "image/svg+xml" });
  });

  it("refuses magic bytes without a readable image", () => {
    expect(validateImage(PNG.subarray(0, 40))).toMatchObject({ ok: false, message: expect.stringContaining("could not be read") });
    expect(validateImage(bytes(0x89, ...text("PNG\r\n\x1a\n")))).toMatchObject({ ok: false });
    expect(validateImage(pngWithSize(0, 10))).toMatchObject({ ok: false, message: expect.stringContaining("empty") });
    expect(validateImage(pngWithSize(4097, 1))).toMatchObject({ ok: false, message: expect.stringContaining("larger than 4096") });
  });

  it.each([
    "<script>alert(1)</script>",
    '<rect onload="alert(1)"/>',
    '<a href="javascript:alert(1)"><rect/></a>',
    '<image href="https://tracker.example/p.png"/>',
    "<foreignObject><div>hi</div></foreignObject>",
    "<style>@import url(https://evil.example/x.css);</style>",
    '<rect fill="url(https://evil.example/p.svg#a)"/>',
  ])("refuses an SVG containing %s", (body) => {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">${body}</svg>`;
    expect(validateImage(text(svg))).toMatchObject({ ok: false, message: expect.stringContaining("the SVG is not allowed") });
  });

  it("refuses an SVG without the SVG namespace or with a DTD", () => {
    expect(validateImage(text('<svg viewBox="0 0 1 1"><rect/></svg>'))).toMatchObject({ ok: false });
    expect(validateImage(text('<!DOCTYPE svg [<!ENTITY a "a">]><svg xmlns="http://www.w3.org/2000/svg"/>'))).toMatchObject({ ok: false });
  });

  it("names unknown files the way the server does", () => {
    expect(validateImage(text("hello"))).toEqual({ ok: false, message: "the file is not a PNG, JPEG, GIF, WebP or SVG image" });
  });
});

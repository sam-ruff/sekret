import { describe, expect, it } from "vitest";
import { isValidSecretKey, parseDotenv } from "./dotenv";

describe("parseDotenv", () => {
  it("parses simple pairs and ignores comments and blanks", () => {
    const result = parseDotenv("# header\n\nA=1\nB = two \n  # indented comment\n");
    expect(result.entries).toEqual([
      { key: "A", value: "1" },
      { key: "B", value: "two" },
    ]);
    expect(result.issues).toEqual([]);
  });

  it("strips export and inline comments on unquoted values", () => {
    const result = parseDotenv("export TOKEN=abc # used by ci\nURL=http://x/#frag");
    expect(result.entries).toEqual([
      { key: "TOKEN", value: "abc" },
      { key: "URL", value: "http://x/#frag" },
    ]);
  });

  it("keeps quoted values verbatim, including hashes and spaces", () => {
    const result = parseDotenv(`A="hello # world"\nB='single $quoted'\nC=\`tick\``);
    expect(result.entries).toEqual([
      { key: "A", value: "hello # world" },
      { key: "B", value: "single $quoted" },
      { key: "C", value: "tick" },
    ]);
  });

  it("handles escapes and multi-line double quoted values", () => {
    const result = parseDotenv('KEY="line1\\nline2 \\"q\\""\nPEM="-----BEGIN-----\nabc\n-----END-----"\nNEXT=1');
    expect(result.entries).toEqual([
      { key: "KEY", value: 'line1\nline2 "q"' },
      { key: "PEM", value: "-----BEGIN-----\nabc\n-----END-----" },
      { key: "NEXT", value: "1" },
    ]);
  });

  it("allows empty values and lets later keys win", () => {
    const result = parseDotenv("A=\nA=second\nB=");
    expect(result.entries).toEqual([
      { key: "A", value: "second" },
      { key: "B", value: "" },
    ]);
  });

  it("reports malformed lines with their line numbers", () => {
    const result = parseDotenv("GOOD=1\nnot a pair\n1BAD=x\nOPEN='never closed");
    expect(result.entries).toEqual([{ key: "GOOD", value: "1" }]);
    expect(result.issues.map((i) => i.line)).toEqual([2, 3, 4]);
  });

  it("normalises Windows line endings", () => {
    expect(parseDotenv("A=1\r\nB=2\r\n").entries).toEqual([
      { key: "A", value: "1" },
      { key: "B", value: "2" },
    ]);
  });
});

describe("isValidSecretKey", () => {
  it("mirrors the server's key rules", () => {
    expect(isValidSecretKey("_A.b-1")).toBe(true);
    expect(isValidSecretKey("1A")).toBe(false);
    expect(isValidSecretKey("A B")).toBe(false);
    expect(isValidSecretKey("")).toBe(false);
  });
});

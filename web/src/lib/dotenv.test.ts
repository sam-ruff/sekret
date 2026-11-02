import { describe, expect, it } from "vitest";
import { duplicateText, isValidSecretKey, parseDotenv } from "./dotenv";

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

  it("names every key set on more than one line and the line that wins", () => {
    const result = parseDotenv('API_URL=a\nB=1\n# note\nAPI_URL="b"\nB=2\nAPI_URL=c\nC=3');
    expect(result.duplicates).toEqual([
      { key: "B", line: 5, earlier: [2] },
      { key: "API_URL", line: 6, earlier: [1, 4] },
    ]);
    expect(result.entries).toContainEqual({ key: "API_URL", value: "c" });
    expect(parseDotenv("A=1\nB=2").duplicates).toEqual([]);
    expect(result.duplicates.map(duplicateText)).toEqual([
      "Line 5: B is also on line 2. The value from line 5 is used.",
      "Line 6: API_URL is also on lines 1 and 4. The value from line 6 is used.",
    ]);
  });

  it("reports malformed lines with their line numbers", () => {
    const result = parseDotenv("GOOD=1\nnot a pair\n1BAD=x\nOPEN='never closed");
    expect(result.entries).toEqual([{ key: "GOOD", value: "1" }]);
    expect(result.issues.map((i) => i.line)).toEqual([2, 3, 4]);
  });

  it("lets a backslash at the end of a line escape only the newline", () => {
    const result = parseDotenv('A="one\\\ntwo"\nB=2');
    expect(result.entries).toEqual([
      { key: "A", value: "one\\\ntwo" },
      { key: "B", value: "2" },
    ]);
  });

  it("closes a multi-line value on a later line and keeps the lines after it", () => {
    const result = parseDotenv('A="x\n\n\ny" trailing\nB=2');
    expect(result.entries).toEqual([
      { key: "A", value: "x\n\n\ny" },
      { key: "B", value: "2" },
    ]);
  });

  it("parses a huge unterminated double quote in linear time", () => {
    const started = performance.now();
    const result = parseDotenv(`A="${"x\n".repeat(200_000)}`);
    // The old parser took minutes on this; a linear one takes milliseconds.
    expect(performance.now() - started).toBeLessThan(2_000);
    expect(result.issues).toEqual([{ line: 1, message: "unterminated quote for A" }]);
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

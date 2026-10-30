import { describe, expect, it } from "vitest";
import { globMatch } from "./glob";

const path = (pattern: string, text: string) => globMatch(pattern, text, "/");

describe("globMatch", () => {
  it("matches literals and single stars within a segment", () => {
    expect(path("/app", "/app")).toBe(true);
    expect(path("/app", "/apps")).toBe(false);
    expect(path("/app/*", "/app/db")).toBe(true);
    expect(path("/app/*", "/app/db/primary")).toBe(false);
    expect(path("/*", "/anything")).toBe(true);
  });

  it("lets double stars cross separators", () => {
    expect(path("/app/**", "/app/db/primary")).toBe(true);
    expect(path("/**", "/")).toBe(true);
    expect(path("/**", "/x/y/z")).toBe(true);
    expect(path("/app/**/creds", "/app/creds")).toBe(true);
    expect(path("/app/**/creds", "/app/a/b/creds")).toBe(true);
    expect(path("/app/**", "/other/db")).toBe(false);
  });

  it("treats question marks as one non-separator character", () => {
    expect(path("/env?", "/env1")).toBe(true);
    expect(path("/env?", "/env/")).toBe(false);
  });

  it("lets a single star match anything when there is no separator", () => {
    expect(globMatch("DB_*", "DB_PASS")).toBe(true);
    expect(globMatch("*", "a/b/c")).toBe(true);
    expect(globMatch("repo:sam-ruff/*:ref:refs/heads/main", "repo:sam-ruff/sekret:ref:refs/heads/main")).toBe(true);
    expect(globMatch("repo:sam-ruff/*:ref:refs/heads/main", "repo:evil/sekret:ref:refs/heads/main")).toBe(false);
  });

  it("terminates on pathological patterns", () => {
    expect(globMatch("*a".repeat(30), "a".repeat(60) + "b")).toBe(false);
  });
});

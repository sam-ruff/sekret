import { describe, expect, it } from "vitest";
import { countByChildFolder, matchesBelow, matchesSecret, relativeFolder } from "./secret-search";

const secret = (path: string, key: string, comment = "", tags: string[] = []) => ({ path, key, comment, tags });

describe("matchesSecret", () => {
  it("looks at the key, comment and tags without caring about case", () => {
    expect(matchesSecret(secret("/", "SMTP_PASSWORD"), "smtp")).toBe(true);
    expect(matchesSecret(secret("/", "A", "Mail relay"), "RELAY")).toBe(true);
    expect(matchesSecret(secret("/", "A", "", ["email"]), "mail")).toBe(true);
    expect(matchesSecret(secret("/", "A"), "zzz")).toBe(false);
    expect(matchesSecret(secret("/", "A"), "  ")).toBe(true);
  });
});

describe("relativeFolder", () => {
  it("names folders below the parent and nothing else", () => {
    expect(relativeFolder("/", "/payments")).toBe("payments");
    expect(relativeFolder("/", "/payments/eu")).toBe("payments/eu");
    expect(relativeFolder("/payments", "/payments/eu")).toBe("eu");
    expect(relativeFolder("/payments", "/payments")).toBeNull();
    expect(relativeFolder("/pay", "/payments")).toBeNull();
    expect(relativeFolder("/", "/")).toBeNull();
  });
});

describe("countByChildFolder", () => {
  it("counts each secret under the folder directly inside the parent", () => {
    const counts = countByChildFolder("/", [
      secret("/", "TOP"),
      secret("/email", "SMTP"),
      secret("/payments", "A"),
      secret("/payments/eu", "B"),
    ]);
    expect(Object.fromEntries(counts)).toEqual({ email: 1, payments: 2 });
  });
});

describe("matchesBelow", () => {
  it("finds matches in subfolders only, nearest first", () => {
    const found = matchesBelow(
      "/",
      [secret("/", "WEBHOOK_TOP"), secret("/payments/eu", "WEBHOOK_EU"), secret("/payments", "WEBHOOK_SECRET"), secret("/email", "SMTP")],
      "webhook",
    );
    expect(found.map((s) => `${s.path}:${s.key}`)).toEqual(["/payments:WEBHOOK_SECRET", "/payments/eu:WEBHOOK_EU"]);
  });

  it("finds nothing without search text", () => {
    expect(matchesBelow("/", [secret("/email", "SMTP")], " ")).toEqual([]);
  });
});

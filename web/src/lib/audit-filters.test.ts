import { describe, expect, it } from "vitest";
import {
  auditQuery,
  auditSearchParams,
  dateRangeLabel,
  dayEnd,
  dayStart,
  EMPTY_AUDIT_FILTERS,
  hasActiveFilters,
  noMatchHint,
  parseAuditFilters,
  presetRange,
  DATE_PRESETS,
} from "./audit-filters";

describe("noMatchHint", () => {
  it("suggests a wider date range only when a date is set", () => {
    expect(noMatchHint({ ...EMPTY_AUDIT_FILTERS, action: "secret." })).not.toContain("date range");
    expect(noMatchHint({ ...EMPTY_AUDIT_FILTERS, from: "2026-01-01" })).toContain("wider date range");
    expect(noMatchHint({ ...EMPTY_AUDIT_FILTERS, to: "2026-01-01" })).toContain("wider date range");
  });
});

describe("audit filters", () => {
  it("round-trips through the URL, leaving defaults out", () => {
    const filters = {
      ...EMPTY_AUDIT_FILTERS,
      q: "deploy",
      action: "secret.",
      actorKind: "identity" as const,
      environment: "prod",
      from: "2026-03-01",
      to: "2026-03-07",
      order: "asc" as const,
    };
    const params = auditSearchParams(filters);
    expect(params.toString()).toBe("q=deploy&action=secret.&actor_kind=identity&env=prod&from=2026-03-01&to=2026-03-07&order=asc");
    expect(parseAuditFilters(params)).toEqual(filters);
    expect(auditSearchParams(EMPTY_AUDIT_FILTERS).toString()).toBe("");
  });

  it("ignores junk in the URL", () => {
    const parsed = parseAuditFilters(new URLSearchParams("actor_kind=robot&from=yesterday&order=sideways&q=%20x%20"));
    expect(parsed).toEqual({ ...EMPTY_AUDIT_FILTERS, q: "x" });
  });

  it("turns dates into an inclusive range of unix seconds", () => {
    const start = dayStart("2026-03-01");
    expect(dayEnd("2026-03-01") - start).toBe(86399);
    const query = auditQuery({ ...EMPTY_AUDIT_FILTERS, from: "2026-03-01", to: "2026-03-01", actorId: "u1", key: "K", path: "/app" });
    expect(query).toEqual({ order: "desc", since: start, until: start + 86399, actor_id: "u1", key: "K", path: "/app" });
  });

  it("sends only the filters that are set", () => {
    expect(auditQuery(EMPTY_AUDIT_FILTERS)).toEqual({ order: "desc" });
  });

  it("knows when anything narrows the results", () => {
    expect(hasActiveFilters(EMPTY_AUDIT_FILTERS)).toBe(false);
    expect(hasActiveFilters({ ...EMPTY_AUDIT_FILTERS, order: "asc" })).toBe(false);
    expect(hasActiveFilters({ ...EMPTY_AUDIT_FILTERS, path: "/x" })).toBe(true);
  });

  it("labels date ranges", () => {
    const today = new Date(2026, 2, 10);
    const week = presetRange(DATE_PRESETS[1], today);
    expect(week).toEqual({ from: "2026-03-04", to: "2026-03-10" });
    expect(dateRangeLabel(week.from, week.to, today)).toBe("Last 7 days");
    expect(dateRangeLabel("", "", today)).toBe("Any time");
    expect(dateRangeLabel("2026-01-02", "2026-01-05", today)).toBe("2 Jan - 5 Jan");
    expect(dateRangeLabel("2026-01-02", "", today)).toBe("From 2 Jan");
  });
});

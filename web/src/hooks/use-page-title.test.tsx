import { renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";
import { PageTitleScope, pageTitle, usePageTitle } from "./use-page-title";

describe("page titles", () => {
  it("names the page, then the project when there is one", () => {
    expect(pageTitle("Settings", "Storefront")).toBe("Settings · Storefront · sekret");
    expect(pageTitle("Users")).toBe("Users · sekret");
    expect(pageTitle(undefined)).toBe("sekret");
  });

  it("takes the project from the page it sits in", () => {
    const wrapper = ({ children }: { children: ReactNode }) => (
      <PageTitleScope.Provider value="Payments API">{children}</PageTitleScope.Provider>
    );
    renderHook(() => usePageTitle("Secrets"), { wrapper });
    expect(document.title).toBe("Secrets · Payments API · sekret");
  });
});

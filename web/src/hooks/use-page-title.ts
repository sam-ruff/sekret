import { createContext, useContext, useEffect } from "react";

/** The project a page belongs to, named in its tab so several open projects can be told apart. */
export const PageTitleScope = createContext<string | undefined>(undefined);

export function pageTitle(title: string | undefined, scope?: string): string {
  return [title, scope, "sekret"].filter(Boolean).join(" · ");
}

/** Sets the browser tab's title while the page is shown. */
export function usePageTitle(title: string | undefined): void {
  const scope = useContext(PageTitleScope);
  useEffect(() => {
    document.title = pageTitle(title, scope);
  }, [title, scope]);
}

import { useEffect } from "react";

export function pageTitle(title: string | undefined): string {
  return title ? `${title} · sekret` : "sekret";
}

/** Sets the browser tab's title while the page is shown. */
export function usePageTitle(title: string | undefined): void {
  useEffect(() => {
    document.title = pageTitle(title);
  }, [title]);
}

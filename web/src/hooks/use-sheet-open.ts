import { useSyncExternalStore } from "react";

const SHEET = '[data-slot="sheet-content"]';

function subscribe(onChange: () => void): () => void {
  const observer = new MutationObserver(onChange);
  observer.observe(document.body, { childList: true, subtree: true });
  return () => observer.disconnect();
}

function snapshot(): boolean {
  return document.querySelector(SHEET) !== null;
}

/** Whether a drawer is on screen anywhere in the page. */
export function useSheetOpen(): boolean {
  return useSyncExternalStore(subscribe, snapshot, () => false);
}

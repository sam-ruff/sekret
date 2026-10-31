interface PageWindow {
  addEventListener: (type: "pageshow", listener: (event: PageTransitionEvent) => void) => void;
  location: { reload: () => void };
}

/**
 * Reloads a page the browser restored from its back-forward cache, which would otherwise come back
 * with revealed values and a session that may have ended or a server that may have been sealed.
 */
export function reloadWhenRestored(win: PageWindow = window): void {
  win.addEventListener("pageshow", (event) => {
    if (event.persisted) win.location.reload();
  });
}

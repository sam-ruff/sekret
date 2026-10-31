/**
 * Set once the page is on its way out, by signing out or by the browser hiding it. While it is set,
 * nothing may navigate elsewhere and nothing that holds a secret is shown.
 */
let leaving = false;
const listeners = new Set<() => void>();

function notify(): void {
  listeners.forEach((listener) => listener());
}

export function isLeaving(): boolean {
  return leaving;
}

export function beginLeaving(): void {
  if (leaving) return;
  leaving = true;
  notify();
}

/** For when leaving was abandoned, such as a sign-out the server refused. */
export function stopLeaving(): void {
  if (!leaving) return;
  leaving = false;
  notify();
}

export function subscribeLeaving(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Full-page navigation, behind an object so tests can watch it. */
export const browserNavigation = {
  assign(url: string): void {
    window.location.assign(url);
  },
  reload(): void {
    window.location.reload();
  },
};

import { useEffect, useRef } from "react";

/** How long revealed values stay on screen with nobody using the page. */
export const REVEAL_IDLE_MS = 3 * 60_000;

/** How often the wall clock is checked, since timers stall in background tabs and during sleep. */
export const IDLE_CHECK_MS = 5_000;

const ACTIVITY_EVENTS = ["pointerdown", "keydown", "wheel", "touchstart"] as const;
const RESUME_EVENTS = ["focus", "pageshow"] as const;

/**
 * While `active`, calls `onHidden` as soon as the page is hidden, such as on switching tab or app,
 * so revealed values are gone before the system takes its app-switcher snapshot.
 */
export function useOnPageHidden(active: boolean, onHidden: () => void): void {
  const callback = useRef(onHidden);
  useEffect(() => {
    callback.current = onHidden;
  }, [onHidden]);

  useEffect(() => {
    if (!active) return;
    const onVisibility = () => {
      if (document.visibilityState === "hidden") callback.current();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, [active]);
}

/**
 * While `active`, calls `onIdle` once nobody has touched the page for `ms`. Elapsed time is
 * measured with the wall clock, so a laptop that slept with values on screen hides them as soon
 * as the page is seen again rather than when a paused timer finally runs out.
 */
export function useIdle(active: boolean, onIdle: () => void, ms = REVEAL_IDLE_MS): void {
  const callback = useRef(onIdle);
  useEffect(() => {
    callback.current = onIdle;
  }, [onIdle]);

  useEffect(() => {
    if (!active) return;
    let lastActivity = Date.now();
    let timer = 0;
    const check = () => {
      if (Date.now() - lastActivity < ms) return;
      lastActivity = Date.now();
      callback.current();
    };
    const schedule = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(check, ms);
    };
    const touched = () => {
      lastActivity = Date.now();
      schedule();
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") check();
    };
    schedule();
    const interval = window.setInterval(check, Math.min(IDLE_CHECK_MS, ms));
    ACTIVITY_EVENTS.forEach((type) => window.addEventListener(type, touched, { capture: true, passive: true }));
    RESUME_EVENTS.forEach((type) => window.addEventListener(type, check));
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearTimeout(timer);
      window.clearInterval(interval);
      ACTIVITY_EVENTS.forEach((type) => window.removeEventListener(type, touched, { capture: true }));
      RESUME_EVENTS.forEach((type) => window.removeEventListener(type, check));
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [active, ms]);
}

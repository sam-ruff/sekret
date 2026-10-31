import { useEffect, useRef } from "react";

/** How long revealed values stay on screen with nobody using the page. */
export const REVEAL_IDLE_MS = 3 * 60_000;

const ACTIVITY_EVENTS = ["pointerdown", "keydown", "wheel", "touchstart"] as const;

/** While `active`, calls `onIdle` once nobody has touched the page for `ms`. */
export function useIdle(active: boolean, onIdle: () => void, ms = REVEAL_IDLE_MS): void {
  const callback = useRef(onIdle);
  useEffect(() => {
    callback.current = onIdle;
  }, [onIdle]);

  useEffect(() => {
    if (!active) return;
    let timer = window.setTimeout(() => callback.current(), ms);
    const restart = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => callback.current(), ms);
    };
    ACTIVITY_EVENTS.forEach((type) => window.addEventListener(type, restart, { capture: true, passive: true }));
    return () => {
      window.clearTimeout(timer);
      ACTIVITY_EVENTS.forEach((type) => window.removeEventListener(type, restart, { capture: true }));
    };
  }, [active, ms]);
}

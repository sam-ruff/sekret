import { useEffect, useState } from "react";

/** Whole seconds left until `until` (milliseconds since the epoch), ticking down live; 0 once it passes. */
export function useCountdown(until: number): number {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (until <= 0) return;
    const tick = () => {
      const current = Date.now();
      setNow(current);
      if (current >= until) window.clearInterval(timer);
    };
    const timer = window.setInterval(tick, 250);
    const first = window.setTimeout(tick, 0);
    return () => {
      window.clearInterval(timer);
      window.clearTimeout(first);
    };
  }, [until]);

  return Math.max(0, Math.ceil((until - now) / 1000));
}

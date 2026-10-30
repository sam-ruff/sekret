import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { cn } from "@/lib/utils";

export interface LinkTab {
  value: string;
  label: string;
  to: string;
  testId?: string;
  destructive?: boolean;
}

const FADE_LEFT = "linear-gradient(to right, transparent, black 2rem)";
const FADE_RIGHT = "linear-gradient(to left, transparent, black 2rem)";
const FADE_BOTH = "linear-gradient(to right, transparent, black 2rem, black calc(100% - 2rem), transparent)";

/** Fades whichever edge of a horizontal scroller still has hidden content. */
function useEdgeFade() {
  const ref = useRef<HTMLElement>(null);
  const [mask, setMask] = useState<string | undefined>();

  const update = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const left = el.scrollLeft > 1;
    const right = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
    setMask(left && right ? FADE_BOTH : left ? FADE_LEFT : right ? FADE_RIGHT : undefined);
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, [update]);

  return { ref, mask, update };
}

/** Tabs that are plain links, so the selected tab lives in the URL. Scrolls sideways on narrow screens. */
export function LinkTabs({ tabs, current, label }: { tabs: LinkTab[]; current: string; label: string }) {
  const { ref, mask, update } = useEdgeFade();

  useEffect(() => {
    const active = ref.current?.querySelector<HTMLElement>('[aria-current="page"]');
    active?.scrollIntoView({ block: "nearest", inline: "nearest" });
    update();
  }, [current, ref, update]);

  return (
    <nav
      ref={ref}
      onScroll={update}
      className="-mx-4 scroll-px-10 overflow-x-auto px-4 [scrollbar-width:none] md:mx-0 md:px-0 [&::-webkit-scrollbar]:hidden"
      style={{ maskImage: mask, WebkitMaskImage: mask }}
      aria-label={label}
    >
      <div className="flex w-max min-w-full gap-1 border-b">
        {tabs.map((tab) => {
          const active = tab.value === current;
          return (
            <Link
              key={tab.value}
              to={tab.to}
              aria-current={active ? "page" : undefined}
              data-testid={tab.testId}
              className={cn(
                "-mb-px rounded-t-md border-b-2 px-3 py-2 text-sm font-medium whitespace-nowrap transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
                active ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
                tab.destructive && (active ? "border-destructive text-destructive" : "text-destructive/80 hover:text-destructive"),
              )}
            >
              {tab.label}
            </Link>
          );
        })}
      </div>
    </nav>
  );
}

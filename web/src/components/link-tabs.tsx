import { ChevronLeft, ChevronRight } from "lucide-react";
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

const FADE_LEFT = "linear-gradient(to right, transparent, black 3rem)";
const FADE_RIGHT = "linear-gradient(to left, transparent, black 3rem)";
const FADE_BOTH = "linear-gradient(to right, transparent, black 3rem, black calc(100% - 3rem), transparent)";

/** Which edges of a horizontal scroller still have hidden content. */
function useOverflow() {
  const ref = useRef<HTMLElement>(null);
  const [edges, setEdges] = useState({ left: false, right: false });

  const update = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const left = el.scrollLeft > 1;
    const right = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
    setEdges((current) => (current.left === left && current.right === right ? current : { left, right }));
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, [update]);

  return { ref, edges, update };
}

/**
 * Tabs that are plain links, so the selected tab lives in the URL. On narrow screens they scroll
 * sideways, with arrows at whichever edge hides more tabs.
 */
export function LinkTabs({ tabs, current, label }: { tabs: LinkTab[]; current: string; label: string }) {
  const { ref, edges, update } = useOverflow();
  const mask = edges.left && edges.right ? FADE_BOTH : edges.left ? FADE_LEFT : edges.right ? FADE_RIGHT : undefined;

  useEffect(() => {
    const active = ref.current?.querySelector<HTMLElement>('[aria-current="page"]');
    active?.scrollIntoView({ block: "nearest", inline: "nearest" });
    update();
  }, [current, ref, update]);

  const scrollBy = (direction: 1 | -1) => {
    const el = ref.current;
    if (!el) return;
    el.scrollBy({ left: direction * el.clientWidth * 0.6, behavior: "smooth" });
  };

  // Keyboard and screen reader users reach every tab by tabbing, so the arrows are for pointers only.
  const arrow = (direction: 1 | -1) => (
    <button
      type="button"
      tabIndex={-1}
      aria-hidden
      onClick={() => scrollBy(direction)}
      className={cn(
        "absolute top-0 bottom-px z-10 flex w-10 items-center text-muted-foreground hover:text-foreground",
        direction === 1
          ? "-right-4 justify-end bg-linear-to-l from-background from-60% to-transparent pr-3 md:right-0 md:pr-0"
          : "-left-4 justify-start bg-linear-to-r from-background from-60% to-transparent pl-3 md:left-0 md:pl-0",
      )}
      data-testid={direction === 1 ? "tabs-scroll-right" : "tabs-scroll-left"}
    >
      {direction === 1 ? <ChevronRight className="size-4" /> : <ChevronLeft className="size-4" />}
    </button>
  );

  return (
    <div className="relative">
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
                  tab.destructive && (active ? "border-destructive text-destructive" : "text-destructive hover:text-destructive"),
                )}
              >
                {tab.label}
              </Link>
            );
          })}
        </div>
      </nav>
      {edges.left && arrow(-1)}
      {edges.right && arrow(1)}
    </div>
  );
}

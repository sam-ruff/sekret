import { cn } from "@/lib/utils";

const LOGO_PATH =
  "M262 234 L260 371 L280 377 L297 375 L300 383 L226 759 L230 763 L409 761 L457 575 L457 558 L435 539 " +
  "L421 511 L421 476 L437 444 L454 429 L480 417 L509 415 L531 421 L551 433 L570 456 L578 474 L578 511 " +
  "L564 539 L542 558 L542 573 L590 761 L769 763 L773 746 L699 381 L704 375 L731 377 L741 369 L741 238 " +
  "L733 232 L632 234 L630 305 L562 308 L557 234 L446 232 L440 236 L440 305 L372 308 L367 234 L262 234 Z";

/** The sekret mark. It draws in `currentColor`, so set the colour with a text class. */
export function Logo({ className, title }: { className?: string; title?: string }) {
  return (
    <svg
      viewBox="211 209 578 578"
      xmlns="http://www.w3.org/2000/svg"
      fill="currentColor"
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      className={cn("shrink-0", className)}
      data-testid="logo"
    >
      <path d={LOGO_PATH} />
    </svg>
  );
}

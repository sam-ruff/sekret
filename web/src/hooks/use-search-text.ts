import { useEffect, useState } from "react";
import { useDebouncedValue } from "./use-debounced-value";

/**
 * Text for a search box whose committed value lives elsewhere, such as the URL. Typing commits
 * after a pause; a change from outside (for example "Clear filters") replaces what is typed.
 */
export function useSearchText(value: string, onSearch: (q: string) => void, delay = 300) {
  const [text, setText] = useState(value);
  const [seen, setSeen] = useState(value);
  if (value !== seen) {
    setSeen(value);
    if (value !== text.trim()) setText(value);
  }
  const settled = useDebouncedValue(text.trim(), delay);

  useEffect(() => {
    if (settled === text.trim() && settled !== value) onSearch(settled);
  }, [settled, text, value, onSearch]);

  return [text, setText] as const;
}

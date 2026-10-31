import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderResult } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router";
import { vi } from "vitest";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/lib/theme";

// Radix measures some elements; jsdom has no layout to measure.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal("ResizeObserver", NoopResizeObserver);

export function testQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

/** Renders `ui` with the providers every page expects. */
export function renderWithProviders(
  ui: ReactNode,
  { client = testQueryClient(), path = "/" }: { client?: QueryClient; path?: string } = {},
): RenderResult & { client: QueryClient } {
  // A wrapper rather than inline providers, so `rerender` keeps them.
  const wrapper = ({ children }: { children: ReactNode }) => (
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <TooltipProvider>
          <MemoryRouter initialEntries={[path]}>{children}</MemoryRouter>
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
  return Object.assign(render(ui, { wrapper }), { client });
}

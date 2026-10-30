import { useQuery } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { fetchBlob, mockMode } from "@/api/client";
import { safeLogoUrl } from "@/lib/safe-url";
import { cn } from "@/lib/utils";

/**
 * The browser loads a logo straight from its URL, sending the session cookie. Mock mode has no
 * server to answer that, so the image is fetched through the mock and shown from a blob URL.
 */
function useLogoSrc(raw: string | null | undefined): string | undefined {
  const url = safeLogoUrl(raw);
  const mocked = useQuery({
    queryKey: ["logo", url],
    queryFn: async () => URL.createObjectURL(await fetchBlob(url ?? "")),
    enabled: mockMode && !!url,
    staleTime: Infinity,
  });
  if (!url) return undefined;
  return mockMode ? mocked.data : url;
}

interface ProjectLogoProps {
  url: string | null | undefined;
  /** Shown when there is no logo or it fails to load. */
  fallback: ReactNode;
  className?: string;
  testId?: string;
}

export function ProjectLogo({ url, fallback, className, testId = "project-logo" }: ProjectLogoProps) {
  const src = useLogoSrc(url);
  const [failed, setFailed] = useState<string>();
  if (!src || failed === src) return <>{fallback}</>;
  return (
    <img
      key={src}
      src={src}
      alt=""
      crossOrigin={mockMode ? undefined : "use-credentials"}
      className={cn("shrink-0 object-contain", className)}
      onError={() => setFailed(src)}
      data-testid={testId}
    />
  );
}

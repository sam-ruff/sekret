import type { QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import { forgetAllButStatus } from "@/hooks/queries";
import { clearBeforeLeaving, type ClearOutcome } from "./clipboard";
import { errorMessage } from "./errors";
import { beginLeaving, browserNavigation, isLeaving, stopLeaving } from "./leaving";
import { safeHttpUrl } from "./safe-url";
import { broadcast } from "./tab-sync";

export interface SignOutDeps {
  logout: () => Promise<{ logout_url?: string | null }>;
  assign: (url: string) => void;
  clearClipboard?: () => Promise<ClearOutcome | null>;
}

const defaultDeps: SignOutDeps = {
  logout: api.logout,
  assign: (url) => browserNavigation.assign(url),
};

/**
 * Ends the session, following the identity provider's logout URL when the server returns one.
 * Nothing else may navigate away meanwhile, or the provider's session would outlive this one.
 * Cached data and a copied secret go first, here and in every other open tab.
 */
export async function signOut(queryClient: QueryClient, deps: SignOutDeps = defaultDeps): Promise<void> {
  if (isLeaving()) return;
  beginLeaving();
  void queryClient.cancelQueries();
  let target = "/login";
  try {
    const { logout_url } = await deps.logout();
    target = safeHttpUrl(logout_url) ?? "/login";
  } catch (error) {
    // A session that has already ended counts as signed out.
    if (!(error instanceof ApiError && error.status === 401)) {
      stopLeaving();
      toast.error(errorMessage(error));
      return;
    }
  }
  forgetAllButStatus(queryClient);
  await clearBeforeLeaving(deps.clearClipboard);
  broadcast("signed-out");
  deps.assign(target);
}

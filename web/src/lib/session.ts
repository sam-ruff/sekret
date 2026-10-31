import type { QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api } from "@/api/endpoints";
import { forgetAllButStatus } from "@/hooks/queries";
import { errorMessage } from "./errors";
import { safeHttpUrl } from "./safe-url";
import { broadcast } from "./tab-sync";

/**
 * Ends the session, following the identity provider's logout URL when the server returns one.
 * Cached data goes first, here and in every other open tab.
 */
export async function signOut(queryClient: QueryClient): Promise<void> {
  try {
    const { logout_url } = await api.logout();
    forgetAllButStatus(queryClient);
    broadcast("signed-out");
    window.location.assign(safeHttpUrl(logout_url) ?? "/login");
  } catch (error) {
    toast.error(errorMessage(error));
  }
}

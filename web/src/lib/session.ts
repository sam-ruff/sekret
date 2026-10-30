import { toast } from "sonner";
import { api } from "@/api/endpoints";
import { errorMessage } from "./errors";
import { safeHttpUrl } from "./safe-url";

/** Ends the session, following the identity provider's logout URL when the server returns one. */
export async function signOut(): Promise<void> {
  try {
    const { logout_url } = await api.logout();
    window.location.assign(safeHttpUrl(logout_url) ?? "/login");
  } catch (error) {
    toast.error(errorMessage(error));
  }
}

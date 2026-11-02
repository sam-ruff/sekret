import {
  keepPreviousData,
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
  type Query,
  type QueryClient,
  type QueryKey,
  type UseQueryOptions,
  type UseQueryResult,
} from "@tanstack/react-query";
import { useEffect } from "react";
import { toast } from "sonner";
import { isSealError } from "@/api/client";
import { api, type IdentityQuery, type UserQuery } from "@/api/endpoints";
import { errorMessage } from "@/lib/errors";

export const keys = {
  sysStatus: ["sys-status"] as const,
  /** Kept apart from `sysStatus` so it is dropped with everything else when the server locks. */
  sysStatusDetail: ["sys-status-detail"] as const,
  authConfig: ["auth-config"] as const,
  me: ["me"] as const,
  projects: ["projects"] as const,
  project: (p: string) => ["project", p] as const,
  permissions: (p: string) => ["project", p, "permissions"] as const,
  environments: (p: string) => ["project", p, "environments"] as const,
  secrets: (p: string, env: string, path: string) => ["project", p, "secrets", env, path] as const,
  secretValues: (p: string, env: string, path: string) => ["project", p, "secret-values", env, path] as const,
  /** One value; shares the prefix of `secretValues` so refreshing a folder's values refreshes these too. */
  secretValue: (p: string, env: string, path: string, key: string) =>
    ["project", p, "secret-values", env, path, "key", key] as const,
  versions: (p: string, env: string, path: string, key: string) => ["project", p, "versions", env, path, key] as const,
  overview: (p: string, path: string) => ["project", p, "overview", path] as const,
  snapshots: (p: string, env: string) => ["project", p, "snapshots", env] as const,
  snapshot: (p: string, env: string, id: string, path: string) => ["project", p, "snapshot", env, id, path] as const,
  members: (p: string) => ["project", p, "members"] as const,
  roles: (p: string) => ["project", p, "roles"] as const,
  projectAudit: (p: string) => ["project", p, "audit"] as const,
  projectPolicy: (p: string) => ["project", p, "secret-policy"] as const,
  secretPolicy: (p: string, env: string, path: string, key: string) => ["project", p, "policy", env, path, key] as const,
  secretAccess: (p: string, env: string, path: string, key: string) => ["project", p, "access", env, path, key] as const,
  secretAccessSetting: (p: string) => ["project", p, "secret-access"] as const,
  /** Prefix for every page and search of users. */
  users: ["users"] as const,
  userPage: (query: UserQuery) => ["users", query] as const,
  identities: ["identities"] as const,
  identityPage: (query: IdentityQuery) => ["identities", query] as const,
  identity: (id: string) => ["identity", id] as const,
  authMethods: (id: string) => ["identity", id, "auth"] as const,
  clientSecrets: (id: string) => ["identity", id, "client-secrets"] as const,
  orgBindings: ["org", "bindings"] as const,
  orgRoles: ["org", "roles"] as const,
  orgAudit: ["org", "audit"] as const,
};

/** The gate keeps the status until a request finds the server sealed; `fresh` refetches it on mount. */
export function useSysStatus(fresh = false) {
  return useQuery({ queryKey: keys.sysStatus, queryFn: api.sysStatus, staleTime: fresh ? 0 : Infinity });
}

/** Revealed values and history leave the cache as soon as nothing shows them. */
export const SECRET_VALUE_GC_TIME = 0;

/**
 * A query that exists only while `options` is set. A disabled `useQuery` still observes its
 * query and keeps its data, so values hidden again would stay in memory; with no observer at
 * all, a zero `gcTime` drops them at once and the next reveal asks the server again.
 */
export function useOptionalQuery<T>(options: UseQueryOptions<T, Error, T, QueryKey> | null): UseQueryResult<T> | undefined {
  const queries: UseQueryOptions<T, Error, T, QueryKey>[] = options ? [options] : [];
  const [result] = useQueries({ queries });
  return options ? (result as UseQueryResult<T> | undefined) : undefined;
}

/**
 * Drops everything cached but the server status, so no secret outlives a sealed server. Mutations
 * go too, since their variables and results can hold passphrases, values or client secrets.
 */
export function forgetAllButStatus(queryClient: QueryClient): void {
  const predicate = (query: Query) => query.queryKey[0] !== keys.sysStatus[0];
  void queryClient.cancelQueries({ predicate });
  queryClient.removeQueries({ predicate });
  queryClient.getMutationCache().clear();
}

export const SEAL_WATCH_INTERVAL_MS = 15_000;

/**
 * While `active`, checks every so often and when the tab comes back whether the server is still
 * unlocked and the session still alive, so values on screen go when either ends.
 */
export function useSealWatch(active: boolean, intervalMs = SEAL_WATCH_INTERVAL_MS): void {
  const queryClient = useQueryClient();
  useEffect(() => {
    if (!active) return;
    const check = () => {
      void queryClient.invalidateQueries({ queryKey: keys.sysStatus });
      void queryClient.invalidateQueries({ queryKey: keys.me });
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") check();
    };
    document.addEventListener("visibilitychange", onVisibility);
    const timer = window.setInterval(check, intervalMs);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      window.clearInterval(timer);
    };
  }, [active, intervalMs, queryClient]);
}

export function useMe() {
  return useQuery({ queryKey: keys.me, queryFn: api.me, staleTime: 60_000 });
}

export function useAuthConfig() {
  return useQuery({ queryKey: keys.authConfig, queryFn: api.authConfig, staleTime: Infinity });
}

export function useProjects() {
  return useQuery({ queryKey: keys.projects, queryFn: api.projects });
}

export function useProject(project: string, enabled = true) {
  return useQuery({ queryKey: keys.project(project), queryFn: () => api.project(project), enabled });
}

export function useEnvironments(project: string) {
  return useQuery({
    queryKey: keys.environments(project),
    queryFn: async () => {
      const envs = await api.environments(project);
      return [...envs].sort((a, b) => a.position - b.position || a.slug.localeCompare(b.slug));
    },
  });
}

export function useRoles(project: string, enabled = true) {
  return useQuery({ queryKey: keys.roles(project), queryFn: () => api.roles(project), enabled });
}

export function useOrgRoles(enabled = true) {
  return useQuery({ queryKey: keys.orgRoles, queryFn: api.orgRoles, enabled });
}

/** One page of users; the previous page stays on screen while the next loads. */
export function useUserPage(query: UserQuery, enabled = true) {
  return useQuery({
    queryKey: keys.userPage(query),
    queryFn: () => api.users(query),
    enabled,
    placeholderData: keepPreviousData,
  });
}

export function useIdentityPage(query: IdentityQuery, enabled = true) {
  return useQuery({
    queryKey: keys.identityPage(query),
    queryFn: () => api.identities(query),
    enabled,
    placeholderData: keepPreviousData,
  });
}

interface MutationOptions<TVars, TResult> {
  mutationFn: (vars: TVars) => Promise<TResult>;
  /** Query keys (prefixes) to refresh after success. */
  invalidate?: QueryKey[];
  success?: string | ((result: TResult, vars: TVars) => string | undefined);
  onSuccess?: (result: TResult, vars: TVars) => void;
  /** Return true to say the error was handled and needs no toast. */
  onError?: (error: unknown) => boolean | void;
  /** How long the finished mutation, with its variables and result, stays cached once unused. */
  gcTime?: number;
}

/** A mutation that refreshes affected queries, toasts the outcome and surfaces server messages. */
export function useApiMutation<TVars = void, TResult = unknown>(options: MutationOptions<TVars, TResult>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: options.mutationFn,
    ...(options.gcTime !== undefined && { gcTime: options.gcTime }),
    onSuccess: async (result, vars) => {
      await Promise.all((options.invalidate ?? []).map((queryKey) => queryClient.invalidateQueries({ queryKey })));
      const message = typeof options.success === "function" ? options.success(result, vars) : options.success;
      if (message) toast.success(message);
      options.onSuccess?.(result, vars);
    },
    onError: (error) => {
      if (options.onError?.(error)) return;
      // The status gate takes over and moves to the setup or unlock page.
      if (isSealError(error)) return;
      toast.error(errorMessage(error));
    },
  });
}

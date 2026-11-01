import { useParams, useSearchParams } from "react-router";
import { useEnvironments } from "./queries";
import { folderFromLink } from "@/lib/paths";

/** The project from the URL, its environments, the selected one (defaulting to the first) and the folder path. */
export function useProjectEnv() {
  const { project = "", env: envParam } = useParams();
  const [search] = useSearchParams();
  const path = folderFromLink(search.get("path"));
  const environments = useEnvironments(project);
  const envs = environments.data ?? [];
  const env = envs.find((e) => e.slug === envParam) ?? (envParam ? undefined : envs[0]);
  return { project, envParam, env, envs, path, environments };
}

export function folderQuery(path: string): string {
  return path === "/" ? "" : `?path=${encodeURIComponent(path)}`;
}

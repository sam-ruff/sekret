import type { SecretVersion } from "@/api/types";

/** Whether two versions hold the same visible value and tags, so rolling one back to the other changes nothing. */
export function sameContent(a: SecretVersion, b: SecretVersion | undefined): boolean {
  if (!b || a.value_hidden || b.value_hidden || a.deleted || b.deleted) return false;
  if (a.value == null || a.value !== b.value) return false;
  return [...a.tags].sort().join("\n") === [...b.tags].sort().join("\n");
}

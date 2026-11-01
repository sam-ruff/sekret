export interface EnvironmentDeleteText {
  /** It still holds secrets the reader can see, which the server would refuse to delete. */
  blocked: boolean;
  text: string;
}

/** What the delete dialog says, from the secrets the reader can see in the environment. */
export function environmentDeleteText(count: number | undefined, failed: boolean): EnvironmentDeleteText {
  const loss = "The history of every secret that was in it and all of its snapshots are deleted for good. This cannot be undone.";
  if (failed) return { blocked: false, text: `sekret could not check what is in it. Only an empty environment can be deleted. ${loss}` };
  if (count === undefined) return { blocked: false, text: "Checking what is in it..." };
  if (count === 0) return { blocked: false, text: `It holds no secrets you can see. ${loss}` };
  const secrets = count === 1 ? "1 secret" : `${count} secrets`;
  return {
    blocked: true,
    text: `It still holds ${secrets}, counting its folders. Only an empty environment can be deleted, so delete or move them first.`,
  };
}

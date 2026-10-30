// Shared by the hostile mock seed and the XSS spec, so this module must not import anything.

export const HOSTILE_SEED_FLAG = "sekret-mock-seed";
export const HOSTILE_SEED = "hostile";

/** Each sets `window.__xss` if it is ever parsed as markup or followed as a URL. */
export const HOSTILE = {
  img: `<img src=x onerror="window.__xss=1">`,
  script: "<script>window.__xss=1</script>",
  js: "javascript:window.__xss=1",
  svg: `"><svg onload=window.__xss=1>`,
} as const;

export const HOSTILE_PROJECT = "hostile";
export const HOSTILE_SECRET = "HOSTILE_VALUE";

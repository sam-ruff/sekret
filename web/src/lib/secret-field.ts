/**
 * Keeps browsers and writing assistants from reading or rewriting a secret: no spellcheck (which can
 * send the text to a cloud service), no autocorrect or capitalisation, and Grammarly told to stay out.
 */
export const SECRET_FIELD_ATTRIBUTES = {
  spellCheck: false,
  autoComplete: "off",
  autoCorrect: "off",
  autoCapitalize: "off",
  "data-gramm": "false",
  "data-gramm_editor": "false",
  "data-enable-grammarly": "false",
} as const;

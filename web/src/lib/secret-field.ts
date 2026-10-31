/** Tells 1Password, LastPass, Bitwarden and Dashlane not to offer, fill or save the field. */
export const PASSWORD_MANAGER_IGNORE = {
  "data-1p-ignore": "true",
  "data-lpignore": "true",
  "data-bwignore": "true",
  "data-form-type": "other",
} as const;

/**
 * For a secret a password manager should keep, such as the server passphrase: no spellcheck (which
 * can send the text to a cloud service), no autocorrect or capitalisation, and Grammarly told to stay out.
 */
export const PASSPHRASE_FIELD_ATTRIBUTES = {
  spellCheck: false,
  autoComplete: "off",
  autoCorrect: "off",
  autoCapitalize: "off",
  "data-gramm": "false",
  "data-gramm_editor": "false",
  "data-enable-grammarly": "false",
} as const;

/** For any other secret, which password managers are also told to leave alone. */
export const SECRET_FIELD_ATTRIBUTES = {
  ...PASSPHRASE_FIELD_ATTRIBUTES,
  ...PASSWORD_MANAGER_IGNORE,
} as const;

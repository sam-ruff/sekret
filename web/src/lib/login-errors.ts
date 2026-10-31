/** What the server's `?error=` codes on the login page mean. The page never shows the parameter itself. */
const LOGIN_ERRORS: Record<string, string> = {
  provider_refused: "The identity provider refused the sign-in.",
  incomplete_response: "The sign-in response was incomplete. Please try again.",
  other_browser: "The sign-in was started in another browser. Please try again.",
  expired: "The sign-in attempt expired. Please try again.",
  reauth_not_performed: "The identity provider did not ask you to sign in again. Please try again.",
  not_allowed: "Your account is not allowed to use sekret.",
  account_disabled: "Your sekret account has been disabled.",
};

export const GENERIC_LOGIN_ERROR = "Signing in did not work. Please try again.";

/** Fixed text for a login error code, or null when there was no error. */
export function loginErrorText(code: string | null): string | null {
  if (code === null) return null;
  return Object.hasOwn(LOGIN_ERRORS, code) ? LOGIN_ERRORS[code] : GENERIC_LOGIN_ERROR;
}

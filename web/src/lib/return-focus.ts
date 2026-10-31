/**
 * For `onCloseAutoFocus` on a dialog opened from a menu item, which no longer exists when the
 * dialog closes. Focus goes to `element` instead of falling back to the page body.
 */
export function focusInstead(event: Event, element: HTMLElement | null | undefined): void {
  if (!element?.isConnected) return;
  event.preventDefault();
  element.focus();
}

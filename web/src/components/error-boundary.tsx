import { AlertCircle, RotateCw } from "lucide-react";
import { Component, type ErrorInfo, type ReactNode } from "react";
import { StandaloneHeader, StandalonePage } from "@/components/sys/standalone-page";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Runs once when something below throws, for example to drop cached secrets. */
  onError?: () => void;
  /** Reloads the page; replaced in tests. */
  reload?: () => void;
  /**
   * `app` replaces the whole interface; `section` replaces only what it wraps, so navigation
   * and the rest of the page keep working.
   */
  variant?: "app" | "section";
  /** A section boundary starts afresh whenever this changes, such as on navigation. */
  resetKey?: unknown;
}

interface ErrorBoundaryState {
  failed: boolean;
  failedAt: unknown;
}

/** Shows a plain message when rendering fails, rather than a blank page. */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { failed: false, failedAt: undefined };

  static getDerivedStateFromError(): Partial<ErrorBoundaryState> {
    return { failed: true };
  }

  static getDerivedStateFromProps(props: ErrorBoundaryProps, state: ErrorBoundaryState): Partial<ErrorBoundaryState> | null {
    if (!state.failed) return { failedAt: props.resetKey };
    if (!Object.is(state.failedAt, props.resetKey)) return { failed: false, failedAt: props.resetKey };
    return null;
  }

  componentDidCatch(error: unknown, info: ErrorInfo): void {
    this.props.onError?.();
    console.error(error, info.componentStack);
  }

  render() {
    if (!this.state.failed) return this.props.children;
    if (this.props.variant === "section") {
      return (
        <Alert variant="destructive" data-testid="section-error">
          <AlertCircle />
          <AlertTitle>This part of the page stopped working</AlertTitle>
          <AlertDescription>
            <p>Something here could not be shown. The rest of sekret still works.</p>
            <Button
              variant="outline"
              size="sm"
              className="mt-2"
              onClick={() => this.setState({ failed: false })}
              data-testid="section-error-retry"
            >
              <RotateCw />
              Try again
            </Button>
          </AlertDescription>
        </Alert>
      );
    }
    const reload = this.props.reload ?? (() => window.location.reload());
    return (
      <StandalonePage>
        <Card data-testid="app-error">
          <StandaloneHeader
            title="Something went wrong"
            pageTitle="Error"
            icon={<AlertCircle />}
            description="This page stopped working. Reloading usually fixes it."
          />
          <CardContent>
            <Button onClick={reload} className="w-full" data-testid="app-error-reload">
              <RotateCw />
              Reload
            </Button>
          </CardContent>
        </Card>
      </StandalonePage>
    );
  }
}

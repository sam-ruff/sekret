import { AlertCircle, RotateCw } from "lucide-react";
import { Component, type ErrorInfo, type ReactNode } from "react";
import { StandaloneHeader, StandalonePage } from "@/components/sys/standalone-page";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Runs once when something below throws, for example to drop cached secrets. */
  onError?: () => void;
  /** Reloads the page; replaced in tests. */
  reload?: () => void;
}

interface ErrorBoundaryState {
  failed: boolean;
}

/** Replaces the whole interface with a plain message when rendering fails, rather than a blank page. */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true };
  }

  componentDidCatch(error: unknown, info: ErrorInfo): void {
    this.props.onError?.();
    console.error(error, info.componentStack);
  }

  render() {
    if (!this.state.failed) return this.props.children;
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

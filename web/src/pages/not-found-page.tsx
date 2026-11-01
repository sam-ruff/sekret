import { Compass } from "lucide-react";
import { Link } from "react-router";
import { EmptyState } from "@/components/states";
import { Button } from "@/components/ui/button";
import { usePageTitle } from "@/hooks/use-page-title";

export function NotFoundPage() {
  usePageTitle("Not found");
  return (
    <EmptyState
      icon={<Compass />}
      title="Nothing lives here"
      headingLevel={1}
      description="This page does not exist, or it moved somewhere more secret."
      action={
        <Button asChild>
          <Link to="/projects">Back to projects</Link>
        </Button>
      }
      testId="not-found"
    />
  );
}

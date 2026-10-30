import { Compass } from "lucide-react";
import { Link } from "react-router";
import { EmptyState } from "@/components/states";
import { Button } from "@/components/ui/button";

export function NotFoundPage() {
  return (
    <EmptyState
      icon={<Compass />}
      title="Nothing lives here"
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

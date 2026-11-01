import { Folder } from "lucide-react";
import { Fragment } from "react";
import { Link } from "react-router";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { crumbs } from "@/lib/paths";

export function FolderBreadcrumbs({ path, hrefFor }: { path: string; hrefFor: (path: string) => string }) {
  const trail = crumbs(path);
  return (
    <Breadcrumb data-testid="folder-breadcrumbs">
      <BreadcrumbList className="font-mono text-sm">
        {trail.map((crumb, index) => {
          const last = index === trail.length - 1;
          return (
            <Fragment key={crumb.path}>
              {index > 0 && <BreadcrumbSeparator />}
              <BreadcrumbItem>
                {last ? (
                  <BreadcrumbPage className="flex items-center gap-1.5" data-testid="current-folder">
                    {index === 0 && <Folder className="size-3.5" />}
                    {crumb.name}
                  </BreadcrumbPage>
                ) : (
                  <BreadcrumbLink asChild>
                    <Link to={hrefFor(crumb.path)} className="flex items-center gap-1.5" data-testid={index === 0 ? "crumb-root" : `crumb-${crumb.name}`}>
                      {index === 0 && <Folder className="size-3.5" />}
                      {crumb.name}
                    </Link>
                  </BreadcrumbLink>
                )}
              </BreadcrumbItem>
            </Fragment>
          );
        })}
      </BreadcrumbList>
    </Breadcrumb>
  );
}

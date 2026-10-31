import { useQueryClient } from "@tanstack/react-query";
import { LogOut, Monitor, Moon, Sun } from "lucide-react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { useMe } from "@/hooks/queries";
import { initials } from "@/lib/format";
import { signOut } from "@/lib/session";
import { useTheme, type Theme } from "@/lib/theme";

export function ThemeToggle() {
  const { resolved, setTheme } = useTheme();
  const next = resolved === "dark" ? "light" : "dark";
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setTheme(next)}
      aria-label={`Switch to ${next} mode`}
      data-testid="theme-toggle"
    >
      {resolved === "dark" ? <Sun /> : <Moon />}
    </Button>
  );
}

export function UserMenu() {
  const { data: me, isPending } = useMe();
  const { theme, setTheme } = useTheme();
  const queryClient = useQueryClient();

  if (isPending) return <Skeleton className="size-8 rounded-full" />;
  const label = me?.name || me?.email || "Signed in";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="rounded-full" aria-label="Account" data-testid="user-menu">
          <Avatar className="size-8">
            <AvatarFallback className="bg-primary/15 text-xs font-semibold text-primary">{initials(label)}</AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-60">
        <DropdownMenuLabel className="font-normal">
          <div className="truncate text-sm font-medium">{label}</div>
          {me?.email && <div className="truncate text-xs text-muted-foreground">{me.email}</div>}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuLabel className="text-xs text-muted-foreground">Appearance</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={theme} onValueChange={(v) => setTheme(v as Theme)}>
          <DropdownMenuRadioItem value="light">
            <Sun /> Light
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark">
            <Moon /> Dark
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="system">
            <Monitor /> System
          </DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => void signOut(queryClient)} data-testid="logout">
          <LogOut />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

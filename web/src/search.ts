// What the search window (Cmd+K) finds in Audit: projects by name, and open advisories by advisory, alias or package, from the API.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { FolderGit2, ShieldAlert } from "lucide-react";
import type { Finding, Project } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [list, found] = await Promise.all([
      call<{ projects: Project[] }>("/api/v1/projects?limit=500", { signal }),
      call<{ findings: Finding[] }>(`/api/v1/findings?${new URLSearchParams({ q, limit: "8" })}`, { signal }),
    ]);
    const named: SearchResult[] = list.projects
      .filter((e) => e.name.toLowerCase().includes(q))
      .slice(0, 6)
      .map((e) => ({
        id: `project:${e.id}`,
        label: e.name,
        detail: t("search.open", { open: Object.values(e.open).reduce((n, c) => n + c, 0) }),
        kind: t("search.project"),
        icon: FolderGit2,
        mono: true,
        href: `/projects/${encodeURIComponent(e.id)}`,
      }));
    const findings: SearchResult[] = found.findings.map((f) => ({
      id: `advisory:${f.project.id}:${f.fingerprint}`,
      label: f.advisory,
      detail: `${f.package} ${f.version} · ${f.project.name}`,
      kind: t("search.advisory"),
      icon: ShieldAlert,
      severity: f.severity,
      mono: true,
      href: `/projects/${encodeURIComponent(f.project.id)}`,
    }));
    return [...named, ...findings];
  };
}

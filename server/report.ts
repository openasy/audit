import { createHash } from "node:crypto";

export type Severity = "critical" | "high" | "medium" | "low";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export interface Advisory {
  /** Stable across branches: the ecosystem, the package, its version and the advisory. */
  fingerprint: string;
  ecosystem: string;
  package: string;
  version: string;
  /** The advisory's own id, such as GHSA-xxxx or CVE-2024-0001. */
  advisory: string;
  aliases: string[];
  severity: Severity;
  summary: string;
  fixedVersion: string | null;
  /** The lockfile or manifest it was found in. */
  path: string;
}

export interface Inventory {
  ecosystem: string;
  name: string;
  version: string;
  path: string;
}

export class ReportError extends Error {}

/** Most advisories one report may hold. */
export const MAX_FINDINGS = 50_000;

type Obj = Record<string, any>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v: unknown, max: number) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);

// ---------------------------------------------------------------------------------------------- severity

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

const roundUp = (n: number) => {
  const i = Math.round(n * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
};

/** The base score of a CVSS v3.0 or v3.1 vector, or null when it is not one. */
export function cvss3Base(vector: string): number | null {
  const m = /^CVSS:3\.[01]\/(.+)$/.exec(vector.trim());
  if (!m) return null;
  const v = Object.fromEntries(m[1]!.split("/").map((p) => p.split(":") as [string, string]));
  const av = WEIGHTS.AV[v.AV as keyof typeof WEIGHTS.AV];
  const ac = WEIGHTS.AC[v.AC as keyof typeof WEIGHTS.AC];
  const ui = WEIGHTS.UI[v.UI as keyof typeof WEIGHTS.UI];
  const c = WEIGHTS.CIA[v.C as keyof typeof WEIGHTS.CIA];
  const i = WEIGHTS.CIA[v.I as keyof typeof WEIGHTS.CIA];
  const a = WEIGHTS.CIA[v.A as keyof typeof WEIGHTS.CIA];
  const changed = v.S === "C";
  const pr = ({ N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 } as Record<string, number>)[v.PR ?? ""];
  if ([av, ac, ui, c, i, a, pr].some((x) => x === undefined) || (v.S !== "C" && v.S !== "U")) return null;
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  return roundUp(Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10));
}

export const fromScore = (n: number): Severity | null => (n >= 9 ? "critical" : n >= 7 ? "high" : n >= 4 ? "medium" : n > 0 ? "low" : null);

const LABELS: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

/** CVSS v3 first, then the database's own label, then medium: an advisory nobody rated is not ignored. */
function severityOf(vuln: Obj): Severity {
  for (const s of Array.isArray(vuln.severity) ? vuln.severity : []) {
    if (!isObj(s) || typeof s.score !== "string") continue;
    const score = /^\d+(\.\d+)?$/.test(s.score) ? Number(s.score) : cvss3Base(s.score);
    const found = score === null ? null : fromScore(score);
    if (found) return found;
  }
  const label = isObj(vuln.database_specific) && typeof vuln.database_specific.severity === "string" ? vuln.database_specific.severity.toUpperCase() : "";
  return LABELS[label] ?? "medium";
}

// ---------------------------------------------------------------------------------------------- ecosystems

const LOCKFILES: Array<[RegExp, string]> = [
  [/(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|package\.json)$/, "npm"],
  [/(^|\/)(requirements[^/]*\.txt|poetry\.lock|Pipfile\.lock|pdm\.lock|uv\.lock)$/, "PyPI"],
  [/(^|\/)(go\.mod|go\.sum)$/, "Go"],
  [/(^|\/)(Cargo\.lock|Cargo\.toml)$/, "crates.io"],
  [/(^|\/)(composer\.lock|composer\.json)$/, "Packagist"],
];

/** OSV writes `Go`, `npm`, `PyPI`, `crates.io`, `Packagist`, sometimes with a release suffix (`Debian:12`). */
export function ecosystemOf(value: unknown, path = ""): string {
  const e = text(value, 64);
  if (e) return e.split(":")[0]!;
  return LOCKFILES.find(([re]) => re.test(path))?.[1] ?? "unknown";
}

/** A path as the project knows it: no file:// prefix, no ./, no backslashes. */
export function normalizePath(uri: string): string {
  let path = uri;
  try {
    path = decodeURIComponent(uri);
  } catch {
    // keep it as sent
  }
  return path
    .replace(/^file:\/\/\/?/, "")
    .replace(/^(\.\/)+/, "")
    .replace(/\\/g, "/")
    .slice(0, 1024);
}

// ---------------------------------------------------------------------------------------------- readers

function fixedFor(vuln: Obj, ecosystem: string, name: string): string | null {
  for (const a of Array.isArray(vuln.affected) ? vuln.affected : []) {
    if (!isObj(a) || !isObj(a.package) || a.package.name !== name || ecosystemOf(a.package.ecosystem) !== ecosystem) continue;
    for (const range of Array.isArray(a.ranges) ? a.ranges : []) {
      for (const event of isObj(range) && Array.isArray(range.events) ? range.events : []) {
        const fixed = isObj(event) ? text(event.fixed, 128) : null;
        if (fixed) return fixed;
      }
    }
  }
  return null;
}

type Found = Omit<Advisory, "fingerprint">;

/** `osv-scanner --format json`. */
function readOsv(body: Obj): { tool: string; found: Found[]; packages: Inventory[] } {
  const found: Found[] = [];
  const packages: Inventory[] = [];
  for (const result of Array.isArray(body.results) ? body.results : []) {
    if (!isObj(result)) continue;
    const path = normalizePath(text(isObj(result.source) ? result.source.path : undefined, 2048) ?? "unknown");
    for (const entry of Array.isArray(result.packages) ? result.packages : []) {
      if (!isObj(entry) || !isObj(entry.package)) continue;
      const name = text(entry.package.name, 256);
      const version = text(entry.package.version, 128) ?? "unknown";
      if (!name) continue;
      const ecosystem = ecosystemOf(entry.package.ecosystem, path);
      packages.push({ ecosystem, name, version, path });
      for (const vuln of Array.isArray(entry.vulnerabilities) ? entry.vulnerabilities : []) {
        if (!isObj(vuln)) continue;
        const advisory = text(vuln.id, 128);
        if (!advisory) continue;
        if (found.length >= MAX_FINDINGS) throw new ReportError(`A report may hold at most ${MAX_FINDINGS} advisories.`);
        found.push({
          ecosystem,
          package: name,
          version,
          advisory,
          aliases: (Array.isArray(vuln.aliases) ? vuln.aliases : []).filter((a): a is string => typeof a === "string").slice(0, 20),
          severity: severityOf(vuln),
          summary: text(vuln.summary, 300) ?? text(vuln.details, 300) ?? advisory,
          fixedVersion: fixedFor(vuln, ecosystem, name),
          path,
        });
      }
    }
  }
  return { tool: "osv-scanner", found, packages };
}

/**
 * SARIF 2.1.0 from scanners that report advisories (Trivy, Grype, osv-scanner --format sarif). The rule is the
 * advisory; the package comes from the result's properties, or from the "Package: x" and "Installed Version: y" lines
 * of the message that Trivy writes. A result without a package is left out: it cannot be followed between scans.
 */
function readSarif(body: Obj): { tool: string; found: Found[]; packages: Inventory[] } {
  if (typeof body.version === "string" && !body.version.startsWith("2.1")) throw new ReportError(`SARIF ${body.version} is not supported; send version 2.1.0.`);
  const tools: string[] = [];
  const found: Found[] = [];
  for (const run of body.runs as unknown[]) {
    if (!isObj(run)) continue;
    const driver = isObj(run.tool) && isObj(run.tool.driver) ? run.tool.driver : {};
    const tool = text(driver.name, 64);
    if (tool && !tools.includes(tool)) tools.push(tool);
    const rules = new Map<string, Obj>();
    if (Array.isArray(driver.rules)) for (const r of driver.rules) if (isObj(r) && typeof r.id === "string") rules.set(r.id, r);
    for (const result of Array.isArray(run.results) ? run.results : []) {
      if (!isObj(result) || (Array.isArray(result.suppressions) && result.suppressions.length > 0)) continue;
      const advisory = text(result.ruleId ?? (isObj(result.rule) ? result.rule.id : undefined), 128);
      const props = isObj(result.properties) ? result.properties : {};
      const message = text(isObj(result.message) ? (result.message.text ?? result.message.markdown) : undefined, 2000) ?? "";
      const name = text(props.package ?? props.packageName ?? /Package:\s*(\S+)/.exec(message)?.[1], 256);
      if (!advisory || !name) continue;
      if (found.length >= MAX_FINDINGS) throw new ReportError(`A report may hold at most ${MAX_FINDINGS} advisories.`);
      const rule = rules.get(advisory);
      const location =
        Array.isArray(result.locations) && isObj(result.locations[0]) && isObj(result.locations[0].physicalLocation)
          ? result.locations[0].physicalLocation
          : {};
      const path = normalizePath(text(isObj(location.artifactLocation) ? location.artifactLocation.uri : undefined, 2048) ?? "unknown");
      const rated = fromScore(Number(props["security-severity"] ?? (isObj(rule?.properties) ? rule!.properties["security-severity"] : NaN)));
      found.push({
        ecosystem: ecosystemOf(props.ecosystem, path),
        package: name,
        version: text(props.version ?? props.installedVersion ?? /Installed Version:\s*(\S+)/.exec(message)?.[1], 128) ?? "unknown",
        advisory,
        aliases: [],
        severity: rated ?? (result.level === "error" ? "high" : result.level === "note" ? "low" : "medium"),
        summary: text(isObj(rule?.shortDescription) ? rule!.shortDescription.text : undefined, 300) ?? message.split("\n")[0]!.slice(0, 300) ?? advisory,
        fixedVersion: text(props.fixedVersion ?? /Fixed Version:\s*(\S+)/.exec(message)?.[1], 128),
        path,
      });
    }
  }
  return { tool: tools.join(", ") || "unknown", found, packages: [] };
}

/** Reads the advisories of an osv-scanner JSON report or a SARIF 2.1.0 log. Each advisory in each package version once. */
export function parseReport(body: unknown): { tool: string; findings: Advisory[]; packages: Inventory[] } {
  if (!isObj(body)) throw new ReportError("Send the JSON of `osv-scanner --format json`, or a SARIF 2.1.0 log.");
  let read: ReturnType<typeof readOsv>;
  if (Array.isArray(body.results)) read = readOsv(body);
  else if (Array.isArray(body.runs)) read = readSarif(body);
  else throw new ReportError("Send the JSON of `osv-scanner --format json` (a results array), or a SARIF 2.1.0 log (a runs array).");
  const seen = new Set<string>();
  const findings: Advisory[] = [];
  for (const f of read.found) {
    const fingerprint = createHash("sha256").update(`${f.ecosystem}\n${f.package}\n${f.version}\n${f.advisory}`).digest("hex").slice(0, 32);
    if (seen.has(fingerprint)) continue; // the same package in two lockfiles is one finding
    seen.add(fingerprint);
    findings.push({ ...f, fingerprint });
  }
  const unique = new Map(read.packages.map((p) => [`${p.ecosystem}\n${p.name}\n${p.version}\n${p.path}`, p]));
  return { tool: read.tool, findings, packages: [...unique.values()] };
}

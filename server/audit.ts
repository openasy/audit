import { randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { parseReport, ReportError, SEVERITIES, type Advisory, type Severity } from "./report.ts";

export type ProblemCode =
  | "invalid-token"
  | "invalid-json"
  | "invalid-body"
  | "invalid-report"
  | "not-found"
  | "not-configured"
  | "payload-too-large"
  | "internal-error";

export class AuditError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export type FailOn = Severity | "none";
export type Triage = "open" | "false-positive" | "accepted" | "not-affected";
export type Status = "open" | "suppressed" | "resolved";

const FAIL_ON: FailOn[] = [...SEVERITIES, "none"];
const TRIAGE: Triage[] = ["open", "false-positive", "accepted", "not-affected"];
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const RANK_SQL = `CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END`;

// owner/name, as the forge writes it, or a plain name.
const PROJECT_NAME = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const BRANCH = /^[^\s\x00-\x1f]{1,255}$/;
const MAX_ACCEPT_DAYS = 366;
/** Advisories in the answer to a scan, for CI logs. The rest are on the scan's page. */
const SCAN_FINDINGS_IN_ANSWER = 100;

const now = () => new Date().toISOString();
const bad = (detail: string) => new AuditError(422, "invalid-body", detail);
const notFound = (what: string) => new AuditError(404, "not-found", `${what} does not exist.`);

export interface Page<T> {
  items: T[];
  /** Opaque; pass it back as `cursor` for the next page. Absent on the last page (ADR 0024). */
  nextCursor?: string;
}

const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const o = (JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown }).o;
    if (typeof o === "number" && Number.isSafeInteger(o) && o >= 0) return o;
  } catch {
    // fall through
  }
  throw bad("cursor is not one this API returned.");
}

export function parseLimit(value: string | null, max = 500, fallback = 100): number {
  if (value === null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`limit must be between 1 and ${max}.`);
  return n;
}

export type Counts = Record<Severity, number>;
const zero = (): Counts => ({ critical: 0, high: 0, medium: 0, low: 0 });

export interface FindingFilter {
  status: Status;
  severity?: Severity[];
  ecosystem?: string;
  q?: string;
  projectId?: string;
}

interface FindingRow {
  project_id: string;
  project_name: string;
  fingerprint: string;
  ecosystem: string;
  package: string;
  version: string;
  advisory: string;
  aliases: string;
  severity: Severity;
  summary: string;
  fixed_version: string | null;
  path: string;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  triage: Triage;
  reason: string | null;
  triaged_by: string | null;
  triaged_at: string | null;
  expires_at: string | null;
}

export interface AuditOptions {
  /** Scans, and fixed findings nobody decided about, older than this are deleted (ADR 0015). */
  retentionDays?: number;
}

const aliasesOf = (json: string): string[] => {
  try {
    const v = JSON.parse(json) as unknown;
    return Array.isArray(v) ? v.filter((a): a is string => typeof a === "string") : [];
  } catch {
    return [];
  }
};

export function createAudit(db: DatabaseSync, { retentionDays = 365 }: AuditOptions = {}) {
  // A decision that has not expired. A finding whose acceptance ran out is open again.
  const SUPPRESSED = `(triage <> 'open' AND (expires_at IS NULL OR expires_at > ?))`;

  const projectRow = (id: string) => {
    const r = db.prepare("SELECT * FROM projects WHERE id = ?").get(id) as Record<string, string> | undefined;
    if (!r) throw notFound("The project");
    return r;
  };

  function openCounts(projectId?: string): Counts {
    const c = zero();
    const rows = db
      .prepare(`SELECT severity, COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND NOT ${SUPPRESSED} ${projectId ? "AND project_id = ?" : ""} GROUP BY severity`)
      .all(...([now(), ...(projectId ? [projectId] : [])] as SQLInputValue[])) as Array<{ severity: Severity; n: number }>;
    for (const r of rows) c[r.severity] = r.n;
    return c;
  }

  function presentProject(r: Record<string, any>) {
    const last = db.prepare("SELECT created_at, kind, branch, new_count, blocking FROM scans WHERE project_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1").get(r.id) as Record<string, any> | undefined;
    const suppressed = (db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE project_id = ? AND resolved_at IS NULL AND ${SUPPRESSED}`).get(r.id, now()) as { n: number }).n;
    const packages = (db.prepare("SELECT COUNT(DISTINCT ecosystem || name || version) AS n FROM packages WHERE project_id = ?").get(r.id) as { n: number }).n;
    return {
      id: r.id as string,
      name: r.name as string,
      defaultBranch: r.default_branch as string,
      failOn: r.fail_on as FailOn,
      open: openCounts(r.id),
      suppressed,
      packages,
      lastScan: last ? { at: last.created_at as string, kind: last.kind as "baseline" | "change", branch: last.branch as string, new: last.new_count as number, passed: last.blocking === 0 } : null,
      createdAt: r.created_at as string,
    };
  }

  function presentFinding(f: FindingRow) {
    const active = f.triage !== "open" && (!f.expires_at || f.expires_at > now());
    return {
      project: { id: f.project_id, name: f.project_name },
      fingerprint: f.fingerprint,
      ecosystem: f.ecosystem,
      package: f.package,
      version: f.version,
      advisory: f.advisory,
      aliases: aliasesOf(f.aliases),
      severity: f.severity,
      summary: f.summary,
      fixedVersion: f.fixed_version,
      path: f.path,
      firstSeen: f.first_seen,
      lastSeen: f.last_seen,
      resolvedAt: f.resolved_at,
      triage: f.triage === "open" ? null : { state: f.triage as Exclude<Triage, "open">, reason: f.reason!, by: f.triaged_by, at: f.triaged_at, expiresAt: f.expires_at, active },
    };
  }

  function findingsQuery(filter: FindingFilter, cursor: string | undefined, limit: number) {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    const at = `'${now()}'`;
    if (filter.status === "resolved") where.push("f.resolved_at IS NOT NULL");
    else {
      where.push("f.resolved_at IS NULL");
      where.push(filter.status === "suppressed" ? SUPPRESSED.replace("?", at) : `NOT ${SUPPRESSED.replace("?", at)}`);
    }
    if (filter.projectId) (where.push("f.project_id = ?"), args.push(filter.projectId));
    if (filter.ecosystem) (where.push("f.ecosystem = ?"), args.push(filter.ecosystem));
    if (filter.severity?.length) (where.push(`f.severity IN (${filter.severity.map(() => "?").join(",")})`), args.push(...filter.severity));
    if (filter.q) {
      const like = `%${filter.q.replace(/[\\%_]/g, "\\$&")}%`;
      where.push("(f.advisory LIKE ? ESCAPE '\\' OR f.package LIKE ? ESCAPE '\\' OR f.aliases LIKE ? ESCAPE '\\' OR f.summary LIKE ? ESCAPE '\\')");
      args.push(like, like, like, like);
    }
    const offset = decodeCursor(cursor);
    const rows = db
      .prepare(
        `SELECT f.*, p.name AS project_name FROM findings f JOIN projects p ON p.id = f.project_id WHERE ${where.join(" AND ")}
         ORDER BY ${RANK_SQL.replaceAll("severity", "f.severity")} DESC, f.first_seen DESC, f.fingerprint LIMIT ? OFFSET ?`,
      )
      .all(...args, limit + 1, offset) as unknown as FindingRow[];
    return { items: rows.slice(0, limit).map(presentFinding), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) } satisfies Page<unknown>;
  }

  function presentScan(s: Record<string, any>, projectName: string) {
    return {
      id: s.id as string,
      project: { id: s.project_id as string, name: projectName },
      kind: s.kind as "baseline" | "change",
      branch: s.branch as string,
      commit: (s.commit_sha as string | null) ?? null,
      pullRequest: (s.pull_request as string | null) ?? null,
      tool: s.tool as string,
      total: s.total as number,
      new: s.new_count as number,
      suppressed: s.suppressed as number,
      blocking: s.blocking as number,
      failOn: s.fail_on as FailOn,
      passed: s.blocking === 0,
      createdAt: s.created_at as string,
    };
  }

  const brief = (f: Advisory) => ({ fingerprint: f.fingerprint, ecosystem: f.ecosystem, package: f.package, version: f.version, advisory: f.advisory, severity: f.severity, summary: f.summary, fixedVersion: f.fixedVersion });

  return {
    /**
     * Takes an osv-scanner report or a SARIF log from CI. Scans of the default branch become the baseline; every other
     * scan is compared with it, and only advisories the baseline does not have, and nobody has decided about, can
     * fail the check. The default branch itself adopts what is there and never fails.
     */
    ingest(params: { project: string | null; branch: string | null; commit?: string | null; pullRequest?: string | null; defaultBranch?: string | null }, raw: Buffer) {
      const name = params.project;
      if (!name || !PROJECT_NAME.test(name)) throw bad("project is required: a name such as acme/web, up to 128 letters, digits, . _ - and /.");
      const branch = params.branch;
      if (!branch || !BRANCH.test(branch)) throw bad("branch is required: the branch that was scanned.");
      const commit = params.commit || null;
      if (commit && !/^[A-Za-z0-9]{4,64}$/.test(commit)) throw bad("commit must be a commit hash.");
      const pullRequest = params.pullRequest || null;
      if (pullRequest && !/^[A-Za-z0-9._#/-]{1,64}$/.test(pullRequest)) throw bad("pullRequest must be the number or name of the pull request.");
      if (params.defaultBranch && !BRANCH.test(params.defaultBranch)) throw bad("defaultBranch is not a branch name.");

      let body: unknown;
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new AuditError(422, "invalid-report", "The body is not JSON.");
      }
      let parsed: ReturnType<typeof parseReport>;
      try {
        parsed = parseReport(body);
      } catch (err) {
        if (err instanceof ReportError) throw new AuditError(422, "invalid-report", err.message);
        throw err;
      }

      const at = now();
      const id = randomUUID();
      db.exec("BEGIN IMMEDIATE");
      try {
        let project = db.prepare("SELECT * FROM projects WHERE name = ?").get(name) as Record<string, string> | undefined;
        if (!project) {
          const projectId = randomUUID();
          db.prepare("INSERT INTO projects (id, name, default_branch, fail_on, created_at) VALUES (?, ?, ?, 'high', ?)").run(projectId, name, params.defaultBranch || "main", at);
          project = projectRow(projectId);
        } else if (params.defaultBranch && params.defaultBranch !== project.default_branch) {
          db.prepare("UPDATE projects SET default_branch = ? WHERE id = ?").run(params.defaultBranch, project.id!);
          project.default_branch = params.defaultBranch;
        }
        const projectId = project.id!;
        const failOn = project.fail_on as FailOn;
        const kind = branch === project.default_branch && !pullRequest ? "baseline" : "change";

        const known = new Map<string, { resolved_at: string | null; triage: Triage; expires_at: string | null }>();
        for (const r of db.prepare("SELECT fingerprint, resolved_at, triage, expires_at FROM findings WHERE project_id = ?").all(projectId) as Array<{ fingerprint: string; resolved_at: string | null; triage: Triage; expires_at: string | null }>) known.set(r.fingerprint, r);
        const decided = (f: Advisory) => {
          const k = known.get(f.fingerprint);
          return !!k && k.triage !== "open" && (!k.expires_at || k.expires_at > at);
        };
        // New: the baseline has no open finding with this fingerprint.
        const fresh = parsed.findings.filter((f) => !known.has(f.fingerprint) || known.get(f.fingerprint)!.resolved_at !== null);
        const added = fresh.filter((f) => !decided(f));
        // The default branch is what was merged: its scan adopts what is there and never fails a pipeline. Changes do.
        const blocking = failOn === "none" || kind === "baseline" ? 0 : added.filter((f) => RANK[f.severity] >= RANK[failOn]).length;

        db.prepare(
          "INSERT INTO scans (id, project_id, kind, branch, commit_sha, pull_request, tool, total, new_count, suppressed, blocking, fail_on, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run(id, projectId, kind, branch, commit, pullRequest, parsed.tool, parsed.findings.length, added.length, fresh.length - added.length, blocking, failOn, at);

        if (kind === "baseline") {
          const upsert = db.prepare(
            `INSERT INTO findings (project_id, fingerprint, ecosystem, package, version, advisory, aliases, severity, summary, fixed_version, path, first_seen, last_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (project_id, fingerprint) DO UPDATE SET aliases = excluded.aliases, severity = excluded.severity, summary = excluded.summary,
               fixed_version = excluded.fixed_version, path = excluded.path, last_seen = excluded.last_seen,
               first_seen = CASE WHEN findings.resolved_at IS NULL THEN findings.first_seen ELSE excluded.first_seen END, resolved_at = NULL`,
          );
          for (const f of parsed.findings) upsert.run(projectId, f.fingerprint, f.ecosystem, f.package, f.version, f.advisory, JSON.stringify(f.aliases), f.severity, f.summary, f.fixedVersion, f.path, at, at);
          // What the default branch no longer reports is fixed: the dependency was updated or removed.
          db.prepare("UPDATE findings SET resolved_at = ? WHERE project_id = ? AND resolved_at IS NULL AND last_seen < ?").run(at, projectId, at);
          if (parsed.packages.length) {
            db.prepare("DELETE FROM packages WHERE project_id = ?").run(projectId);
            const insert = db.prepare("INSERT OR IGNORE INTO packages (project_id, ecosystem, name, version, path) VALUES (?, ?, ?, ?, ?)");
            for (const p of parsed.packages) insert.run(projectId, p.ecosystem, p.name, p.version, p.path);
          }
        } else {
          const insert = db.prepare(
            "INSERT INTO scan_findings (scan_id, fingerprint, ecosystem, package, version, advisory, aliases, severity, summary, fixed_version, path, suppressed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          );
          for (const f of fresh) insert.run(id, f.fingerprint, f.ecosystem, f.package, f.version, f.advisory, JSON.stringify(f.aliases), f.severity, f.summary, f.fixedVersion, f.path, decided(f) ? 1 : 0);
        }
        db.exec("COMMIT");
        const scan = presentScan(db.prepare("SELECT * FROM scans WHERE id = ?").get(id) as Record<string, any>, name);
        return { ...scan, findings: added.sort((a, b) => RANK[b.severity] - RANK[a.severity]).slice(0, SCAN_FINDINGS_IN_ANSWER).map(brief) };
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    },

    summary() {
      const projects = (db.prepare("SELECT COUNT(*) AS n FROM projects").get() as { n: number }).n;
      const suppressed = (db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND ${SUPPRESSED}`).get(now()) as { n: number }).n;
      const week = new Date(Date.now() - 7 * 86_400_000).toISOString();
      const failing = (db.prepare("SELECT COUNT(*) AS n FROM scans WHERE kind = 'change' AND blocking > 0 AND created_at > ?").get(week) as { n: number }).n;
      const fixable = (db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND fixed_version IS NOT NULL AND NOT ${SUPPRESSED}`).get(now()) as { n: number }).n;
      const lastScanAt = (db.prepare("SELECT MAX(created_at) AS t FROM scans").get() as { t: string | null }).t;
      return { projects, open: openCounts(), suppressed, fixable, failingChecks: failing, lastScanAt };
    },

    severityTotals: () => openCounts(),
    projectCount: () => (db.prepare("SELECT COUNT(*) AS n FROM projects").get() as { n: number }).n,
    suppressedCount: () => (db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND ${SUPPRESSED}`).get(now()) as { n: number }).n,

    listProjects(cursor: string | undefined, limit: number): Page<ReturnType<typeof presentProject>> {
      const offset = decodeCursor(cursor);
      const rows = db.prepare("SELECT * FROM projects ORDER BY name LIMIT ? OFFSET ?").all(limit + 1, offset) as Array<Record<string, any>>;
      return { items: rows.slice(0, limit).map(presentProject), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    project: (id: string) => presentProject(projectRow(id)),

    updateProject(id: string, body: Record<string, unknown>) {
      projectRow(id);
      const { defaultBranch, failOn, ...rest } = body;
      if (Object.keys(rest).length || (defaultBranch === undefined && failOn === undefined)) throw bad("Expected { defaultBranch?, failOn? }.");
      if (defaultBranch !== undefined) {
        if (typeof defaultBranch !== "string" || !BRANCH.test(defaultBranch)) throw bad("defaultBranch must be a branch name.");
        db.prepare("UPDATE projects SET default_branch = ? WHERE id = ?").run(defaultBranch, id);
      }
      if (failOn !== undefined) {
        if (typeof failOn !== "string" || !FAIL_ON.includes(failOn as FailOn)) throw bad(`failOn must be one of ${FAIL_ON.join(", ")}.`);
        db.prepare("UPDATE projects SET fail_on = ? WHERE id = ?").run(failOn, id);
      }
      return presentProject(projectRow(id));
    },

    deleteProject(id: string) {
      if (db.prepare("DELETE FROM projects WHERE id = ?").run(id).changes === 0) throw notFound("The project");
    },

    findings(filter: FindingFilter, cursor: string | undefined, limit: number) {
      if (filter.projectId) projectRow(filter.projectId);
      return findingsQuery(filter, cursor, limit);
    },

    /** Where a package is used, by name (a part of it) and ecosystem, across the default branches of every project. */
    packages(filter: { q?: string; ecosystem?: string; projectId?: string }, cursor: string | undefined, limit: number) {
      if (filter.projectId) projectRow(filter.projectId);
      const where: string[] = ["1 = 1"];
      const args: SQLInputValue[] = [];
      if (filter.projectId) (where.push("k.project_id = ?"), args.push(filter.projectId));
      if (filter.ecosystem) (where.push("k.ecosystem = ?"), args.push(filter.ecosystem));
      if (filter.q) (where.push("k.name LIKE ? ESCAPE '\\'"), args.push(`%${filter.q.replace(/[\\%_]/g, "\\$&")}%`));
      const offset = decodeCursor(cursor);
      const rows = db
        .prepare(`SELECT k.*, p.name AS project_name FROM packages k JOIN projects p ON p.id = k.project_id WHERE ${where.join(" AND ")} ORDER BY k.name, k.version, p.name, k.path LIMIT ? OFFSET ?`)
        .all(...args, limit + 1, offset) as Array<Record<string, any>>;
      return {
        items: rows.slice(0, limit).map((r) => ({ ecosystem: r.ecosystem as string, name: r.name as string, version: r.version as string, path: r.path as string, project: { id: r.project_id as string, name: r.project_name as string } })),
        ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }),
      } satisfies Page<unknown>;
    },

    scans(projectId: string, cursor: string | undefined, limit: number) {
      const project = projectRow(projectId);
      const offset = decodeCursor(cursor);
      const rows = db.prepare("SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?").all(projectId, limit + 1, offset) as Array<Record<string, any>>;
      return { items: rows.slice(0, limit).map((s) => presentScan(s, project.name!)), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) } satisfies Page<unknown>;
    },

    scan(id: string) {
      const s = db.prepare("SELECT s.*, p.name AS project_name FROM scans s JOIN projects p ON p.id = s.project_id WHERE s.id = ?").get(id) as Record<string, any> | undefined;
      if (!s) throw notFound("The scan");
      const findings = (db.prepare(`SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY ${RANK_SQL} DESC, package, advisory`).all(id) as Array<Record<string, any>>).map((f) => ({
        fingerprint: f.fingerprint as string,
        ecosystem: f.ecosystem as string,
        package: f.package as string,
        version: f.version as string,
        advisory: f.advisory as string,
        aliases: aliasesOf(f.aliases),
        severity: f.severity as Severity,
        summary: f.summary as string,
        fixedVersion: (f.fixed_version as string | null) ?? null,
        path: f.path as string,
        suppressed: f.suppressed === 1,
      }));
      return { ...presentScan(s, s.project_name), findings };
    },

    /** Sets or clears the decision about one advisory. It follows the fingerprint to every branch of the project. */
    triage(projectId: string, fingerprint: string, body: Record<string, unknown>, by: string) {
      projectRow(projectId);
      const { state, reason, expiresAt, ...rest } = body;
      if (Object.keys(rest).length || typeof state !== "string" || !TRIAGE.includes(state as Triage)) throw bad(`Expected { state, reason?, expiresAt? }; state is one of ${TRIAGE.join(", ")}.`);
      const held = db.prepare("SELECT 1 FROM findings WHERE project_id = ? AND fingerprint = ?").get(projectId, fingerprint);
      if (!held) {
        // An advisory that is only in a pull request: keep the decision on a baseline row that starts resolved.
        const s = db
          .prepare("SELECT sf.* FROM scan_findings sf JOIN scans s ON s.id = sf.scan_id WHERE s.project_id = ? AND sf.fingerprint = ? ORDER BY s.created_at DESC LIMIT 1")
          .get(projectId, fingerprint) as Record<string, any> | undefined;
        if (!s) throw notFound("The finding");
        const at = now();
        db.prepare(
          "INSERT INTO findings (project_id, fingerprint, ecosystem, package, version, advisory, aliases, severity, summary, fixed_version, path, first_seen, last_seen, resolved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run(projectId, fingerprint, s.ecosystem, s.package, s.version, s.advisory, s.aliases, s.severity, s.summary, s.fixed_version, s.path, at, at, at);
      }
      if (state === "open") {
        db.prepare("UPDATE findings SET triage = 'open', reason = NULL, triaged_by = NULL, triaged_at = NULL, expires_at = NULL WHERE project_id = ? AND fingerprint = ?").run(projectId, fingerprint);
      } else {
        // A decision without a reason is lost the day its author leaves (ADR 0044).
        if (typeof reason !== "string" || reason.trim().length < 3 || reason.length > 500) throw bad("reason is required: 3 to 500 characters.");
        let expires: string | null = null;
        if (expiresAt !== undefined && expiresAt !== null) {
          const t = typeof expiresAt === "string" ? Date.parse(expiresAt) : NaN;
          if (Number.isNaN(t) || t <= Date.now()) throw bad("expiresAt must be a date in the future.");
          if (t > Date.now() + MAX_ACCEPT_DAYS * 86_400_000) throw bad(`expiresAt must be within ${MAX_ACCEPT_DAYS} days.`);
          expires = new Date(t).toISOString();
        }
        // Accepted risk always ends; not affected and false positive do not need to.
        if (state === "accepted" && !expires) throw bad("expiresAt is required for accepted risk.");
        db.prepare("UPDATE findings SET triage = ?, reason = ?, triaged_by = ?, triaged_at = ?, expires_at = ? WHERE project_id = ? AND fingerprint = ?").run(state, reason.trim(), by, now(), expires, projectId, fingerprint);
      }
      const row = db.prepare("SELECT f.*, p.name AS project_name FROM findings f JOIN projects p ON p.id = f.project_id WHERE f.project_id = ? AND f.fingerprint = ?").get(projectId, fingerprint) as unknown as FindingRow;
      return presentFinding(row);
    },

    purge() {
      const before = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
      db.prepare("DELETE FROM scans WHERE created_at < ?").run(before);
      db.prepare("DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at < ? AND triage = 'open'").run(before);
    },
  };
}

export type Audit = ReturnType<typeof createAudit>;
export { SEVERITIES };

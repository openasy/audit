import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { osv, startApp, type TestPackage } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
const lodash: TestPackage = { name: "lodash", version: "4.17.20", vulns: [{ id: "GHSA-lodash", aliases: ["CVE-2021-23337"], cvss: CRIT, fixed: "4.17.21" }] };
const minimist: TestPackage = { name: "minimist", version: "1.2.5", vulns: [{ id: "GHSA-minimist", cvss: MED, fixed: "1.2.6" }] };
const requests: TestPackage = { name: "requests", version: "2.19.0", ecosystem: "PyPI", vulns: [{ id: "GHSA-requests", label: "HIGH", fixed: "2.20.0" }] };
const axios: TestPackage = { name: "axios", version: "0.21.0", vulns: [{ id: "GHSA-axios", cvss: CRIT }] };
const clean: TestPackage = { name: "left-pad", version: "1.3.0" };

const json = async (res: Response) => (await res.json()) as any;
const baseline = (...p: TestPackage[]) => app.scan({ project: "acme/web", branch: "main", commit: "aaaa1111" }, osv("package-lock.json", ...p));
const pull = (n: string, ...p: TestPackage[]) => app.scan({ project: "acme/web", branch: `feature-${n}`, pullRequest: n }, osv("package-lock.json", ...p));
const project = async () => (await json(await app.admin("/api/v1/projects"))).projects[0];

describe("scans", () => {
  it("adopts the default branch even when it holds critical advisories", async () => {
    const scan = await json(await baseline(lodash, minimist, requests, clean));
    expect(scan).toMatchObject({ kind: "baseline", total: 3, new: 3, blocking: 0, passed: true, failOn: "high", project: { name: "acme/web" } });
    expect(await project()).toMatchObject({
      name: "acme/web",
      defaultBranch: "main",
      open: { critical: 1, high: 1, medium: 1, low: 0 },
      packages: 4,
      suppressed: 0,
    });
  });

  it("fails a pull request only for advisories it adds, at or above failOn", async () => {
    // lodash and minimist are old news. axios is critical and new; a medium one is new but below the bar.
    const medium: TestPackage = { name: "ws", version: "7.0.0", vulns: [{ id: "GHSA-ws", cvss: MED }] };
    const scan = await json(await pull("7", lodash, minimist, requests, axios, medium));
    expect(scan).toMatchObject({ kind: "change", total: 5, new: 2, blocking: 1, passed: false });
    expect(scan.findings.map((f: { advisory: string }) => f.advisory)).toEqual(["GHSA-axios", "GHSA-ws"]);
    expect(scan.findings[0]).toMatchObject({ ecosystem: "npm", package: "axios", version: "0.21.0", severity: "critical", fixedVersion: null });
  });

  it("does not fail a pull request that only updates a dependency", async () => {
    // The vulnerable version is gone, the new version has nothing.
    expect(await json(await pull("8", { name: "lodash", version: "4.17.21" }, minimist, requests))).toMatchObject({ new: 0, passed: true });
  });

  it("treats another version of the same package as a new advisory", async () => {
    const older: TestPackage = { name: "lodash", version: "4.17.19", vulns: [{ id: "GHSA-lodash", cvss: CRIT }] };
    expect(await json(await pull("9", older, minimist, requests))).toMatchObject({ new: 1, blocking: 1 });
  });

  it("does not let a pull request change the baseline", async () => {
    const list = await json(await app.admin("/api/v1/findings"));
    expect(list.findings.map((f: { advisory: string }) => f.advisory).sort()).toEqual(["GHSA-lodash", "GHSA-minimist", "GHSA-requests"]);
    expect(list.findings[0]).toMatchObject({
      advisory: "GHSA-lodash",
      aliases: ["CVE-2021-23337"],
      fixedVersion: "4.17.21",
      path: "package-lock.json",
      severity: "critical",
    });
  });

  it("marks advisories fixed when the default branch stops reporting them, and opens them again if they return", async () => {
    await baseline({ name: "lodash", version: "4.17.21" }, minimist, requests);
    const p = await project();
    expect((await json(await app.admin(`/api/v1/projects/${p.id}/findings?status=resolved`))).findings.map((f: { advisory: string }) => f.advisory)).toEqual([
      "GHSA-lodash",
    ]);
    expect(await json(await pull("10", lodash, minimist, requests))).toMatchObject({ new: 1 });
    await baseline(lodash, minimist, requests);
    expect((await json(await app.admin(`/api/v1/projects/${p.id}/findings?status=resolved`))).findings).toEqual([]);
  });

  it("keeps an inventory of the packages the default branch listed, and searches it", async () => {
    const all = await json(await app.admin("/api/v1/packages"));
    expect(all.packages.map((x: { name: string }) => x.name)).toEqual(["lodash", "minimist", "requests"]);
    expect(all.packages[0]).toMatchObject({ ecosystem: "npm", version: "4.17.20", path: "package-lock.json", project: { name: "acme/web" } });
    expect((await json(await app.admin("/api/v1/packages?q=mini"))).packages.map((x: { name: string }) => x.name)).toEqual(["minimist"]);
    expect((await json(await app.admin("/api/v1/packages?ecosystem=PyPI"))).packages.map((x: { name: string }) => x.name)).toEqual(["requests"]);
    expect((await json(await app.admin("/api/v1/packages?q=%25"))).packages).toEqual([]);
    expect((await json(await app.admin("/api/v1/packages?limit=1"))).nextCursor).toBeDefined();
    expect((await app.admin("/api/v1/packages?project=missing")).status).toBe(404);
    expect((await app.admin("/api/v1/packages?q=" + "x".repeat(200))).status).toBe(422);
  });
});

describe("decisions", () => {
  const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();
  const decide = async (advisory: string, body: unknown, status = "open") => {
    const p = await project();
    const f = (await json(await app.admin(`/api/v1/projects/${p.id}/findings?q=${advisory}&status=${status}`))).findings[0];
    return app.admin(`/api/v1/projects/${p.id}/findings/${f.fingerprint}`, { method: "PUT", body: JSON.stringify(body) });
  };

  it("takes not-affected with a reason, and keeps it for the next pull request", async () => {
    expect((await decide("GHSA-lodash", { state: "not-affected", reason: "" })).status).toBe(422);
    const done = await json(await decide("GHSA-lodash", { state: "not-affected", reason: "We never call template()" }));
    expect(done).toMatchObject({ advisory: "GHSA-lodash", triage: { state: "not-affected", by: "admin token", expiresAt: null, active: true } });
    expect((await project()).open).toMatchObject({ critical: 0, high: 1, medium: 1 });
    expect(await json(await pull("11", lodash, minimist, requests))).toMatchObject({ new: 0, passed: true });
  });

  it("needs an end for accepted risk, and lets a false positive stand", async () => {
    expect((await decide("GHSA-requests", { state: "accepted", reason: "Internal use only" })).status).toBe(422);
    expect((await decide("GHSA-requests", { state: "accepted", reason: "Internal use only", expiresAt: inDays(-1) })).status).toBe(422);
    expect((await decide("GHSA-requests", { state: "accepted", reason: "Internal use only", expiresAt: inDays(400) })).status).toBe(422);
    expect((await decide("GHSA-requests", { state: "ignored", reason: "x" })).status).toBe(422);
    expect((await decide("GHSA-requests", { state: "false-positive", reason: "x ok", extra: 1 })).status).toBe(422);
    const done = await json(await decide("GHSA-requests", { state: "accepted", reason: "Internal use only until the rewrite", expiresAt: inDays(30) }));
    expect(done).toMatchObject({ triage: { state: "accepted", expiresAt: expect.any(String), active: true } });
    expect((await json(await app.admin("/api/v1/findings?status=suppressed"))).findings.map((f: { advisory: string }) => f.advisory).sort()).toEqual([
      "GHSA-lodash",
      "GHSA-requests",
    ]);
    // The acceptance runs out.
    app.db.prepare("UPDATE findings SET expires_at = ? WHERE triage = 'accepted'").run(new Date(Date.now() - 1000).toISOString());
    expect((await project()).open.high).toBe(1);
    expect(await json(await decide("GHSA-requests", { state: "open" }, "open"))).toMatchObject({ triage: null });
  });

  it("keeps the decision for an advisory that is only in a pull request", async () => {
    const first = await json(await pull("12", lodash, minimist, requests, axios));
    expect(first).toMatchObject({ new: 1, passed: false });
    const p = await project();
    const put = (body: unknown) =>
      app.admin(`/api/v1/projects/${p.id}/findings/${first.findings[0].fingerprint}`, { method: "PUT", body: JSON.stringify(body) });
    expect((await app.admin(`/api/v1/projects/${p.id}/findings/nope`, { method: "PUT", body: JSON.stringify({ state: "open" }) })).status).toBe(404);
    expect((await put({ state: "false-positive", reason: "The scanner read a test fixture" })).status).toBe(200);
    expect(await json(await pull("12", lodash, minimist, requests, axios))).toMatchObject({ new: 0, suppressed: 1, passed: true });
    const scanId = (await json(await app.admin(`/api/v1/projects/${p.id}/scans`))).scans[0].id;
    expect((await json(await app.admin(`/api/v1/scans/${scanId}`))).findings).toMatchObject([{ advisory: "GHSA-axios", suppressed: true }]);
    // Merged: the decision comes with it.
    await baseline(lodash, minimist, requests, axios);
    expect((await json(await app.admin(`/api/v1/projects/${p.id}/findings?status=suppressed&q=axios`))).findings).toMatchObject([{ resolvedAt: null }]);
  });
});

describe("projects, filters and access", () => {
  it("filters and pages findings", async () => {
    const all = await json(await app.admin("/api/v1/findings?limit=1"));
    expect(all.findings).toHaveLength(1);
    expect(all.nextCursor).toBeDefined();
    // Both critical advisories have a decision, so none is open.
    expect((await json(await app.admin("/api/v1/findings?severity=critical"))).findings).toEqual([]);
    expect((await json(await app.admin("/api/v1/findings?ecosystem=PyPI"))).findings.map((f: { advisory: string }) => f.advisory)).toEqual(["GHSA-requests"]);
    expect((await json(await app.admin("/api/v1/findings?q=CVE-2021"))).findings).toEqual([]);
    expect((await json(await app.admin("/api/v1/findings?status=suppressed&q=CVE-2021"))).findings.map((f: { advisory: string }) => f.advisory)).toEqual([
      "GHSA-lodash",
    ]);
    expect((await app.admin("/api/v1/findings?severity=urgent")).status).toBe(422);
    expect((await app.admin("/api/v1/findings?status=gone")).status).toBe(422);
    expect((await app.admin("/api/v1/findings?limit=0")).status).toBe(422);
    expect((await app.admin("/api/v1/findings?cursor=junk")).status).toBe(422);
  });

  it("changes what fails a check, and the default branch, and deletes", async () => {
    const p = await project();
    const patch = (body: unknown) => app.admin(`/api/v1/projects/${p.id}`, { method: "PATCH", body: JSON.stringify(body) });
    const extra: TestPackage = { name: "ws", version: "7.0.0", vulns: [{ id: "GHSA-ws-new", cvss: CRIT }] };
    expect((await patch({ failOn: "none" })).status).toBe(200);
    expect(await json(await pull("13", lodash, minimist, requests, axios, extra))).toMatchObject({ new: 1, blocking: 0, passed: true, failOn: "none" });
    await patch({ failOn: "high" });
    expect(await json(await pull("14", lodash, minimist, requests, axios, extra))).toMatchObject({ new: 1, blocking: 1, passed: false });
    expect((await patch({ failOn: "urgent" })).status).toBe(422);
    expect((await patch({})).status).toBe(422);
    expect((await patch({ name: "x" })).status).toBe(422);
    expect((await patch({ defaultBranch: "has space" })).status).toBe(422);
    expect(await json(await patch({ defaultBranch: "trunk" }))).toMatchObject({ defaultBranch: "trunk" });
    expect(await json(await baseline(lodash))).toMatchObject({ kind: "change" });
    expect((await app.admin(`/api/v1/projects/${p.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/projects/${p.id}`)).status).toBe(404);
    expect((await json(await app.admin("/api/v1/summary"))).projects).toBe(0);
    expect((await json(await app.admin("/api/v1/packages"))).packages).toEqual([]);
  });

  it("takes a SARIF log, gzip, and refuses what it cannot compare", async () => {
    const send = (query: Record<string, string>, body: string | Buffer, headers: Record<string, string> = {}) =>
      app.ingest(`/api/v1/scans?${new URLSearchParams(query)}`, { method: "POST", body, headers });
    const sarif = JSON.stringify({
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "Trivy" } },
          results: [
            {
              ruleId: "CVE-2024-1",
              level: "error",
              message: { text: "Package: minimist\nInstalled Version: 1.2.5\nFixed Version: 1.2.6" },
              locations: [{ physicalLocation: { artifactLocation: { uri: "yarn.lock" } } }],
            },
          ],
        },
      ],
    });
    expect(await json(await send({ project: "acme/api", branch: "main" }, sarif))).toMatchObject({ kind: "baseline", tool: "Trivy", total: 1 });
    expect((await send({ project: "acme/api", branch: "main" }, gzipSync(osv("go.sum", lodash)), { "content-encoding": "gzip" })).status).toBe(201);
    const problem = async (res: Response, status: number, code: string) => (expect(res.status).toBe(status), expect(await json(res)).toMatchObject({ code }));
    await problem(await send({ project: "acme/api", branch: "main" }, "{nope"), 422, "invalid-report");
    await problem(await send({ project: "acme/api", branch: "main" }, JSON.stringify({ hello: 1 })), 422, "invalid-report");
    await problem(await send({ branch: "main" }, osv("a")), 422, "invalid-body");
    await problem(await send({ project: "../etc", branch: "main" }, osv("a")), 422, "invalid-body");
    await problem(await send({ project: "acme/api" }, osv("a")), 422, "invalid-body");
    await problem(await send({ project: "acme/api", branch: "main", commit: "no hash!" }, osv("a")), 422, "invalid-body");
    await problem(await send({ project: "acme/api", branch: "main", pullRequest: "a b" }, osv("a")), 422, "invalid-body");
    await problem(await send({ project: "acme/api", branch: "main", defaultBranch: "a b" }, osv("a")), 422, "invalid-body");
    await problem(await send({ project: "acme/api", branch: "main" }, osv("a"), { "content-encoding": "br" }), 400, "invalid-body");
  });

  it("asks for a token, and answers version, health and metrics", async () => {
    expect((await fetch(`${app.base}/api/v1/scans?project=a&branch=main`, { method: "POST", body: osv("a") })).status).toBe(401);
    expect(
      (await fetch(`${app.base}/api/v1/scans?project=a&branch=main`, { method: "POST", body: osv("a"), headers: { authorization: "Bearer nope" } })).status,
    ).toBe(401);
    expect((await app.ingest("/api/v1/findings")).status).toBe(401);
    expect((await app.ingest("/api/v1/packages")).status).toBe(401);
    const closed = await startApp({ version: "0.1.0", ingestToken: undefined, adminToken: undefined });
    expect((await fetch(`${closed.base}/api/v1/scans?project=a&branch=main`, { method: "POST", body: osv("a") })).status).toBe(503);
    await closed.close();
    expect(await json(await fetch(`${app.base}/api/v1/version`))).toEqual({ product: "audit", version: "0.1.0" });
    expect((await fetch(`${app.base}/readyz`)).status).toBe(200);
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="audit",version="0.1.0"} 1');
    expect(metrics).toContain('openasy_audit_open_findings{severity="high"}');
  });
});

describe("the overview", () => {
  let own: Awaited<ReturnType<typeof startApp>>;
  beforeAll(async () => {
    own = await startApp({ version: "0.1.0" });
  });
  afterAll(() => own.close());

  it("counts open by day, found and fixed by week, and ranks packages and projects", async () => {
    const scan = (...p: TestPackage[]) => own.scan({ project: "acme/web", branch: "main", commit: "aaaa1111" }, osv("package-lock.json", ...p));
    await scan(lodash, minimist, requests);
    await scan({ name: "lodash", version: "4.17.21" }, minimist, requests);
    await own.scan({ project: "acme/web", branch: "feature-1", pullRequest: "1" }, osv("package-lock.json", minimist, requests, axios));
    const o = await json(await own.admin("/api/v1/overview"));
    expect(o.open).toEqual({ critical: 0, high: 1, medium: 1, low: 0 });
    expect(o.days).toHaveLength(30);
    expect(o.days.at(-1).open).toEqual(o.open);
    expect(o.weeks).toHaveLength(12);
    expect(o.weeks.at(-1)).toEqual({ week: expect.any(String), new: 3, fixed: 1 });
    expect(o.topPackages[0]).toMatchObject({ package: "requests", ecosystem: "PyPI", open: 1, projects: 1, severity: "high" });
    expect(o.topProjects).toEqual([{ id: expect.any(String), name: "acme/web", open: 2, critical: 0 }]);
    expect(o.checks).toEqual({ days7: { passed: 0, failed: 1 }, days30: { passed: 0, failed: 1 } });
  });
});

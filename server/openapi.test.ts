import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, INGEST_TOKEN, osv, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "audit-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({
  headers: { authorization: `Bearer ${token}`, "content-type": type },
  ...(body !== undefined && { body }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // audit's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let project = "";
  let scanId = "";
  let fingerprint = "";
  const CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
  const lodash = { name: "lodash", version: "4.17.20", vulns: [{ id: "GHSA-lodash", aliases: ["CVE-2021-23337"], cvss: CRIT, fixed: "4.17.21" }] };
  const axios = { name: "axios", version: "0.21.0", vulns: [{ id: "GHSA-axios", label: "HIGH" }] };
  const send = (body = osv("package-lock.json", lodash), token = INGEST_TOKEN) => auth(token, body);
  const path = (query: string) => `/api/v1/scans?${query}`;

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("scans: baseline, change, and every refusal", async () => {
    const baseline = (await call("POST", "/api/v1/scans", send(), path("project=acme/web&branch=main&commit=abc123"))).body as { project: { id: string } };
    project = baseline.project.id;
    const change = (await call("POST", "/api/v1/scans", send(osv("package-lock.json", lodash, axios)), path("project=acme/web&branch=fix&pullRequest=3")))
      .body as { id: string; findings: Array<{ fingerprint: string }> };
    scanId = change.id;
    fingerprint = change.findings[0]!.fingerprint;
    await call("POST", "/api/v1/scans", send("{nope"), path("project=acme/web&branch=main"));
    await call("POST", "/api/v1/scans", send(JSON.stringify({ hello: 1 })), path("project=acme/web&branch=main"));
    await call("POST", "/api/v1/scans", send(), path("branch=main"));
    await call("POST", "/api/v1/scans", auth("wrong", osv("a")), path("project=acme/web&branch=main"));
    await call("POST", "/api/v1/scans", { method: "POST" }, path("project=acme/web&branch=main"));
    await call("GET", "/api/v1/scans/{id}", admin(), `/api/v1/scans/${scanId}`);
    await call("GET", "/api/v1/scans/{id}", admin(), "/api/v1/scans/missing");
    await call("GET", "/api/v1/scans/{id}", {}, `/api/v1/scans/${scanId}`);
  });

  it("projects", async () => {
    await call("GET", "/api/v1/projects", admin());
    await call("GET", "/api/v1/projects", admin(), "/api/v1/projects?limit=1");
    await call("GET", "/api/v1/projects", admin(), "/api/v1/projects?limit=0");
    await call("GET", "/api/v1/projects", {});
    await call("GET", "/api/v1/projects/{id}", admin(), `/api/v1/projects/${project}`);
    await call("GET", "/api/v1/projects/{id}", admin(), "/api/v1/projects/missing");
    await call("PATCH", "/api/v1/projects/{id}", admin({ failOn: "critical" }), `/api/v1/projects/${project}`);
    await call("PATCH", "/api/v1/projects/{id}", admin({ failOn: "urgent" }), `/api/v1/projects/${project}`);
    await call("PATCH", "/api/v1/projects/{id}", admin("nope"), `/api/v1/projects/${project}`);
    await call("PATCH", "/api/v1/projects/{id}", admin({ failOn: "high" }), "/api/v1/projects/missing");
    await call("PATCH", "/api/v1/projects/{id}", { method: "PATCH" }, `/api/v1/projects/${project}`);
    await call("GET", "/api/v1/projects/{id}/scans", admin(), `/api/v1/projects/${project}/scans`);
    await call("GET", "/api/v1/projects/{id}/scans", admin(), "/api/v1/projects/missing/scans");
    await call("GET", "/api/v1/projects/{id}/scans", admin(), `/api/v1/projects/${project}/scans?cursor=junk`);
    await call("GET", "/api/v1/projects/{id}/scans", {}, `/api/v1/projects/${project}/scans`);
  });

  it("findings, packages and decisions", async () => {
    const { body } = await call("GET", "/api/v1/findings", admin());
    expect((body as { findings: unknown[] }).findings).toHaveLength(1);
    await call("GET", "/api/v1/findings", admin(), "/api/v1/findings?status=resolved&severity=high,critical&ecosystem=npm&q=lodash&limit=1");
    await call("GET", "/api/v1/findings", admin(), `/api/v1/findings?project=${project}`);
    await call("GET", "/api/v1/findings", admin(), "/api/v1/findings?severity=urgent");
    await call("GET", "/api/v1/findings", {});
    await call("GET", "/api/v1/projects/{id}/findings", admin(), `/api/v1/projects/${project}/findings`);
    await call("GET", "/api/v1/projects/{id}/findings", admin(), `/api/v1/projects/${project}/findings?status=suppressed`);
    await call("GET", "/api/v1/projects/{id}/findings", admin(), "/api/v1/projects/missing/findings");
    await call("GET", "/api/v1/projects/{id}/findings", {}, `/api/v1/projects/${project}/findings`);
    await call("GET", "/api/v1/packages", admin());
    await call("GET", "/api/v1/packages", admin(), `/api/v1/packages?q=lod&ecosystem=npm&project=${project}&limit=1`);
    await call("GET", "/api/v1/packages", admin(), "/api/v1/packages?project=missing");
    await call("GET", "/api/v1/packages", {});

    const put = (fp: string, state: unknown) =>
      call("PUT", "/api/v1/projects/{id}/findings/{fingerprint}", admin(state), `/api/v1/projects/${project}/findings/${fp}`);
    await put(fingerprint, { state: "false-positive", reason: "A test fixture" });
    await put(fingerprint, { state: "not-affected", reason: "The code is not called" });
    await put(fingerprint, { state: "accepted", reason: "Behind the VPN", expiresAt: inDays(30) });
    await put(fingerprint, { state: "accepted", reason: "No end" });
    await put(fingerprint, "nope");
    await put("missing", { state: "open" });
    await call("GET", "/api/v1/projects/{id}/findings", admin(), `/api/v1/projects/${project}/findings?status=suppressed`);
    await put(fingerprint, { state: "open" });
    await call("PUT", "/api/v1/projects/{id}/findings/{fingerprint}", { method: "PUT" }, `/api/v1/projects/${project}/findings/${fingerprint}`);
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/overview", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("deletes a project", async () => {
    await call("DELETE", "/api/v1/projects/{id}", admin(), `/api/v1/projects/${project}`);
    await call("DELETE", "/api/v1/projects/{id}", admin(), `/api/v1/projects/${project}`);
    await call("DELETE", "/api/v1/projects/{id}", { method: "DELETE" }, "/api/v1/projects/x");
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});

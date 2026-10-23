// Starts the app on a random port for tests.
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createAudit } from "./audit.ts";

export const INGEST_TOKEN = "test-ingest-token";
export const ADMIN_TOKEN = "test-admin-token";

export interface TestVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  /** A CVSS vector or a number. */
  cvss?: string;
  /** The database's own label, used when there is no score. */
  label?: string;
  fixed?: string;
}

export interface TestPackage {
  name: string;
  version: string;
  ecosystem?: string;
  vulns?: TestVuln[];
}

/** The JSON of `osv-scanner --format json`, cut down to what audit reads. */
export function osv(path: string, ...packages: TestPackage[]) {
  return JSON.stringify({
    results: [
      {
        source: { path, type: "lockfile" },
        packages: packages.map((p) => ({
          package: { name: p.name, version: p.version, ecosystem: p.ecosystem ?? "npm" },
          vulnerabilities: (p.vulns ?? []).map((v) => ({
            id: v.id,
            aliases: v.aliases ?? [],
            summary: v.summary ?? `${v.id} in ${p.name}`,
            ...(v.cvss && { severity: [{ type: "CVSS_V3", score: v.cvss }] }),
            ...(v.label && { database_specific: { severity: v.label } }),
            ...(v.fixed && {
              affected: [
                { package: { name: p.name, ecosystem: p.ecosystem ?? "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: v.fixed }] }] },
              ],
            }),
          })),
        })),
      },
    ],
  });
}

export async function startApp(opts: Partial<AppOptions> & { version: string }) {
  const db = openDb(":memory:");
  const audit = createAudit(db);
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "audit", productName: "OpenAsy Audit", origin: base });
  handler = createApp({ db, audit, auth, ingestToken: INGEST_TOKEN, adminToken: ADMIN_TOKEN, ...opts });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const ingest = as(INGEST_TOKEN);
  /** Sends a scan the way CI does. */
  const scan = (query: Record<string, string>, body: string) => ingest(`/api/v1/scans?${new URLSearchParams(query)}`, { method: "POST", body });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, audit, auth, base, admin, ingest, scan, close };
}

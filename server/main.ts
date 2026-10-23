import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { log } from "./log.ts";
import { parseProducts } from "./products.ts";
import { createAudit } from "./audit.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.AUDIT_DB ?? "/data/audit.db";
const retentionDays = Number(process.env.AUDIT_RETENTION_DAYS ?? 365);
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.AUDIT_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.AUDIT_METRICS_PORT ? Number(process.env.AUDIT_METRICS_PORT) : undefined;

if (!Number.isFinite(retentionDays) || retentionDays < 1) throw new Error("AUDIT_RETENTION_DAYS must be a number of days, 1 or more");

const db = openDb(dbPath);
// The address people open audit at, behind the TLS proxy (ADR 0026). Cookies, passkeys and OIDC redirects use it.
const publicUrl = (process.env.AUDIT_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
const secretsKeyFile = process.env.AUDIT_KEY_FILE ?? "/run/secrets/openasy-kek";
const auth = createAuth({
  db,
  product: "audit",
  productName: "OpenAsy Audit",
  origin: publicUrl,
  // Locally the same audit is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.AUDIT_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "AUDIT_"),
  secretsKey: readSecretsKey(secretsKeyFile),
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens.
  onEvent: (event) => log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event }),
});
const audit = createAudit(db, { retentionDays });
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });
const server = createServer(
  createApp({
    db,
    audit,
    version,
    auth,
    ingestToken: process.env.AUDIT_INGEST_TOKEN,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(audit, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "audit started", { version, port, db: dbPath, headless, retentionDays }));
if (!process.env.AUDIT_INGEST_TOKEN)
  log("warn", "AUDIT_INGEST_TOKEN is not set; CI needs an API token with the editor role (Settings, API tokens) to send scans");
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "AUDIT_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys. Put audit behind TLS (ADR 0026)", { url: publicUrl });
}
if (auth.secretsInClear)
  log("warn", "no secrets key: TOTP secrets are stored unencrypted. Mount a 32-byte key (openssl rand -hex 32)", { file: secretsKeyFile });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

audit.purge();
const timers: NodeJS.Timeout[] = [setInterval(() => auth.purge(), 5 * 60_000), setInterval(() => audit.purge(), 24 * 3_600_000)];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

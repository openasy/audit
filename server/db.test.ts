import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "audit-")), "nested", "audit.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();

    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("deletes a project's scans, findings and packages with it", () => {
    const db = openDb(":memory:");
    db.exec(`INSERT INTO projects VALUES ('r', 'acme/web', 'main', 'high', 'now');
      INSERT INTO scans VALUES ('s', 'r', 'baseline', 'main', NULL, NULL, 'osv-scanner', 1, 1, 0, 0, 'high', 'now');
      INSERT INTO findings (project_id, fingerprint, ecosystem, package, version, advisory, severity, summary, path, first_seen, last_seen) VALUES ('r', 'f', 'npm', 'lodash', '1', 'GHSA-x', 'low', 'm', 'a', 'now', 'now');
      INSERT INTO packages VALUES ('r', 'npm', 'lodash', '1', 'package-lock.json');
      DELETE FROM projects`);
    expect(db.prepare("SELECT (SELECT COUNT(*) FROM scans) + (SELECT COUNT(*) FROM findings) + (SELECT COUNT(*) FROM packages) AS n").get()).toEqual({ n: 0 });
  });
});

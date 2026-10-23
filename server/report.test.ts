import { describe, expect, it } from "vitest";
import { cvss3Base, ecosystemOf, fromScore, normalizePath, parseReport, ReportError } from "./report.ts";
import { osv, type TestPackage } from "./test-app.ts";

const parse = (...p: TestPackage[]) => parseReport(JSON.parse(osv("package-lock.json", ...p)));
const lodash: TestPackage = {
  name: "lodash",
  version: "4.17.20",
  vulns: [
    {
      id: "GHSA-35jh-r3h4-6jhm",
      aliases: ["CVE-2021-23337"],
      summary: "Command injection",
      cvss: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      fixed: "4.17.21",
    },
  ],
};

describe("cvss3Base", () => {
  it("computes the base score of v3 vectors", () => {
    expect(cvss3Base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3Base("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")).toBe(8.8);
    expect(cvss3Base("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
    expect(cvss3Base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")).toBe(5.3);
    expect(cvss3Base("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")).toBe(5.5);
    expect(cvss3Base("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")).toBe(1.8);
    expect(cvss3Base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
  });
  it("refuses what is not a v3 vector", () => {
    expect(cvss3Base("AV:N/AC:L/Au:N/C:P/I:P/A:P")).toBeNull();
    expect(cvss3Base("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeNull();
    expect(cvss3Base("CVSS:3.1/AV:N")).toBeNull();
  });
  it("rates scores", () => {
    expect([9.8, 9, 8.8, 7, 6.9, 4, 3.9, 0.1, 0].map(fromScore)).toEqual(["critical", "critical", "high", "high", "medium", "medium", "low", "low", null]);
  });
});

describe("parseReport (osv-scanner)", () => {
  it("reads package, advisory, aliases, severity, summary and the fixed version", () => {
    const { tool, findings, packages } = parse(lodash, { name: "left-pad", version: "1.3.0" });
    expect(tool).toBe("osv-scanner");
    expect(findings).toEqual([
      {
        fingerprint: expect.stringMatching(/^[0-9a-f]{32}$/),
        ecosystem: "npm",
        package: "lodash",
        version: "4.17.20",
        advisory: "GHSA-35jh-r3h4-6jhm",
        aliases: ["CVE-2021-23337"],
        severity: "high",
        summary: "Command injection",
        fixedVersion: "4.17.21",
        path: "package-lock.json",
      },
    ]);
    // Every package the report lists is in the inventory, with or without advisories.
    expect(packages.map((p) => `${p.name}@${p.version}`).sort()).toEqual(["left-pad@1.3.0", "lodash@4.17.20"]);
  });

  it("rates by score, then by the database label, then as medium", () => {
    const sev = (v: { cvss?: string; label?: string }) => parse({ name: "x", version: "1", vulns: [{ id: "A-1", ...v }] }).findings[0]!.severity;
    expect(sev({ cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" })).toBe("critical");
    expect(sev({ cvss: "7.5" })).toBe("high");
    expect(sev({ label: "CRITICAL" })).toBe("critical");
    expect(sev({ label: "MODERATE" })).toBe("medium");
    expect(sev({ label: "LOW" })).toBe("low");
    // A v2 vector is not scored; the label decides.
    expect(sev({ cvss: "AV:N/AC:L/Au:N/C:P/I:P/A:P", label: "HIGH" })).toBe("high");
    expect(sev({})).toBe("medium");
  });

  it("tells ecosystems apart from the report and from the lockfile name", () => {
    expect(ecosystemOf("PyPI")).toBe("PyPI");
    expect(ecosystemOf("Debian:12")).toBe("Debian");
    expect(ecosystemOf(undefined, "svc/go.sum")).toBe("Go");
    expect(ecosystemOf(undefined, "Cargo.lock")).toBe("crates.io");
    expect(ecosystemOf(undefined, "composer.lock")).toBe("Packagist");
    expect(ecosystemOf(undefined, "poetry.lock")).toBe("PyPI");
    expect(ecosystemOf(undefined, "pnpm-lock.yaml")).toBe("npm");
    expect(ecosystemOf(undefined, "other.txt")).toBe("unknown");
  });

  it("keeps one finding for the same advisory in the same package version, even in two lockfiles", () => {
    const body = JSON.parse(osv("a/package-lock.json", lodash));
    body.results.push(JSON.parse(osv("b/package-lock.json", lodash)).results[0]);
    const { findings, packages } = parseReport(body);
    expect(findings).toHaveLength(1);
    expect(packages).toHaveLength(2);
  });

  it("keeps another version of the same package apart", () => {
    const fp = (version: string) => parse({ name: "lodash", version, vulns: [{ id: "A-1" }] }).findings[0]!.fingerprint;
    expect(fp("4.17.20")).not.toBe(fp("4.17.19"));
    expect(fp("4.17.20")).toBe(fp("4.17.20"));
  });
});

describe("parseReport (SARIF)", () => {
  const sarif = (result: object, rules: object[] = []) => ({ version: "2.1.0", runs: [{ tool: { driver: { name: "Trivy", rules } }, results: [result] }] });

  it("reads Trivy's results: the rule is the advisory and the message names the package", () => {
    const { tool, findings } = parseReport(
      sarif(
        {
          ruleId: "CVE-2024-0001",
          level: "error",
          message: { text: "Package: minimist\nInstalled Version: 1.2.5\nVulnerability CVE-2024-0001\nFixed Version: 1.2.6" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "yarn.lock" } } }],
        },
        [{ id: "CVE-2024-0001", shortDescription: { text: "Prototype pollution" }, properties: { "security-severity": "9.8" } }],
      ),
    );
    expect(tool).toBe("Trivy");
    expect(findings).toMatchObject([
      {
        ecosystem: "npm",
        package: "minimist",
        version: "1.2.5",
        advisory: "CVE-2024-0001",
        severity: "critical",
        fixedVersion: "1.2.6",
        summary: "Prototype pollution",
        path: "yarn.lock",
      },
    ]);
  });

  it("leaves out results without a package and suppressed ones", () => {
    expect(parseReport(sarif({ ruleId: "CVE-1", message: { text: "no package named" } })).findings).toEqual([]);
    expect(
      parseReport(sarif({ ruleId: "CVE-1", suppressions: [{ kind: "external" }], properties: { package: "x" }, message: { text: "m" } })).findings,
    ).toEqual([]);
  });
});

describe("parseReport (refusals)", () => {
  it("refuses what is neither", () => {
    for (const body of [[], null, "x", {}, { hello: 1 }]) expect(() => parseReport(body)).toThrow(ReportError);
    expect(() => parseReport({ version: "1.0.0", runs: [] })).toThrow(/not supported/);
    expect(parseReport({ results: [] })).toEqual({ tool: "osv-scanner", findings: [], packages: [] });
  });
  it("gives the path the project knows", () => {
    expect(normalizePath("file:///src/a%20b/go.sum")).toBe("src/a b/go.sum");
    expect(normalizePath("./web\\package-lock.json")).toBe("web/package-lock.json");
  });
});

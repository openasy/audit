# audit

[![CI](https://github.com/openasy/audit/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/audit/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Audit product: known vulnerabilities in the dependencies of every project, for
npm, pip, Go, Cargo and Composer, where **a pull request fails only for what it adds** (ADR 0044). Your pipeline runs
[osv-scanner](https://github.com/google/osv-scanner), [Trivy](https://github.com/aquasecurity/trivy) or Grype on the
lockfiles and sends the result here. audit compares it with the default branch and answers whether the check passes.

```
CI: osv-scanner --format json  ──POST /api/v1/scans──▶  audit  ──▶  { new, blocking, passed }
                                                          └── baseline, package inventory, decisions, history
```

audit reads reports and nothing else: it holds no scanner and no advisory database, so what it knows is what your
scanner knew when it ran.

## What it reads

From the JSON of `osv-scanner --format json` (the subset is in `openapi.json`): each result's `source.path`, each
package's `name`, `version` and `ecosystem`, and for each advisory its `id`, `aliases`, `summary`, `severity`,
`database_specific.severity` and the `fixed` version in `affected[].ranges[].events[]`. SARIF 2.1.0 from Trivy, Grype
or `osv-scanner --format sarif` works too: the rule is the advisory and the package comes from the result.

**Severity** is the CVSS v3 base score when the report has one (computed from the vector), then the database's label,
then medium. An advisory nobody rated is not ignored.

## How a scan is compared

- A scan of the **default branch** is the baseline. It adopts what is there and never fails a pipeline, and its
  package list becomes the project's inventory. What it stops reporting is marked fixed (the dependency was updated or
  removed), and opens again if it returns.
- Any other scan, or any scan with `pullRequest`, reports only the advisories the baseline does not have and nobody has
  decided about. `blocking` counts those at or above the project's **fail on** severity (high by default; set under
  the project).
- An advisory is found again by **ecosystem, package, version and advisory id**. Updating a package clears its old
  advisories; adding a vulnerable version, or a different vulnerable version of the same package, is new.
- Decisions stay with the advisory on every branch: **not affected** (the vulnerable code is not used), **false
  positive** and **accepted risk**, each with a reason, and an end date for accepted risk.

**Packages** answers "where is this package used?" from the default branch of every project. osv-scanner lists the
packages that have advisories unless it is asked for all of them, so the inventory is what the report lists.

## Run

```bash
openssl rand -hex 32 > openasy-kek
export AUDIT_INGEST_TOKEN=$(openssl rand -hex 32)
docker compose up -d
docker compose logs audit | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

```bash
osv-scanner --format json --lockfile package-lock.json > osv.json
curl -sf -X POST -H "Authorization: Bearer $AUDIT_INGEST_TOKEN" -H 'content-type: application/json' \
  --data-binary @osv.json \
  "https://audit.example.com/api/v1/scans?project=acme/web&branch=$BRANCH&commit=$SHA&pullRequest=$PR" > scan.json
jq -e '.passed' scan.json
```

`project` and `branch` are required. A new project uses `main` as its default branch unless you send `defaultBranch`.
The body may be gzipped (`Content-Encoding: gzip`), up to 64 MiB unpacked and 50,000 advisories.

`openasy-kek` encrypts sign-in secrets in the database (ADR 0021). Keep it apart from the volume and with your backups.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `AUDIT_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher. Give every product the same value |
| `AUDIT_INGEST_TOKEN` | | Lets CI send scans and nothing else. An API token with the editor role works too |
| `AUDIT_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `AUDIT_DB` | `/data/audit.db` | SQLite file (WAL), on the `/data` volume |
| `AUDIT_RETENTION_DAYS` | `365` | Scans, and fixed advisories nobody decided about, older than this are deleted |
| `AUDIT_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `AUDIT_HEADLESS` | `false` | `true` serves only the API |
| `AUDIT_PASSWORD_SIGN_IN`, `AUDIT_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

## Roles

Viewers see everything; editors also decide about advisories and send scans; admins also change a project's policy and
delete it, and manage members and API tokens (ADR 0003).

## Develop

```bash
npm install
npm test        # report parsing and CVSS scores, the comparison with the baseline, decisions, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).

# SecureChain

A CLI tool that scans an npm `package.json`, checks each dependency against known
vulnerability databases, applies a machine learning layer for contextual risk scoring
and behavioral anomaly detection, explains its scores with SHAP, and emits a
machine-readable JSON report (for a CI/CD gate) plus a self-contained, minimal,
light/dark HTML report, sorted worst-severity-first, for human review.

This is a CI/CD first tool. `scan` always writes its two output files; the intended
flow is push, CI scans, CI blocks or passes, developer reads the report artifact,
fixes or accepts, pushes again, the same shape as Dependabot or `npm audit` in CI,
not a dashboard you keep open. An optional local GUI (see
[GUI_GUIDE.md](GUI_GUIDE.md)) is available as a convenience layer on top of this
same flow, useful for reviewing a scan and pushing without leaving one window, but
it never replaces CI as the actual enforcement point.


## How it actually works, end to end

1. **A developer pushes a commit** (or opens/updates a pull request) to a repo
   that has `.github/workflows/dependency-risk-scan.yml` in it. GitHub sees that
   file and automatically starts the workflow - nobody has to run anything by
   hand, and nothing needs to happen locally first.
2. **`securechain scan` runs inside that GitHub Actions job**, reads
   `package.json`, and for every dependency: looks up its CVE/advisory record,
   checks real-world exploit intelligence (EPSS score and CISA KEV status) when
   a CVE ID exists, pulls 4 behavioral signals from the npm registry, runs them through the
   Random Forest (contextual risk score) and Isolation Forest (behavioral
   anomaly flag), explains both with SHAP, and produces a final severity
   (Safe/Low/Medium/High/Critical). This is written to two files:
   `result/report.json` (machine-readable, for the next step) and
   `result/report.html` (the human-readable GUI).
3. **`securechain check` reads that JSON report** and applies exactly one rule:
   is there any dependency above `--max-severity` (default: only Safe is
   exempt) that does **not** have a matching entry in `.riskignore.json`? If
   yes, it exits with a non-zero code - GitHub shows that job as failed (red)
   and the merge/deploy is blocked. If every non-Safe dependency is either
   genuinely fixed or has a recorded exception, it exits zero (green).
4. **A red job is the signal to act.** The developer opens that failed run on
   GitHub, downloads the `report.html` artifact, and reads it. For each flagged
   dependency, the Recommendation tab says one of: upgrade to version X (a real
   fix exists), no fix exists / apply a manual mitigation, or - for a
   behavioral-only flag with no CVE at all - manually audit this dependency.
5. **The developer makes one of two distinct decisions per flagged dependency**
   (these are not the same thing, and only one of them involves
   `.riskignore.json`):
   - **Fix it**: follow the recommendation, edit `package.json` to the
     suggested version. Nothing needs to change in `.riskignore.json` - the
     next scan will simply find that dependency clean.
   - **Accept it**: deliberately choose to keep the current version anyway
     (no fix exists yet, or the risk doesn't apply to this project's usage),
     and run `securechain accept package@version --reason "..."` to record
     that decision. This is a *different* action from following the
     recommendation, not an alternative way of doing the same thing.
6. **The developer pushes again.** GitHub Actions reruns the whole pipeline
   from scratch, independently, with no memory of the previous run - it
   re-derives the answer purely from whatever is in the manifest and
   `.riskignore.json` at that new commit. Fixed dependencies now show Safe/Low
   and never blocked in the first place; accepted ones show a warning instead
   of a failure; anything neither fixed nor accepted still blocks, exactly as
   before.

This repo actually demonstrates the loop two different ways (see "Demo dataset"
below for the full breakdown): a polished, always-green/always-red **CI
walkthrough** (`demo/package.vulnerable.json` and `demo/package.fixed.json`,
wired into the workflow as 3 separate jobs so you can see pass/fail/exception
side by side on every push), and a **hands-on exercise** (`demo/package.json`,
a single file *not* wired into CI, meant to be edited in place by hand - fix a
dependency, re-scan, see the gate change from fail to pass, exactly like a
real project).

**One caveat about "fixing" a behavioral-only flag**: for a dependency flagged
purely by the Isolation Forest (no CVE at all), the anomaly reflects that
package's *entire* registry history - who has ever maintained it, its whole
release pattern - not the specific version your manifest happens to pin. So
downgrading to an older version does **not** clear a behavioral flag; only
accepting it (or removing the dependency entirely) does. A CVE-based finding,
by contrast, genuinely goes away once you upgrade past the patched version.

**What this does *not* react to**: `securechain` only ever runs when GitHub
tells it to, via the `on: push` / `on: pull_request` triggers in the workflow
file - both are things that happen *on GitHub's servers* (a commit landing on
a branch, or a pull request being opened/updated). Running `git pull` (or
`git fetch`, `git clone`) is a purely local operation on your own machine that
downloads commits *from* GitHub *to* you - GitHub's servers have no visibility
into it at all, so there is no way for any GitHub Actions workflow, from this
tool or any other, to trigger on it. If you want the scan to run when you pull
someone else's changes locally, that would have to be a local pre-pull or
post-merge git hook instead - a different mechanism entirely, not something
this tool sets up.

## Setup

```bash
python -m venv .venv
. .venv/Scripts/activate        # Windows
# source .venv/bin/activate      # macOS/Linux
pip install -e ".[dev]"

# Train the Random Forest classifier and Isolation Forest anomaly detector
# (writes models/classifier.joblib, models/anomaly.joblib, models/baseline_metrics.json)
python scripts/train_models.py

pytest
```

Optional environment variables for live (non-demo) scans:
- `GITHUB_TOKEN` - enables GitHub Advisory Database GraphQL lookups.
- `NVD_API_KEY` - raises the NVD API rate limit (5 req/30s without a key).
- `GITHUB_ACTOR` / `GITLAB_USER_LOGIN` - already set automatically by GitHub
  Actions / GitLab CI; recorded in the report as `scanned_by` so it's always
  clear who triggered a given scan (falls back to the local OS username when
  running outside CI).

## CLI usage

```bash
securechain scan <manifest-path> [--output result/report.json] [--html result/report.html] [--cache-dir DIR] [--offline] [--ignore-file .riskignore.json]
securechain check <report.json> [--max-severity safe] [--ignore-file .riskignore.json]
securechain accept <package>@<version> --reason "<text>" --ignore-file .riskignore.json [--accepted-by NAME]
```

- `scan` runs the full pipeline (manifest parsing, CVE lookup, behavioral feature
  extraction, ML scoring, SHAP explanation, severity labeling, recommendations) and
  writes both reports to `result/` by default (`--output`/`--html` override the path).
- `check` is the CI/CD gate: it reads a JSON report, applies `.riskignore.json`
  exceptions, and exits non-zero if any dependency strictly above `--max-severity`
  (**default `safe`**, i.e. Low/Medium/High/Critical all block) is not covered by an
  exception. Only a genuinely Safe dependency never blocks.
- `accept` records a developer-accepted risk in `.riskignore.json`. It never touches
  code or dependencies - fixing the vulnerability means editing `package.json`
  yourself and re-scanning; `accept` is only for the "we're consciously keeping this"
  path.

### Why every non-Safe tier blocks, not just Critical/High

Most scanners treat only Critical/High as build-breaking, and let Medium/Low pass
silently. This tool's position is: a risk is a risk regardless of tier. An unpatched
Low or Medium-severity dependency can still cause real damage (data exposure,
downstream compromise), and "ignore it, it's only Low" is exactly how a real problem
sits unreviewed indefinitely. So by default nothing short of a genuinely clean
(Safe) dependency passes without either a real fix or a deliberate, recorded, dated
acceptance. `--max-severity` is still there if a project genuinely wants a looser
threshold.

### Try it against the demo manifest

`demo/package.json` is a single, realistic manifest with 15 dependencies (9 clean,
6 flagged at Low/Medium/High/Critical) - there is no separate "vulnerable" and
"fixed" copy. You edit it in place, the same way you'd fix a real project:

```bash
securechain scan demo/package.json --cache-dir demo/fixtures --offline
securechain check result/report.json --ignore-file .riskignore.json
# exits non-zero: colors (Low), minimist, axios (Medium), moment (High), and
# xml2js, node-ipc (Critical) are all unaccepted - 6 failures.

securechain accept colors@1.4.1 --reason "no fix possible, reviewed" --ignore-file .riskignore.json
securechain check result/report.json --ignore-file .riskignore.json
# colors now warns instead of failing; the other 5 unaccepted ones still block.

# Now actually fix the other 5 by editing demo/package.json yourself:
#   minimist  1.2.0 -> 1.2.6
#   axios     1.5.0 -> 1.6.0
#   moment    2.29.1 -> 2.29.4
#   xml2js    0.4.19 -> 0.5.0
#   node-ipc  9.2.1 -> 9.2.2

securechain scan demo/package.json --cache-dir demo/fixtures --offline
securechain check result/report.json --ignore-file .riskignore.json
# exits zero: every CVE-based finding was fixed by upgrading; colors (the one
# behavioral-only, no-CVE flag) is already accepted from the step above.
```

`--cache-dir demo/fixtures` points the scanner at curated offline fixtures for the 15
demo packages (see below) so the walkthrough is deterministic and doesn't depend on
live network access, API tokens, or rate limits. Omit it (and `--offline`) for a real
scan against live NVD / GitHub Advisory / npm registry data.

## Architecture

```
manifest.py        package.json -> [(name, version), ...]
vuln_lookup.py      GitHub Advisory (GraphQL) + NVD clients, cache-first wrapper -> LookupResult
behavioral.py        npm registry/downloads clients -> 4 behavioral features
ml/
  training_data.py    synthetic training data generator (documented labeling rule)
  classifier.py        Random Forest: CVSS + 4 behavioral features -> risk_score in [0,1]
  anomaly.py             Isolation Forest: 4 behavioral features only -> anomaly flag
  explain.py               SHAP TreeExplainer (KernelExplainer fallback for anomaly model)
severity.py          CVSS-based base label + capped one-tier anomaly escalation
recommend.py          upgrade / manual-mitigation / audit / no-action text
riskignore.py          .riskignore.json read/write/match (exact package@version)
gate.py                  check command: exceptions + exit-code decision
pipeline.py                orchestrates the above into one scan
report_json.py               JSON report schema + writer + scanned_by detection
report_html.py                 self-contained light/dark HTML report + Chart.js bar chart
cli.py                            scan / check / accept commands (argparse)
```

### Pipeline flow (per dependency)

1. **Manifest scan** extracts `name@version`.
2. **Vulnerability lookup**: cache (if `--cache-dir` given) -> GitHub Advisory Database
   (version-range aware) -> NVD (best-effort keyword fallback). Never raises; a
   failure degrades to `lookup_status: "lookup_failed"` rather than crashing the scan.
3. **Exploit-intelligence lookup** (only when the vulnerability lookup returned a
   CVE ID, not a GHSA-only identifier): EPSS (FIRST.org's daily-updated predicted
   probability of real-world exploitation in the next 30 days, plus its percentile)
   and CISA KEV catalog membership (confirmed active exploitation). CVSS measures
   potential impact if exploited; it says nothing about whether anyone actually is
   exploiting it, which is the gap this step closes. Same cache-first, never-raises
   design as the vulnerability lookup - degrades to `"not_applicable"` for non-CVE
   identifiers and `"lookup_failed"` on a network/parse error.
4. **Behavioral feature extraction** from npm registry/downloads metadata:
   - `release_frequency_deviation` - coefficient of variation of the gaps between
     consecutive published versions (self-normalizing against a package's own
     typical cadence).
   - `maintainer_count` - size of the current maintainers list.
   - `version_jump_irregularity` - coefficient of variation of the weighted semver
     delta (`major*10000 + minor*100 + patch`) between consecutive chronological
     releases.
   - `download_age_ratio` - weekly downloads / package age in days.
5. **Random Forest** predicts a contextual `risk_score` in `[0, 1]` from CVSS + the
   4 behavioral features.
6. **Isolation Forest** predicts a boolean `anomaly_flagged` from the 4 behavioral
   features only (CVSS is deliberately excluded, so a package can be flagged purely
   on unusual behavior with no CVE at all).
7. **SHAP** explains both model outputs per dependency (`TreeExplainer` for the
   classifier; the anomaly explainer tries `TreeExplainer` first and falls back to
   `KernelExplainer` over `score_samples` if the installed SHAP version doesn't
   support Isolation Forest directly).
8. **Severity labeling**: a base label from standard CVSS ranges (Critical
   9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9, Safe = no advisory record),
   then the anomaly detector may escalate by **exactly one tier, never more** - a
   Safe/no-CVE package can reach Low via anomaly alone, but never Medium or higher.
9. **Recommendation**: upgrade instruction (CVE + fixed version known), manual
   mitigation notice (CVE, no fixed version), behavioral audit notice (anomaly, no
   CVE), or "No action required" (Low/Safe). A KEV-listed CVE gets an urgent prefix
   regardless of severity tier - confirmed active exploitation outranks a CVSS
   bucket.

## JSON report schema

```jsonc
{
  "scan_date": "2026-07-09T00:00:00+00:00",
  "manifest_path": "demo/package.vulnerable.json",
  "scanned_by": "ayush",
  "summary": {"total": 10, "critical": 2, "high": 1, "medium": 3, "low": 2, "safe": 2},
  "dependencies": [
    {
      "package": "xml2js",
      "version": "0.4.19",
      "lookup_status": "ok",              // "ok" | "no_cve" | "lookup_failed"
      "cvss": {"score": 9.8, "cve_id": "GHSA-776f-qq4e-3rc3", "source": "cache", "fixed_version": "0.5.0", "severity_label": null, "summary": "Prototype pollution in xml2js allows attacker-controlled XML input to modify Object.prototype, potentially leading to denial of service or property injection in the host application."},
      "exploit_intel": {"status": "not_applicable", "epss_score": null, "epss_percentile": null, "in_kev": false, "kev_date_added": null, "source": null},
      "behavioral": {"release_frequency_deviation": 0.29, "maintainer_count": 2, "version_jump_irregularity": 0.45, "download_age_ratio": 3565.1, "status": "ok"},
      "risk_score": 0.995,
      "anomaly_flagged": false,
      "base_severity": "Critical",
      "severity": "Critical",
      "escalated": false,
      "recommendation": "Upgrade xml2js to version 0.5.0 or later to remediate GHSA-776f-qq4e-3rc3.",
      "shap": {
        "classifier": {"attributions": [{"feature": "cvss_score", "value": 9.8, "shap_value": 0.41}, "..."], "base_value": 0.1, "model_output": 0.995, "top_feature": "cvss_score", "explanation_text": "Flagged due to a CVE with a CVSS score of 9.8 and ..."},
        "anomaly": {"attributions": ["..."], "base_value": 0.0, "model_output": -0.02, "top_feature": "maintainer_count", "explanation_text": "Not flagged. Primary contributing factors were ..."}
      }
    }
  ]
}
```

`scanned_by` is whichever of `GITHUB_ACTOR`, `GITLAB_USER_LOGIN`, or `CI_COMMIT_AUTHOR`
is set (i.e. the platform-reported identity of whoever triggered the run), falling
back to the local OS username when none of those are present.

`exploit_intel.status` is `"ok"` (EPSS score/percentile and KEV membership were
resolved), `"not_applicable"` (the dependency has no CVE ID to look up - either no
advisory exists, or the advisory is GHSA-only), or `"lookup_failed"` (a network/parse
error; never blocks the scan). `epss_score` is FIRST.org's predicted probability
(0.0-1.0) that this CVE will be exploited in the wild in the next 30 days;
`epss_percentile` ranks it against every other scored CVE. `in_kev` is `true` only
if the CVE is confirmed on CISA's Known Exploited Vulnerabilities catalog - real,
observed exploitation, not a prediction.

`cvss.summary` is the advisory's own plain-language description of the
vulnerability - what an attacker actually gets from it (e.g. "allows an attacker
to modify Object.prototype via a crafted `__proto__` payload"), not just a
number. It's pulled straight from GitHub Advisory Database / the curated fixture
and is `null` when no advisory record exists.

## The HTML report

A single self-contained `.html` file with a minimal light/dark UI (follows your
OS/browser preference by default; a "Toggle theme" button overrides it, remembered
via `localStorage`). Layout:

- **Header** - title, scan date, manifest path, who ran it (`scanned_by`), theme toggle.
- **Stat strip** - total scanned plus one tile per severity tier, the count colored
  with that tier's severity color.
- **Severity Scale legend** - five solid, rounded badges (Safe/Low/Medium/High/
  Critical) as a quick color key.
- **One card per dependency, sorted Critical first down to Safe last** - so whatever
  needs attention is always at the top, regardless of where it happens to sit in the
  manifest. Each card shows the package name, version, an **ACCEPTED** tag (read-only
  - hover for who/when/why) if it's already in `.riskignore.json`, a **KEV** tag if
  the CVE is confirmed on CISA's Known Exploited Vulnerabilities catalog, and a solid
  severity badge, followed by a row of tabs:
  - **Recommendation** - shown by default: which library/version to upgrade to
    when a fix exists, a manual-mitigation notice when it doesn't, or a
    behavioral-audit notice for an anomaly-only flag with no CVE at all. A KEV-listed
    CVE gets an urgent prefix here regardless of severity tier.
  - **CVSS** - score, CVE/GHSA identifier, fixed version, and (when a CVE ID exists)
    exploit intelligence: EPSS score/percentile and CISA KEV status. CVSS alone
    measures potential impact if exploited, not whether anyone actually is
    exploiting it - this is the piece that closes that gap.
  - **Severity** - base severity vs. final severity and *why* (CVSS analysis,
    whether a behavioral anomaly escalated it and by how much), a plain-language
    description of what an attacker could actually do with it (pulled straight
    from the advisory's own summary, when the advisory record has one), and the
    SHAP explanation of what drove the Random Forest's risk score.
  - **Behavioral** - the 4 raw behavioral features, the anomaly flag, and the
    SHAP explanation of *why* the Isolation Forest did or didn't consider this
    pattern suspicious (e.g. a single maintainer plus an irregular version jump).
- **Chart.js bar chart** - dependency count per severity tier.

There is no interactive action anywhere in the file beyond the theme toggle and tab
switching - no button writes to disk, no form submits anywhere. Reviewing a flagged
dependency and deciding what to do about it happens outside this file: edit
`package.json` to fix it, or run `securechain accept` to record a deliberate
exception, then push again.

Color is a fixed, reserved 5-step traffic-light scale - green Safe, blue Low, amber
Medium, orange High, red Critical - used only for severity (badges, stat-tile
numbers, and the matching Chart.js bars). Each color's badge text (white, or dark
text for the lighter amber Medium) was chosen by checking WCAG contrast (>= 4.5:1)
against that exact fill, not eyeballed. Everything else in the report (cards, tabs,
panels, the theme itself) uses a small neutral palette of grays - tinted slightly
warm or cool for a polished look the way real design systems do, never a hue - so
severity is still the only *meaningful* color in the document. Tab switching and the
theme toggle are one small inline vanilla-JS block, so the only external reference
remains the Chart.js CDN `<script src="...">` tag - the file still opens directly by
double-clicking, no build step, no server.

## `.riskignore.json` exception mechanism

```json
{
  "exceptions": [
    {"package": "colors", "version": "1.4.1", "reason": "No fix possible for a behavioral-only flag with no CVE; reviewed and accepted.", "date": "2026-07-10", "accepted_by": "your-name"}
  ]
}
```

Matching is exact on `package` + `version`. Upgrading (or downgrading) to a
different, still-vulnerable version is **not** covered by an old entry - a new
exception has to be recorded deliberately via `securechain accept`. This repo's own
`.riskignore.json` carries exactly one entry, `colors@1.4.1` - a genuinely
unfixable, behavioral-only flag with no CVE, permanently accepted rather than
blocking every scan forever. As you work through `demo/package.json` yourself,
you'll add further entries the same way, exactly as a real project would.

**Trade-off worth naming explicitly**: this mechanism is only as good as the
discipline behind it. It solves "don't let something ship completely
unreviewed," not "guarantee every acceptance was actually a good decision" -
nothing stops a team from rubber-stamping every finding just to make the gate
pass, which would defeat the entire point. The tool enforces *that a reason
and a name are on record*; it cannot enforce that the reason is a good one.
That's a process/culture problem no tool can fully solve, and worth
acknowledging as a limitation rather than a solved problem.

## Offline demo fixtures

`demo/fixtures/` contains curated cache files (`advisories.json`, `npm_metadata.json`,
`npm_downloads.json`, `exploit_intel.json`) for the 15 demo packages, referencing
real CVE/GHSA IDs where they exist (`CVE-2020-7598` for minimist, `CVE-2023-45857`
for axios, `CVE-2022-31129` for moment, a curated critical-severity xml2js
prototype-pollution record, and `GHSA-lzc9-3d29-fq7f` for the real node-ipc
"protestware" incident). `exploit_intel.json` holds real EPSS scores/percentiles
(pulled from FIRST.org's public API) and real CISA KEV membership checks for the
three CVE-identified packages, captured on 2026-07-09 - EPSS updates daily, so a
live re-lookup will return slightly different numbers over time; this is a
snapshot for deterministic demo/CI runs, not a claim of permanent accuracy.
xml2js and node-ipc use GHSA identifiers with no CVE ever assigned, so they have
no entry here - EPSS and KEV are both indexed strictly by CVE ID, and the report
surfaces this as `"not_applicable"` rather than a failed lookup.
`--cache-dir demo/fixtures` makes `scan` consult these before falling back to live
APIs (or, with `--offline`, skip live APIs entirely). This keeps the demo walkthrough
and CI runs deterministic regardless of live rate limits, tokens, or advisory data
changing over time. Omit both flags for a real scan against live data.

## Demo dataset

`demo/package.vulnerable.json` / `demo/package.fixed.json` - the pair wired
into the 3-job GitHub Actions workflow so pass/fail/exception are always
visible side by side on every push - carry 20 packages spanning all 5
severity tiers:

| Package | Version | Expected severity | Why |
|---|---|---|---|
| lodash | 4.17.21 | Safe | No known CVE, unremarkable behavioral profile. |
| chalk | 5.3.0 | Safe | No known CVE, healthy maintainer pool, unremarkable behavioral profile. |
| uuid | 9.0.1 | Safe | No known CVE, unremarkable behavioral profile. |
| debug | 4.3.4 | Safe | No known CVE, unremarkable behavioral profile. |
| semver | 7.5.4 | Safe | No known CVE, unremarkable behavioral profile. |
| commander | 11.1.0 | Safe | No known CVE, unremarkable behavioral profile. |
| dotenv | 16.3.1 | Safe | No known CVE, unremarkable behavioral profile. |
| yargs | 17.7.2 | Safe | No known CVE, unremarkable behavioral profile. |
| picocolors | 1.0.0 | Safe | No known CVE, unremarkable behavioral profile. |
| colors | 1.4.1 | Low | No CVE was ever filed - in January 2022 the maintainer intentionally sabotaged this exact version (and the related `faker` package) as a protest, breaking countless builds. A single maintainer and a sharply irregular release history trigger the one-tier anomaly escalation from Safe. There's no fixed version to upgrade to (it wasn't a code vulnerability); it can only be resolved by accepting it in `.riskignore.json` or removing the dependency - downgrading does **not** clear it, since the anomaly reflects the package's whole registry history, not the pinned version. |
| minimist | 1.2.0 | Medium | Known CVE (CVE-2020-7598, prototype pollution), CVSS 5.6, fix available in 1.2.6. |
| axios | 1.5.0 | Medium | Known CVE (CVE-2023-45857, cross-origin cookie leak via redirected proxy auth), CVSS 6.5, fix available in 1.6.0. |
| word-wrap | 1.2.3 | Medium | Known CVE (CVE-2023-26115, ReDoS when trimming input), CVSS 5.3, fix available in 1.2.4. |
| moment | 2.29.1 | High | Known CVE (CVE-2022-31129, ReDoS in date parsing), CVSS 7.5, fix available in 2.29.4. |
| ansi-regex | 5.0.0 | High | Known CVE (CVE-2021-3807, ReDoS matching invalid ANSI escape codes), CVSS 7.5, fix available in 5.0.1. |
| glob-parent | 5.1.1 | High | Known CVE (CVE-2020-28469, ReDoS in the enclosure regex), CVSS 7.5, fix available in 5.1.2. |
| json5 | 2.2.1 | High | Known CVE (CVE-2022-46175, prototype pollution via `__proto__` keys), CVSS 7.1, fix available in 2.2.2. |
| tar | 6.1.0 | High | Known CVE (CVE-2021-32804, arbitrary file creation/overwrite via insufficiently sanitized absolute paths), CVSS 8.2, fix available in 6.1.1. |
| xml2js | 0.4.19 | Critical | Known prototype-pollution advisory, curated at CVSS 9.8 for this walkthrough, fix available in 0.5.0. |
| node-ipc | 9.2.1 | Critical | Known advisory (GHSA-lzc9-3d29-fq7f, the 2022 "protestware" incident: geo-targeted destructive file writes), curated at CVSS 9.8, fix available in 9.2.2. |

None of the 5 CVEs added above (or the 3 added earlier) are listed on CISA's KEV catalog - verified directly against the live catalog, not assumed.

`demo/package.json` is a separate, smaller 15-dependency manifest meant for a
hands-on manual exercise (see "Try it against the demo manifest" above) - it
is intentionally not kept in lockstep with the 20-package CI pair above, since
it's meant to be edited by hand, not regenerated.

The committed `.riskignore.json` carries one real, permanent entry:
`colors@1.4.1` (no possible fix, so it's accepted rather than blocking every
scan forever). Scanning `demo/package.vulnerable.json` and running `check`
exits non-zero with 10 failures (colors itself just logs a warning, already
covered); scanning `demo/package.fixed.json` (the other 10 dependencies
upgraded to the versions above) exits zero. `demo/package.json` starts out
identical to the vulnerable manifest - work through it by hand, following the
"Try it against the demo manifest" walkthrough above, to reach the same
clean-pass result yourself.

## How this differs from Dependabot / Snyk / `npm audit` / Sonatype Nexus Lifecycle / JFrog Xray

Being honest about scope first: those tools have vastly larger, continuously
updated vulnerability databases, cover many ecosystems (not just npm), and are
maintained by dedicated security teams - this is a research prototype, not a
production competitor on raw coverage. It's also important to be precise about
*which* claims still hold against *which* competitor - some capabilities that
distinguish SecureChain from Dependabot/`npm audit` are already present, and in
some cases more mature, in Snyk and JFrog Xray specifically. Overstating the
gap against those two would not survive scrutiny, so this section is scoped
tool by tool rather than as one blanket claim.

**Against Dependabot and `npm audit`** (both are close to pure CVE/GHSA-database
lookups, no ML layer, no exploit-likelihood signal):
- **Detects risk that has no CVE yet.** If no CVE/GHSA record has been published
  for a package, Dependabot and `npm audit` have nothing to say about it.
  SecureChain's Isolation Forest scores *behavioral* signals (release-cadence
  irregularity, maintainer concentration, version-jump anomalies,
  download-to-age ratio) that can flag a compromised package before anyone has
  filed an advisory (see colors and node-ipc in the demo dataset - both real
  incidents where behavior looked wrong well before, or entirely without, a
  clean CVSS-scored CVE).
- **Adds the exploit-likelihood axis they lack.** Neither Dependabot nor
  `npm audit` incorporates EPSS or CISA KEV; both report a CVSS/GHSA severity
  and stop there. SecureChain looks up FIRST.org's EPSS score and CISA KEV
  status for every CVE-identified dependency, with a KEV hit overriding the
  recommendation regardless of severity tier.
- **Platform-agnostic and account-free.** Dependabot is tied to GitHub's
  infrastructure. SecureChain's gate is a CLI exit code, runs identically in
  any CI platform, and works fully offline with zero account required.

**Against Snyk and JFrog Xray - correcting an overstatement.** Both already
incorporate EPSS and exploit-maturity signals into their own risk/priority
scoring, and both perform **reachability analysis** (checking whether your own
code actually calls the vulnerable function) - something SecureChain does not
do at all, so a vulnerable version is treated as equally risky whether or not
the vulnerable code path is ever invoked. Neither "adds an exploit-likelihood
axis" nor "detects pre-CVE risk" can honestly be claimed as an edge over these
two specifically. What still stands:
- **An open, published, deterministic scoring rule**, not a proprietary
  formula. Snyk's Risk Score and Xray's policy engine are black boxes from the
  outside; SecureChain's severity fusion (CVSS-authoritative, anomaly
  escalation capped at exactly one tier, never a downgrade) is inspectable
  source code, not a vendor-internal weighting.
- **Formal SHAP additive attribution**, not a factor checklist. Snyk shows
  which factors (reachability, EPSS, social trends, ...) contributed to a
  score; SecureChain's SHAP values are a mathematically consistent
  decomposition (base value + sum of per-feature contributions = model
  output) for both the Random Forest and the Isolation Forest.
- **No vendor lock-in.** Free, self-hostable, fully offline-capable, no
  account or API key, source fully readable.
- **A git-native audit trail.** `.riskignore.json` is a plain file reviewed in
  the same pull requests as the code, not a record inside a vendor's hosted
  dashboard.

**Against Sonatype Nexus Lifecycle - a different mechanism, not a strictly
weaker one.** Nexus Lifecycle's Repository Firewall proactively blocks
malicious/typosquat/policy-violating packages *at install time*, backed by a
curated threat-intelligence database (Sonatype reported 454,648 newly
identified malicious packages in 2025 alone, over 1.2 million cumulative since
2019). That is a more mature, larger-scale version of the same goal
SecureChain's Isolation Forest is going after with 4 behavioral features and
no curated malicious-package database behind it - this is an honest
disadvantage, not a wash. What SecureChain still offers that Nexus Lifecycle
doesn't publish: the same three points above (open scoring rule, formal SHAP
attribution, git-native audit trail) plus the fact that SecureChain's
detection runs entirely on public data (npm registry, GitHub Advisory, NVD,
EPSS, CISA KEV) with no proprietary threat-intel subscription required.

**A portable, diffable audit trail** (holds against all five): Dependabot's
"dismiss alert" and Snyk/Xray/Nexus's dashboards all keep exception decisions
inside the vendor's own system. `.riskignore.json` is a plain file in the same
repo as the code, with an exact package+version match, a reason, a date, and a
name on every entry - it travels with the codebase, not with any vendor.

## Methodology notes (for the thesis Evaluation chapter)

- **Synthetic training data**: no real labeled corpus of (CVSS + behavioral features)
  to risk-label mappings exists for this project. Both models are trained on a
  documented synthetic dataset (`securechain/ml/training_data.py`): CVSS and the 4
  behavioral features are sampled from distributions chosen to span realistic
  real-world scales (including very popular, high-download packages), and the
  supervised label is assigned by a deterministic rule (CVSS >= 4.0, or at least 2 of
  the 4 behavioral features are statistical outliers). This is a methodology
  limitation, not a claim of real-world label accuracy; the regression test
  (`tests/test_classifier.py`) guards against silent degradation of this synthetic
  baseline across future changes, not against real-world drift.
- **Severity engine is rule-based, not ML-driven**: the CI/CD gate decision depends
  only on CVSS-derived severity plus the capped anomaly escalation, not directly on
  the Random Forest's `risk_score`. This keeps the gate deterministic and explainable;
  `risk_score` is reported as additional context alongside `severity`, not a
  replacement for it.
- **NVD keyword matching is best-effort**: NVD's CPE dictionary is not reliably
  version-matched to npm package names, so `NVDClient` is used only as a fallback
  when GitHub Advisory Database (which is version-range aware for the npm ecosystem)
  has no record.
- **"Exploit prediction" scope**: SecureChain does not train its own exploit-prediction
  model. It investigates and integrates FIRST.org's existing EPSS model and CISA's
  KEV catalog - both established, published techniques - rather than building a novel
  predictive model from scratch. This project's ML contribution is the dependency risk
  classifier (Random Forest) and the behavioral anomaly detector (Isolation Forest);
  exploit-likelihood is sourced from, not modeled by, this project.

## Possible extensions

Ideas that fit the tool's scope but aren't built, roughly in order of value:

- **Bulk triage from the CLI**: `securechain accept` handles one package at a time;
  an interactive terminal prompt that walks through every unaccepted flagged
  dependency in one pass would speed up a first review of a large manifest.
- **Expiring exceptions**: an optional `expires` date on a `.riskignore.json` entry,
  checked by `check`, so an accepted risk doesn't silently stay accepted forever
  after the "we'll fix it next sprint" reason has gone stale.
- **PR comment integration**: the GitHub Actions workflow could post the
  Recommendation text for any newly-introduced blocking dependency as a PR comment
  (via `gh pr comment` or the GitHub API), so a reviewer sees the actionable fix
  without opening the HTML artifact.
- **Hosted report via GitHub Pages**: publishing `report.html` to a real URL after
  each run would make it viewable without downloading the artifact. Static hosting
  only, though - no write-back mechanism, since GitHub Pages can't run server code;
  any "act on this from the web" feature would need a real backend (e.g. a button
  that opens a pull request via the GitHub API), which is a materially bigger
  feature than anything else on this list.
- **Lockfile-aware scanning**: reading `package-lock.json`/`npm-shrinkwrap.json`
  instead of (or alongside) `package.json` would scan the exact resolved versions
  actually installed, including transitive dependencies, rather than the top-level
  ranges declared in the manifest - a meaningfully bigger scope change than
  anything above, which is why it's last on this list.

## Test suite

`pytest` covers, per the methodology categories used in this project's evaluation:
manifest parsing, vulnerability lookup (mocked APIs + graceful degradation),
behavioral feature extraction, classifier evaluation + regression baseline, anomaly
detection (obvious-outlier and false-positive-rate tests), SHAP additivity and
top-feature-consistency checks, the severity engine's escalation-cap rule,
recommendation text generation, the `.riskignore.json` exception mechanism
(including version-specificity), the CI/CD gate's integration behavior (including
the default safe-only threshold), the HTML report's structure, sorting, and
color scoping, and one full end-to-end regression test tying the pipeline together
against the documented demo table above.

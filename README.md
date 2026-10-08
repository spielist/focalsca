# FocalSCA

A Software Composition Analysis (SCA) tool for Gradle projects, designed for CI/CD pipeline integration, focused on making every finding actionable.

Most SCA tools produce long lists of vulnerable dependencies and leave developers to figure out what to do about them. FocalSCA is designed differently — every design decision is in service of giving a developer exactly what they need to fix a real problem, nothing more.

---

## What Makes FocalSCA Different

### Actionable Reporting
FocalSCA organizes its findings around what a developer can actually remediate. Vulnerable dependencies are grouped under the top-level artifact, so the developer knows exactly which entry in `build.gradle` to update without having to trace the entire dependency tree manually. In SARIF output, each finding points at the line in the build file where that top-level artifact is declared.

### Iterative Fix Version Verification
For each vulnerable top-level dependency, FocalSCA does not simply report the first available fix version. It takes the highest fixed version published in the OSV advisories, then queries OSV again to check whether that version has known vulnerabilities of its own. If it does, FocalSCA repeats the process with that version's fixes, up to five levels deep.

Two fix version recommendations are reported per artifact:

- **Best same-major fix** — the best fix version within the installed major version. Staying within a major version usually carries a lower risk of breaking changes, though not every library follows semantic versioning.
- **Best cross-major fix** — the best fix version across all major versions, shown when there is no same-major fix, or when it is in a higher major version than the same-major recommendation.

Each recommendation includes a severity breakdown of any known vulnerabilities that remain in that version. Fix recommendations are shown in the `console_tree` output format.

Fix versions are recommended only for top-level artifacts that have vulnerabilities of their own. A vulnerability in a transitive dependency is reported against the top-level artifact that brings it in, but no fix version is suggested for it (see [Known Limitations](#known-limitations)).

### Fix Verification and Patched Build Files
With `--fix-mode`, FocalSCA can go a step further with the recommended fix versions:

- **`verify`** — resolves each recommended version with Gradle and scans its full transitive dependency tree, so you can see whether the upgrade brings in vulnerable dependencies of its own. The fix version is resolved on its own, not within your project's complete dependency graph, so your project's conflict resolution may still select different transitive versions.
- **`apply`** — writes copies of the affected build files, with the recommended versions substituted, to the work directory. Fix versions that Gradle cannot resolve are skipped. Your project's own files are never modified.
- **`verify_and_apply`** — both.

`--upgrade-policy` selects which recommendation (same-major or cross-major) `--fix-mode` uses.

### Non-Invasive Scanning
No changes to the target project's files. No plugin installation, no `build.gradle` modification, no files committed to source control. FocalSCA injects a Gradle init script at scan time via the Gradle Tooling API — the same mechanism IDEs use for project import. As with any Gradle invocation, Gradle may create its `.gradle/` cache directory in the project root if one is not already there.

---

## Key Features

- **Gradle-native dependency resolution** — uses the Gradle Tooling API to resolve the full transitive dependency graph including conflict resolution, rather than statically parsing `build.gradle`. What you scan is what actually runs.
- **OSV.dev integration** — vulnerability matching against the [OSV.dev](https://osv.dev) database, which aggregates GitHub Security Advisories, NVD, and other sources with structured, machine-parseable advisory data.
- **CVSS-based severity** — severity is computed from the advisory's CVSS v3 vector (or v2 if no v3 vector is published), falling back to the severity label assigned by the advisory database.
- **Multi-project builds** — every subproject is scanned, and each finding is attributed to the build file that declares the dependency.

---

## Requirements

- Java 17 or later
- Network access to `api.osv.dev`, and to the repositories the target project resolves its dependencies from

---

## Building and Running

```
./gradlew build
```

FocalSCA does not yet ship as a packaged distribution. Run the main class, `com.focalsca.cli.Main`, from your IDE or with the project's runtime classpath:

```
java -cp <classpath> com.focalsca.cli.Main --project /path/to/gradle/project
```

### Options

| Option | Default | Description |
|---|---|---|
| `--project <path>` | *(required)* | Root directory of the Gradle build to scan (the directory containing `settings.gradle`). |
| `--output-format <format>` | `console` | `console` (flat), `console_tree` (grouped by top-level artifact, with fix recommendations), or `sarif`. |
| `--fail-on <severity>` | `high` | Lowest severity that causes exit code `1`: `critical`, `high`, `medium`, or `low`. |
| `--warn-only` | off | Report findings but exit with `0`. A scan that fails still exits with `2`. |
| `--upgrade-policy <policy>` | `same_major` | `same_major` or `any`. Selects which fix recommendation `--fix-mode` uses. |
| `--fix-mode <mode>` | `none` | `none`, `verify`, `apply`, or `verify_and_apply`. See [Fix Verification and Patched Build Files](#fix-verification-and-patched-build-files). |
| `--work-dir <path>` | `./temp` | Directory for temporary files and patched build files. Created if it does not exist. |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no findings at or above `--fail-on` (or `--warn-only` was set). |
| `1` | Scan completed; at least one finding at or above `--fail-on`. |
| `2` | Scan did not complete (for example, OSV.dev could not be reached, or Gradle failed). No result should be assumed. |

### Output Files

- **`results.sarif`** — written to the current directory when `--output-format sarif` is used.
- **`fixcandidates.sarif`** — the scan of the recommended fix versions, written with `--fix-mode verify` or `verify_and_apply`. With a console format, this scan is printed as a second report instead.
- **`<work-dir>/fixed…/`** — patched copies of the build files, written with `--fix-mode apply` or `verify_and_apply`. The directory layout mirrors the project (for example, `app/build.gradle`).

---

## GitHub Code Scanning

SARIF output can be uploaded to GitHub's Security tab:

```yaml
permissions:
  security-events: write

steps:
  - uses: actions/checkout@v4
  - name: Run FocalSCA
    run: java -cp <classpath> com.focalsca.cli.Main --project . --output-format sarif --warn-only
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: results.sarif
```

Use `--warn-only` as shown to let the upload step report findings without failing the job, or drop it to fail the build on findings at or above `--fail-on`.

---

## Security Considerations

- **Scanning runs the target project's build.** Gradle executes a project's build scripts when it resolves dependencies, so scanning a project runs its code. Do not scan repositories you do not trust.
- **Dependency coordinates are sent to OSV.dev.** Every dependency's group, artifact, and version is sent to the public OSV.dev API, including internal or private artifact names. Consider this before scanning proprietary projects.

---

## Known Limitations

- **No fix recommendations for transitive vulnerabilities.** They are reported, attributed to the top-level artifact that introduces them, but no fix version is suggested.
- **Fix versions may not be obtainable.** OSV sometimes lists fixed versions that are not publicly published (for example, commercial-only releases). `--fix-mode verify` and `apply` detect these because Gradle cannot resolve them.
- **Build file line numbers are best-effort.** The declaring line is found by text search, so dependencies declared through version catalogs, variables, BOMs, or in other files are reported against the build file without a line number, and are not patched by `--fix-mode apply`.
- **CVSS v4.** Advisories that publish only a CVSS v4 vector use the advisory database's severity label, or `MEDIUM` if none is given.
- **SARIF rule metadata.** SARIF output does not yet include rule descriptions or GitHub `security-severity` scores.
- **Only `runtimeClasspath` is scanned.** Compile-only, annotation processor, and test dependencies are not included.

---

## A Note on Reachability Analysis

FocalSCA deliberately does not implement reachability analysis — the determination that a vulnerable method is unreachable via static call graph traversal. In real-world Java applications, reflection, dynamic dispatch, and runtime-generated bytecode (CGLIB, Spring proxies) create enough false negatives that a reachability verdict cannot be stated with the confidence a security finding requires. A tool that tells you a vulnerability is unreachable when it may not be is more dangerous than one that flags it for human review. FocalSCA instead focuses on making every finding easier to understand and act on.

---

## Roadmap

- **Persistent CVE cache** — OSV.dev query results are cached locally with a configurable TTL, reducing redundant network calls across pipeline runs and avoiding rate limit issues when scanning large dependency trees.
- **Scan performance transparency** — reports cache hit rate and total scan time, so you can see the cost of each scan and tune the cache TTL accordingly.
- **Fix version inference for transitive vulnerabilities** — when a top-level artifact has no direct CVEs but introduces a vulnerable transitive dep, query Maven Central metadata to identify the lowest version of the top-level artifact that ships a patched version of the transitive dep.
- **Alternative library suggestions** — for abandoned or persistently vulnerable dependencies, suggest replacement libraries via retrieval-augmented generation, grounded in current ecosystem data rather than model training knowledge.
- **Compatibility warnings** — cross-reference your application's actually-called API surface against the target upgrade version's class/method signatures to flag breaking changes before you upgrade.
- **Maven support** — extend dependency extraction to Maven projects via the Maven Embedder API; CVE matching and reporting are build-system-agnostic and will carry over unchanged.
- **Android support** — handle Gradle build variant configurations (`releaseRuntimeClasspath`, `debugRuntimeClasspath`, etc.) for Android projects.
- **Custom Gradle Tooling Model** — replace the current init script + JSON approach with a typed Tooling API model provider for cleaner integration and richer dependency metadata.
- **Per-branch fix version resolution** — OSV advisories sometimes publish fix versions per version branch (e.g., 5.2.x and 5.3.x separately); a future version will query Maven Central to confirm which branch applies to the installed version before recommending an upgrade.
- **Batch OSV queries** — replace the current per-dependency query approach with the `/v1/querybatch` endpoint, which accepts up to 1,000 package queries per request. A 2,000-dependency project would resolve in two batch calls plus a small number of detail fetches, significantly reducing scan latency at enterprise scale.
- **Dead dependency detection** — ASM-based bytecode scanning identifies dependencies with no direct references in your application's compiled output, flagged as lower-priority candidates for removal. Note: as with all static bytecode analysis, dependencies used exclusively via reflection or runtime injection may be incorrectly flagged; findings should be verified before removing a dependency.

---

## Scope

**v1 targets:** Gradle projects using standard Java or Java Library plugins, `runtimeClasspath` configuration, JVM bytecode compiled to `.class` files.

**Out of scope for v1:** Maven projects, Android projects, Kotlin Multiplatform, Groovy or Scala source analysis, dynamic class loading patterns.

---

## License

Licensed under the [Apache License 2.0](LICENSE).

#!/usr/bin/env node
/**
 * CI/CD Leaderboard Scorer
 *
 * Scans student repos via GitHub API and produces scores.json
 * Usage: GITHUB_TOKEN=xxx node score.mjs
 */

import { readFileSync, writeFileSync, mkdirSync } from "fs";

const TOKEN = process.env.GITHUB_TOKEN;
if (!TOKEN) { console.error("GITHUB_TOKEN required"); process.exit(1); }

const API = "https://api.github.com";
const headers = {
  Authorization: `Bearer ${TOKEN}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
};

// ---------------------------------------------------------------------------
// GitHub API helpers
// ---------------------------------------------------------------------------

async function gh(path) {
  const res = await fetch(`${API}${path}`, { headers });
  if (!res.ok) return null;
  return res.json();
}

async function ghRaw(owner, repo, path) {
  const res = await fetch(
    `https://raw.githubusercontent.com/${owner}/${repo}/main/${path}`,
    { headers }
  );
  if (!res.ok) return null;
  return res.text();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Count comment lines vs code lines in source files.
 * Supports Python (#) and JS/TS (single-line and block comments)
 */
function countComments(content, lang) {
  const lines = content.split("\n");
  let comments = 0;
  let code = 0;
  let inBlock = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (lang === "python") {
      if (trimmed.startsWith("#")) { comments++; }
      else if (trimmed.startsWith('"""') || trimmed.startsWith("'''")) {
        const delim = trimmed.slice(0, 3);
        if (inBlock) { comments++; inBlock = false; }
        else if (trimmed.indexOf(delim, 3) !== -1) { comments++; }
        else { comments++; inBlock = true; }
      } else if (inBlock) { comments++; }
      else { code++; }
    } else {
      if (inBlock) {
        comments++;
        if (trimmed.includes("*/")) inBlock = false;
      } else if (trimmed.startsWith("//")) { comments++; }
      else if (trimmed.startsWith("/*")) {
        comments++;
        if (!trimmed.includes("*/")) inBlock = false;
        inBlock = !trimmed.includes("*/");
      } else { code++; }
    }
  }
  return { comments, code, total: comments + code };
}

/** Get all workflow file contents for a repo */
async function getWorkflows(owner, repo) {
  const tree = await gh(`/repos/${owner}/${repo}/git/trees/main?recursive=1`);
  if (!tree?.tree) return { tree: null, workflows: [] };
  const wfPaths = tree.tree
    .filter((f) => f.path.startsWith(".github/workflows/") && (f.path.endsWith(".yml") || f.path.endsWith(".yaml")))
    .map((f) => f.path);
  const workflows = [];
  for (const p of wfPaths) {
    const content = await ghRaw(owner, repo, p);
    if (content) workflows.push({ path: p, content });
  }
  return { tree, workflows };
}

// ---------------------------------------------------------------------------
// Helper: get last CI run (ignoring Dependabot, CodeQL, scheduled updates)
// ---------------------------------------------------------------------------

async function getLastCIRun(owner, repo) {
  const pushRuns = await gh(`/repos/${owner}/${repo}/actions/runs?branch=main&per_page=10&event=push`);
  const filterCI = (runs) => (runs?.workflow_runs || []).filter((r) =>
    r.status === "completed" &&
    !r.name.toLowerCase().includes("dependabot") &&
    !r.name.toLowerCase().includes("codeql") &&
    !r.name.toLowerCase().includes("update #")
  );

  let ciRuns = filterCI(pushRuns);
  if (ciRuns.length) return ciRuns[0];

  const allRuns = await gh(`/repos/${owner}/${repo}/actions/runs?branch=main&per_page=10`);
  ciRuns = filterCI(allRuns);
  return ciRuns.length ? ciRuns[0] : null;
}

// ---------------------------------------------------------------------------
// findGreenStep — searches cached lastRunJobs for green jobs/steps by keyword
// ---------------------------------------------------------------------------

function findGreenStep(ctx, keywords) {
  if (!ctx.lastRun || ctx.lastRun.conclusion !== "success") {
    return { found: false, run: ctx.lastRun };
  }
  if (!ctx.lastRunJobs || ctx.lastRunJobs.length === 0) {
    return { found: false, run: ctx.lastRun };
  }

  for (const job of ctx.lastRunJobs) {
    const jn = job.name.toLowerCase();
    for (const kw of keywords) {
      if (jn.includes(kw) && job.conclusion === "success") {
        return { found: true, detail: `Job "${job.name}" green ✅`, run: ctx.lastRun };
      }
    }
    for (const step of (job.steps || [])) {
      const sn = step.name.toLowerCase();
      for (const kw of keywords) {
        if (sn.includes(kw) && step.conclusion === "success") {
          return { found: true, detail: `Step "${step.name}" in "${job.name}" green ✅`, run: ctx.lastRun };
        }
      }
    }
  }
  return { found: false, run: ctx.lastRun };
}

// ---------------------------------------------------------------------------
// Coverage badge helper
// ---------------------------------------------------------------------------

/** Trusted coverage badge providers — only these are accepted */
const TRUSTED_BADGE_PROVIDERS = [
  { pattern: /codecov\.io\/gh\/[^/]+\/[^/]+/, name: "Codecov" },
  { pattern: /coveralls\.io\/repos\/github\/[^/]+\/[^/]+/, name: "Coveralls" },
  { pattern: /sonarcloud\.io\/api\/project_badges\/measure.*metric=coverage/, name: "SonarCloud" },
  { pattern: /codeclimate\.com\/github\/[^/]+\/[^/]+\/badges/, name: "CodeClimate" },
  { pattern: /app\.codacy\.com\/project\/badge\/Coverage/, name: "Codacy" },
];

/**
 * Parse coverage % from a README badge.
 * Returns { coverage: number, provider: string } or null.
 */
async function parseCoverageBadge(owner, repo) {
  const readme = await ghRaw(owner, repo, "README.md");
  if (!readme) return null;

  const imgRegex = /!\[[^\]]*\]\(([^)]+)\)/g;
  const htmlImgRegex = /<img[^>]+src="([^"]+)"/g;
  const urls = [];
  let m;
  while ((m = imgRegex.exec(readme))) urls.push(m[1]);
  while ((m = htmlImgRegex.exec(readme))) urls.push(m[1]);

  for (const url of urls) {
    const provider = TRUSTED_BADGE_PROVIDERS.find((p) => p.pattern.test(url));
    if (!provider) continue;

    try {
      const res = await fetch(url, { headers: { Accept: "image/svg+xml" } });
      if (!res.ok) continue;
      const svg = await res.text();

      const pctMatch = svg.match(/(\d{1,3}(?:\.\d+)?)\s*%/);
      if (pctMatch) {
        return { coverage: parseFloat(pctMatch[1]), provider: provider.name, url };
      }
    } catch {
      continue;
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Coverage log parsing helper
// ---------------------------------------------------------------------------

async function parseCoverageFromLogs(owner, repo, jobId) {
  const res = await fetch(`${API}/repos/${owner}/${repo}/actions/jobs/${jobId}/logs`, { headers, redirect: "follow" });
  if (!res.ok) return null;
  const logs = await res.text();

  // Jest: "All files | 87.32 |"
  const jestMatch = logs.match(/All files[^|]*\|\s*([\d.]+)\s*\|/);
  if (jestMatch) return parseFloat(jestMatch[1]);

  // Pytest: "TOTAL ... 87%"
  const pytestMatch = logs.match(/TOTAL\s+\d+\s+\d+\s+(\d+)%/);
  if (pytestMatch) return parseFloat(pytestMatch[1]);

  // Generic: "Coverage: 87.5%" or "coverage: 87.5%"
  const genericMatch = logs.match(/coverage[:\s]+(\d+\.?\d*)%/i);
  if (genericMatch) return parseFloat(genericMatch[1]);

  return null;
}

// ---------------------------------------------------------------------------
// Individual checks — each returns { pass: bool, detail: string }
// ---------------------------------------------------------------------------

const CHECKS = {
  // ===== FUNDAMENTALS (60 pts) =====

  pipeline_exists: {
    points: 5,
    category: "fundamentals",
    label: "Pipeline exists",
    run: async (owner, repo, _team, ctx) => {
      return {
        pass: ctx.workflows.length > 0,
        detail: `${ctx.workflows.length} workflow(s) found`,
      };
    },
  },

  pipeline_green: {
    points: 5,
    category: "fundamentals",
    label: "Pipeline green on main",
    run: async (owner, repo, _team, ctx) => {
      const last = ctx.lastRun;
      if (!last) return { pass: false, detail: "No CI runs found" };
      return {
        pass: last.conclusion === "success",
        detail: `Last run: ${last.conclusion} (#${last.run_number} — ${last.name})`,
      };
    },
  },

  lint_pass: {
    points: 5,
    category: "fundamentals",
    label: "Lint step in pipeline",
    run: async (owner, repo, _team, ctx) => {
      const result = findGreenStep(ctx, ["lint", "linter", "format", "eslint", "ruff", "flake8", "prettier", "biome", "style", "check"]);
      if (result.found) {
        return { pass: true, detail: result.detail };
      }
      return { pass: false, detail: "No green lint/format job or step found in last CI run" };
    },
  },

  no_secrets_in_code: {
    points: 5,
    category: "fundamentals",
    label: "No hardcoded secrets",
    run: async (owner, repo, _team, ctx) => {
      const staticFiles = [
        "main.py", "app.js", "app.py", "main.js", "server.js", "index.js",
        "database/database.py", "database/database.js",
        "routers/todo.py", "routes/todo.js",
        "config.py", "config.js", "settings.py",
        "src/app.js", "src/main.js", "src/index.js", "src/server.js",
      ];
      const treeFiles = (ctx.tree?.tree || [])
        .filter((f) => (f.path.endsWith(".py") || f.path.endsWith(".js") || f.path.endsWith(".ts")) &&
          !f.path.includes("node_modules") && !f.path.includes("test") && !f.path.includes(".github"))
        .map((f) => f.path);
      const files = [...new Set([...staticFiles, ...treeFiles])];
      const patterns = [
        /(?:SECRET_KEY|API_KEY|DB_PASSWORD|PASSWORD|TOKEN)\s*=\s*["'][^"']{6,}["']/i,
        /sk-proj-[a-zA-Z0-9]+/,
        /super_secret/i,
        /admin123/,
      ];
      for (const file of files) {
        const content = await ghRaw(owner, repo, file);
        if (!content) continue;
        for (const p of patterns) {
          if (p.test(content)) {
            return { pass: false, detail: `Secret found in ${file}` };
          }
        }
      }
      return { pass: true, detail: "No hardcoded secrets detected" };
    },
  },

  tests_exist: {
    points: 10,
    category: "fundamentals",
    label: "Tests exist in pipeline",
    run: async (owner, repo, _team, ctx) => {
      if (!ctx.tree?.tree) return { pass: false, detail: "Cannot read repo" };

      // Find test files
      const testFiles = ctx.tree.tree.filter(
        (f) =>
          f.path.match(/test[_s]?.*\.(py|js|ts)$/i) ||
          f.path.match(/.*\.test\.(js|ts)$/i) ||
          f.path.match(/.*\.spec\.(js|ts)$/i) ||
          f.path.match(/.*_test\.py$/i)
      );

      if (testFiles.length === 0) return { pass: false, detail: "No test files found" };

      // Anti-cheat: verify test files actually import the app or have real assertions
      let realTests = 0;
      for (const tf of testFiles.slice(0, 5)) {
        const content = await ghRaw(owner, repo, tf.path);
        if (!content) continue;
        const lower = content.toLowerCase();
        const hasAssert = lower.includes("assert") || lower.includes("expect(") || lower.includes("expect (");
        const hasImport = lower.includes("import") || lower.includes("require(");
        const hasEndpoint = lower.includes("/todos") || lower.includes("client") || lower.includes("request(");
        if (hasAssert && (hasImport || hasEndpoint)) realTests++;
      }

      if (realTests === 0) return { pass: false, detail: `${testFiles.length} test file(s) but no real assertions/imports` };

      // Check tests run in CI via green step
      const result = findGreenStep(ctx, ["test", "jest", "vitest", "pytest", "mocha", "spec", "ci"]);
      if (result.found) {
        return { pass: true, detail: `${realTests} real test file(s), run in CI — ${result.detail}` };
      }
      return { pass: false, detail: `${realTests} real test file(s) but not run in CI` };
    },
  },

  tests_pass: {
    points: 5,
    category: "fundamentals",
    label: "Tests pass",
    run: async (owner, repo, _team, ctx) => {
      const result = findGreenStep(ctx, ["test", "jest", "vitest", "pytest", "mocha", "spec"]);
      if (result.found) {
        return { pass: true, detail: result.detail };
      }
      if (!ctx.lastRun) return { pass: false, detail: "No CI runs" };
      if (ctx.lastRun.conclusion !== "success") return { pass: false, detail: `Pipeline not green (${ctx.lastRun.name} #${ctx.lastRun.run_number})` };
      return { pass: false, detail: "No test job/step found in last CI run" };
    },
  },

  coverage_70: {
    points: 10,
    category: "fundamentals",
    label: "Coverage ≥ 70%",
    run: async (owner, repo, _team, ctx) => {
      // Best case: trusted badge in README with real percentage
      if (ctx.coverageBadge) {
        const { coverage, provider } = ctx.coverageBadge;
        return {
          pass: coverage >= 70,
          detail: `${coverage}% via ${provider} badge${coverage >= 70 ? " ✅" : " (< 70%)"}`,
        };
      }

      // Middle tier: parse coverage from job logs
      const covStepResult = findGreenStep(ctx, ["coverage", "cov", "codecov", "coveralls", "test", "jest", "vitest", "pytest"]);
      if (covStepResult.found && ctx.lastRunJobs) {
        // Try to find a job that has coverage/test in its name and parse logs
        for (const job of ctx.lastRunJobs) {
          const jn = job.name.toLowerCase();
          if ((jn.includes("coverage") || jn.includes("cov") || jn.includes("test")) && job.conclusion === "success") {
            try {
              const covPct = await parseCoverageFromLogs(owner, repo, job.id);
              if (covPct !== null) {
                return {
                  pass: covPct >= 70,
                  detail: `${covPct}% from job "${job.name}" logs${covPct >= 70 ? " ✅" : " (< 70%)"}`,
                };
              }
            } catch { /* continue */ }
          }
        }
      }

      // Fallback: check for coverage step in CI + pipeline green
      const covResult = findGreenStep(ctx, ["coverage", "cov", "codecov", "coveralls"]);
      if (covResult.found) {
        return {
          pass: true,
          detail: `Coverage step green — ${covResult.detail} (add a Codecov/SonarCloud badge for exact %)`,
        };
      }

      if (!ctx.lastRun) return { pass: false, detail: "No CI runs" };
      const isGreen = ctx.lastRun.conclusion === "success";
      return {
        pass: false,
        detail: `No coverage step in CI (add a trusted badge for exact %), pipeline ${isGreen ? "green" : "red"}`,
      };
    },
  },

  dockerfile_exists: {
    points: 5,
    category: "fundamentals",
    label: "Dockerfile exists",
    run: async (owner, repo) => {
      const content = await ghRaw(owner, repo, "Dockerfile");
      if (!content) return { pass: false, detail: "No Dockerfile at root" };

      const lower = content.toLowerCase();
      const hasInstall = lower.includes("pip install") || lower.includes("npm") || lower.includes("yarn") || lower.includes("requirements");
      const hasCopy = lower.includes("copy") || lower.includes("add");
      if (!hasInstall || !hasCopy) {
        return { pass: false, detail: "Dockerfile exists but doesn't install dependencies or copy app code" };
      }
      return { pass: true, detail: "Valid Dockerfile found" };
    },
  },

  docker_builds: {
    points: 5,
    category: "fundamentals",
    label: "Docker build in CI",
    run: async (owner, repo, _team, ctx) => {
      const result = findGreenStep(ctx, ["docker", "build-push", "image", "ghcr", "container"]);
      if (result.found) {
        return { pass: true, detail: result.detail };
      }
      return { pass: false, detail: "No green Docker build job/step found in last CI run" };
    },
  },

  swagger_docs: {
    points: 5,
    category: "fundamentals",
    label: "API documentation (Swagger)",
    run: async (_owner, _repo, team) => {
      if (!team.deploy_url) return { pass: false, detail: "No deploy_url — cannot check Swagger" };
      const endpoints = ["/docs", "/api-docs", "/swagger", "/api/docs"];
      for (const ep of endpoints) {
        try {
          const url = team.deploy_url.replace(/\/+$/, "") + ep;
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 30000);
          const res = await fetch(url, { signal: controller.signal });
          clearTimeout(timeout);
          if (res.ok) {
            const body = await res.text();
            if (body.includes("swagger") || body.includes("openapi") || body.includes("Swagger") || body.includes("ReDoc") || body.includes("FastAPI")) {
              return { pass: true, detail: `Swagger found at ${ep}` };
            }
          }
        } catch { /* continue */ }
      }
      return { pass: false, detail: "No Swagger/OpenAPI docs found" };
    },
  },

  comment_ratio: {
    points: 5,
    category: "fundamentals",
    label: "Code commented (≥ 5%)",
    run: async (owner, repo, _team, ctx) => {
      if (!ctx.tree?.tree) return { pass: false, detail: "Cannot read repo" };

      const sourceFiles = ctx.tree.tree.filter((f) => {
        const p = f.path.toLowerCase();
        return (
          (p.endsWith(".py") || p.endsWith(".js") || p.endsWith(".ts")) &&
          !p.includes("node_modules") &&
          !p.includes("test") &&
          !p.includes("__pycache__") &&
          !p.startsWith(".")
        );
      });

      if (sourceFiles.length === 0) return { pass: false, detail: "No source files found" };

      let totalComments = 0;
      let totalCode = 0;

      for (const f of sourceFiles.slice(0, 20)) {
        const content = await ghRaw(owner, repo, f.path);
        if (!content) continue;
        const lang = f.path.endsWith(".py") ? "python" : "js";
        const { comments, code } = countComments(content, lang);
        totalComments += comments;
        totalCode += code;
      }

      const total = totalComments + totalCode;
      if (total === 0) return { pass: false, detail: "No code found" };
      const ratio = Math.round((totalComments / total) * 100);
      return {
        pass: ratio >= 5,
        detail: `${totalComments} comment lines / ${total} total (${ratio}%)`,
      };
    },
  },

  // ===== INTERMEDIATE (40 pts) =====

  security_scan: {
    points: 10,
    category: "intermediate",
    label: "Security scan in CI",
    run: async (owner, repo, _team, ctx) => {
      // Check green step in last CI run
      const result = findGreenStep(ctx, ["security", "scan", "audit", "trivy", "snyk", "gitleaks", "bandit", "codeql", "semgrep", "sast", "dast", "vulnerability"]);
      if (result.found) {
        return { pass: true, detail: result.detail };
      }

      // Check for check runs from security apps
      const checkRuns = await gh(`/repos/${owner}/${repo}/commits/main/check-runs`);
      if (checkRuns?.check_runs) {
        for (const cr of checkRuns.check_runs) {
          const name = cr.name.toLowerCase();
          const appName = (cr.app?.name || "").toLowerCase();
          const securityKeywords = ["security", "trivy", "snyk", "gitleaks", "bandit", "codeql", "semgrep", "sast", "vulnerability"];
          for (const kw of securityKeywords) {
            if ((name.includes(kw) || appName.includes(kw)) && cr.conclusion === "success") {
              return { pass: true, detail: `Check run "${cr.name}" (app: ${cr.app?.name}) green ✅` };
            }
          }
        }
      }

      return { pass: false, detail: "No security scan job/step or check run found" };
    },
  },

  ghcr_published: {
    points: 10,
    category: "intermediate",
    label: "Image on GHCR",
    run: async (owner, repo) => {
      const packages = await gh(`/repos/${owner}/${repo}/packages?package_type=container`);
      if (packages && Array.isArray(packages) && packages.length > 0) {
        return { pass: true, detail: `${packages.length} package(s) on GHCR` };
      }
      const orgPackages = await gh(`/orgs/${owner}/packages?package_type=container`);
      if (orgPackages && Array.isArray(orgPackages)) {
        const match = orgPackages.find((p) => p.repository?.name === repo);
        if (match) return { pass: true, detail: `Package "${match.name}" found in org` };
      }
      const userPackages = await gh(`/users/${owner}/packages?package_type=container`);
      if (userPackages && Array.isArray(userPackages)) {
        const match = userPackages.find((p) => p.repository?.name === repo);
        if (match) return { pass: true, detail: `Package "${match.name}" found for user` };
      }
      return { pass: false, detail: "No container packages found on GHCR" };
    },
  },

  quality_gate: {
    points: 10,
    category: "intermediate",
    label: "Quality gate (SonarCloud etc.)",
    run: async (owner, repo, _team, ctx) => {
      // Check green step in last CI run
      const result = findGreenStep(ctx, ["sonar", "quality", "codeclimate", "codecov", "codacy"]);
      if (result.found) {
        return { pass: true, detail: result.detail };
      }

      // Check GitHub Check Runs API for quality apps
      const checkRuns = await gh(`/repos/${owner}/${repo}/commits/main/check-runs`);
      if (checkRuns?.check_runs) {
        for (const cr of checkRuns.check_runs) {
          const name = cr.name.toLowerCase();
          const appName = (cr.app?.name || "").toLowerCase();
          const qualityKeywords = ["sonar", "quality", "codeclimate", "codecov", "codacy"];
          for (const kw of qualityKeywords) {
            if ((name.includes(kw) || appName.includes(kw)) && cr.conclusion === "success") {
              return { pass: true, detail: `Check run "${cr.name}" (app: ${cr.app?.name}) green ✅` };
            }
          }
        }
      }

      return { pass: false, detail: "No quality gate configured" };
    },
  },

  deployed: {
    points: 10,
    category: "intermediate",
    label: "App deployed (HTTP 200)",
    run: async (_owner, _repo, team) => {
      if (!team.deploy_url) return { pass: false, detail: "No deploy_url in teams.json" };
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30000);
        const res = await fetch(team.deploy_url, { signal: controller.signal });
        clearTimeout(timeout);
        if (!res.ok) return { pass: false, detail: `${team.deploy_url} → HTTP ${res.status}` };

        const body = await res.text();
        const isOurApp =
          body.includes("Enhanced") ||
          body.includes("Todo") ||
          body.includes("todo");
        if (isOurApp) {
          return { pass: true, detail: `${team.deploy_url} → HTTP ${res.status} ✅ (Todo API verified)` };
        }
        try {
          const todosRes = await fetch(team.deploy_url.replace(/\/+$/, "") + "/todos", { signal: AbortSignal.timeout(15000) });
          if (todosRes.ok) {
            const todosBody = await todosRes.text();
            if (todosBody.startsWith("[") || todosBody.includes("todos")) {
              return { pass: true, detail: `${team.deploy_url} → /todos endpoint works ✅` };
            }
          }
        } catch { /* ignore */ }
        return { pass: false, detail: `${team.deploy_url} → HTTP 200 but not our Todo API (wrong app?)` };
      } catch (e) {
        return { pass: false, detail: `${team.deploy_url} → ${e.message}` };
      }
    },
  },

  // ===== ADVANCED (30 pts) =====

  branch_protection: {
    points: 5,
    category: "advanced",
    label: "Branch protection on main",
    run: async (owner, repo) => {
      const prot = await gh(`/repos/${owner}/${repo}/branches/main/protection`);
      if (prot && !prot.message && prot.required_pull_request_reviews) {
        return { pass: true, detail: "Classic branch protection — PR required ✅" };
      }
      const rules = await gh(`/repos/${owner}/${repo}/rules/branches/main`);
      if (rules && Array.isArray(rules) && rules.length > 0) {
        const hasPR = rules.some((r) => r.type === "pull_request");
        if (hasPR) {
          return { pass: true, detail: "Repository ruleset — PR required ✅" };
        }
        const ruleTypes = rules.map((r) => r.type).join(", ");
        return { pass: true, detail: `Repository ruleset active (${ruleTypes})` };
      }
      return { pass: false, detail: "No branch protection (checked classic + rulesets)" };
    },
  },

  auto_deploy: {
    points: 10,
    category: "advanced",
    label: "Auto-deploy on push to main",
    run: async (owner, repo, _team, ctx) => {
      // Check green step in last CI run
      const result = findGreenStep(ctx, ["deploy", "release", "publish"]);
      if (result.found) {
        return { pass: true, detail: result.detail };
      }

      // Check GitHub Deployments API
      const deployments = await gh(`/repos/${owner}/${repo}/deployments?per_page=5`);
      if (deployments && Array.isArray(deployments) && deployments.length > 0) {
        const recent = deployments[0];
        const env = recent.environment || "unknown";
        return { pass: true, detail: `GitHub deployment to "${env}" found (${recent.created_at})` };
      }

      return { pass: false, detail: "No deploy/release/publish step or GitHub deployment found" };
    },
  },

  multi_env: {
    points: 10,
    category: "advanced",
    label: "Multiple environments",
    run: async (owner, repo, _team, ctx) => {
      // PRIMARY: Check GitHub Environments API
      if (ctx.environments && Array.isArray(ctx.environments) && ctx.environments.length >= 2) {
        const envNames = ctx.environments.map((e) => e.name.toLowerCase());
        const hasStaging = envNames.some((n) => ["staging", "dev", "development", "preview", "qa", "test"].includes(n));
        const hasProd = envNames.some((n) => ["production", "prod", "live"].includes(n));
        if (hasStaging && hasProd) {
          const names = ctx.environments.map((e) => e.name).join(", ");
          return { pass: true, detail: `GitHub environments: ${names} ✅` };
        }
        if (ctx.environments.length >= 2) {
          const names = ctx.environments.map((e) => e.name).join(", ");
          return { pass: true, detail: `${ctx.environments.length} GitHub environments: ${names} ✅` };
        }
      }

      // FALLBACK: check job names for deploy-staging/deploy-production patterns in lastRunJobs
      if (ctx.lastRunJobs) {
        let hasStaging = false;
        let hasProd = false;
        let stagingJob = "";
        let prodJob = "";
        for (const job of ctx.lastRunJobs) {
          const jn = job.name.toLowerCase();
          if (!hasStaging && (jn.includes("staging") || jn.includes("deploy-staging") || jn.includes("deploy_staging") || jn.includes("dev"))) {
            hasStaging = true;
            stagingJob = job.name;
          }
          if (!hasProd && (jn.includes("production") || jn.includes("deploy-prod") || jn.includes("deploy_prod") || jn.includes("deploy-production"))) {
            hasProd = true;
            prodJob = job.name;
          }
        }
        if (hasStaging && hasProd) {
          return { pass: true, detail: `Multi-env jobs: "${stagingJob}" + "${prodJob}"` };
        }
      }

      return { pass: false, detail: "No multiple environments (need both staging + production)" };
    },
  },

  pipeline_fast: {
    points: 5,
    category: "advanced",
    label: "Pipeline < 3 minutes",
    run: async (owner, repo) => {
      const runs = await gh(`/repos/${owner}/${repo}/actions/runs?branch=main&status=success&per_page=10&event=push`);
      if (!runs?.workflow_runs?.length) return { pass: false, detail: "No successful runs" };
      let totalMs = 0;
      let count = 0;
      for (const run of runs.workflow_runs) {
        const start = new Date(run.created_at);
        const end = new Date(run.updated_at);
        totalMs += end - start;
        count++;
      }
      const avgMin = totalMs / count / 60000;
      return {
        pass: avgMin < 3,
        detail: `Average: ${avgMin.toFixed(1)} min (last ${count} runs)`,
      };
    },
  },

  dependabot: {
    points: 5,
    category: "advanced",
    label: "Dependabot/Renovate configured",
    run: async (owner, repo, _team, ctx) => {
      const depbot = await ghRaw(owner, repo, ".github/dependabot.yml") || await ghRaw(owner, repo, ".github/dependabot.yaml");
      if (depbot && depbot.includes("package-ecosystem")) {
        return { pass: true, detail: "dependabot config with valid setup" };
      }
      const renovate = await ghRaw(owner, repo, "renovate.json") || await ghRaw(owner, repo, ".github/renovate.json") || await ghRaw(owner, repo, ".github/renovate.json5");
      if (renovate && (renovate.includes("extends") || renovate.includes("packageRules"))) {
        return { pass: true, detail: "renovate.json with valid config" };
      }
      if (ctx.workflows) {
        for (const wf of ctx.workflows) {
          if (wf.content.includes("renovatebot/github-action") || wf.content.includes("renovate/renovate")) {
            return { pass: true, detail: `Renovate via GitHub Action in ${wf.path}` };
          }
        }
      }
      return { pass: false, detail: "No valid dependency update config" };
    },
  },
};

// ---------------------------------------------------------------------------
// EXPERT checks
// ---------------------------------------------------------------------------

const EXPERT_CHECKS = {
  ci_notifications: {
    points: 5,
    category: "expert",
    label: "CI notifications (Discord/Slack)",
    run: async (owner, repo, _team, ctx) => {
      // Check for notification job/step in last run
      const result = findGreenStep(ctx, ["notify", "notification", "discord", "slack", "webhook", "alert"]);
      if (result.found) {
        return { pass: true, detail: result.detail };
      }
      // Also check workflow YAML for webhook URLs or notification actions
      for (const wf of ctx.workflows) {
        const lower = wf.content.toLowerCase();
        if (lower.includes("discord-webhook") || lower.includes("slack-webhook") ||
            lower.includes("slackapi/") || lower.includes("discord_webhook") ||
            lower.includes("8398a7/action-slack") || lower.includes("rtcamp/action-slack") ||
            lower.includes("rjstone/discord-webhook")) {
          return { pass: true, detail: `Notification action in ${wf.path}` };
        }
      }
      return { pass: false, detail: "No CI notification job/step found" };
    },
  },
};

// ---------------------------------------------------------------------------
// BONUS checks
// ---------------------------------------------------------------------------

const BONUS_CHECKS = {
  coverage_80: {
    points: 5,
    category: "bonus",
    label: "Coverage ≥ 80%",
    run: async (owner, repo, _team, ctx) => {
      const badge = ctx.coverageBadge;
      if (!badge) return { pass: false, detail: "No trusted coverage badge in README" };
      return {
        pass: badge.coverage >= 80,
        detail: `${badge.coverage}% via ${badge.provider}`,
      };
    },
  },

  coverage_90: {
    points: 5,
    category: "bonus",
    label: "Coverage ≥ 90%",
    run: async (owner, repo, _team, ctx) => {
      const badge = ctx.coverageBadge;
      if (!badge) return { pass: false, detail: "No trusted coverage badge in README" };
      return {
        pass: badge.coverage >= 90,
        detail: `${badge.coverage}% via ${badge.provider}`,
      };
    },
  },

  coverage_95: {
    points: 5,
    category: "bonus",
    label: "Coverage ≥ 95%",
    run: async (owner, repo, _team, ctx) => {
      const badge = ctx.coverageBadge;
      if (!badge) return { pass: false, detail: "No trusted coverage badge in README" };
      return {
        pass: badge.coverage >= 95,
        detail: `${badge.coverage}% via ${badge.provider}`,
      };
    },
  },

  conventional_commits: {
    points: 5,
    category: "bonus",
    label: "Conventional commits",
    run: async (owner, repo) => {
      const commits = await gh(`/repos/${owner}/${repo}/commits?per_page=20`);
      if (!commits || !Array.isArray(commits) || commits.length === 0) {
        return { pass: false, detail: "No commits found" };
      }
      const conventionalRegex = /^(feat|fix|docs|style|refactor|test|chore|ci|build|perf|revert)(\(.+\))?!?:\s/;
      const mergeRegex = /^Merge (pull request|branch|remote-tracking branch)/i;
      const filtered = commits.filter((c) => !mergeRegex.test(c.commit.message));
      if (filtered.length === 0) {
        return { pass: false, detail: "No non-merge commits found" };
      }
      let conventional = 0;
      for (const c of filtered) {
        const msg = c.commit.message;
        if (conventionalRegex.test(msg)) {
          conventional++;
        } else {
          const lines = msg.split("\n").filter((l) => l.trim());
          const bodyConventional = lines.filter((l) => conventionalRegex.test(l.replace(/^\*\s*/, ""))).length;
          if (bodyConventional >= 2) conventional++;
        }
      }
      const pct = Math.round((conventional / filtered.length) * 100);
      return {
        pass: pct >= 80,
        detail: `${conventional}/${filtered.length} conventional (${pct}%)`,
      };
    },
  },

  readme_badges: {
    points: 5,
    category: "bonus",
    label: "README with badges",
    run: async (owner, repo) => {
      const readme = await ghRaw(owner, repo, "README.md");
      if (!readme) return { pass: false, detail: "No README.md" };

      const badgePatterns = [
        /!\[.*?\]\(https?:\/\/.*?badge.*?\)/gi,
        /!\[.*?\]\(https?:\/\/.*?shields\.io.*?\)/gi,
        /!\[.*?\]\(https?:\/\/.*?github\.com\/.*?actions\/workflows.*?\)/gi,
        /!\[.*?\]\(https?:\/\/.*?codecov\.io.*?\)/gi,
        /!\[.*?\]\(https?:\/\/.*?sonarcloud\.io.*?\)/gi,
      ];

      const allBadges = new Set();
      for (const p of badgePatterns) {
        let m;
        while ((m = p.exec(readme))) allBadges.add(m[0]);
      }

      return {
        pass: allBadges.size >= 2,
        detail: `${allBadges.size} badge(s) found`,
      };
    },
  },

  health_endpoint: {
    points: 5,
    category: "bonus",
    label: "Health endpoint",
    run: async (_owner, _repo, team) => {
      if (!team.deploy_url) return { pass: false, detail: "No deploy URL" };
      const base = team.deploy_url.replace(/\/+$/, "");
      for (const path of ["/health", "/healthz", "/api/health"]) {
        try {
          const res = await fetch(`${base}${path}`, { signal: AbortSignal.timeout(10000) });
          if (!res.ok) continue;
          const text = await res.text();
          try {
            const json = JSON.parse(text);
            if (json.status) {
              return { pass: true, detail: `${path} → ${JSON.stringify(json).slice(0, 100)}` };
            }
          } catch { /* not JSON, skip */ }
        } catch { continue; }
      }
      return { pass: false, detail: "No /health, /healthz, or /api/health returning JSON with status" };
    },
  },

  perf_tests: {
    points: 5,
    category: "bonus",
    label: "Performance tests in CI",
    run: async (owner, repo, _team, ctx) => {
      const result = findGreenStep(ctx, ["perf", "performance", "load", "k6", "artillery", "benchmark", "stress"]);
      if (result.found) {
        return { pass: true, detail: result.detail };
      }
      return { pass: false, detail: "No performance test job/step found in last CI run" };
    },
  },

  auto_changelog: {
    points: 5,
    category: "bonus",
    label: "Automated changelog",
    run: async (owner, repo, _team, ctx) => {
      // Check workflows for changelog tools
      if (ctx.workflows) {
        for (const wf of ctx.workflows) {
          const lower = wf.content.toLowerCase();
          if (lower.includes("release-please") || lower.includes("semantic-release") || lower.includes("conventional-changelog") || lower.includes("auto-changelog") || lower.includes("standard-version")) {
            const tool = ["release-please", "semantic-release", "conventional-changelog", "auto-changelog", "standard-version"].find(t => lower.includes(t));
            return { pass: true, detail: `Found ${tool} in ${wf.path}` };
          }
        }
      }

      // Check package.json for release scripts
      const pkg = await ghRaw(owner, repo, "package.json");
      if (pkg) {
        try {
          const json = JSON.parse(pkg);
          const scripts = JSON.stringify(json.scripts || {}).toLowerCase();
          const deps = JSON.stringify({ ...json.dependencies, ...json.devDependencies }).toLowerCase();
          for (const tool of ["semantic-release", "release-please", "conventional-changelog", "auto-changelog", "standard-version"]) {
            if (scripts.includes(tool) || deps.includes(tool)) {
              return { pass: true, detail: `Found ${tool} in package.json` };
            }
          }
        } catch { /* invalid package.json */ }
      }

      // Check for CHANGELOG.md that looks auto-generated
      const changelog = await ghRaw(owner, repo, "CHANGELOG.md");
      if (changelog && changelog.length > 200) {
        const versionHeaders = (changelog.match(/^##?\s+\[?\d+\.\d+/gm) || []).length;
        if (versionHeaders >= 2) {
          return { pass: true, detail: `CHANGELOG.md has ${versionHeaders} version entries` };
        }
      }

      // Fallback: check green step for changelog/release tools
      const result = findGreenStep(ctx, ["changelog", "release-notes", "release-please", "semantic-release"]);
      if (result.found) {
        return { pass: true, detail: result.detail };
      }

      return { pass: false, detail: "No release-please/semantic-release/conventional-changelog found" };
    },
  },
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function scoreTeam(team) {
  const cleanRepo = team.repo.replace(/\.git$/, "");
  const [owner, repo] = cleanRepo.split("/");
  console.log(`\n🔍 Scoring ${team.team} (${team.repo})...`);

  // Pre-fetch and cache all shared data
  const { tree, workflows } = await getWorkflows(owner, repo);
  const coverageBadge = await parseCoverageBadge(owner, repo);
  const lastRun = await getLastCIRun(owner, repo);

  let lastRunJobs = null;
  if (lastRun) {
    const jobsData = await gh(`/repos/${owner}/${repo}/actions/runs/${lastRun.id}/jobs`);
    lastRunJobs = jobsData?.jobs || [];
  }

  let environments = null;
  const envData = await gh(`/repos/${owner}/${repo}/environments`);
  if (envData?.environments) {
    environments = envData.environments;
  }

  const ctx = { tree, workflows, coverageBadge, lastRun, lastRunJobs, environments };

  const results = {};
  let total = 0;
  let maxTotal = 0;

  console.log(`  --- Core checks ---`);
  for (const [key, check] of Object.entries(CHECKS)) {
    try {
      const result = await check.run(owner, repo, team, ctx);
      results[key] = { ...result, points: check.points, label: check.label, category: check.category };
      if (result.pass) total += check.points;
      maxTotal += check.points;
      const icon = result.pass ? "✅" : "❌";
      console.log(`  ${icon} ${check.label} (${result.pass ? check.points : 0}/${check.points}) — ${result.detail}`);
    } catch (e) {
      results[key] = { pass: false, points: check.points, label: check.label, category: check.category, detail: `Error: ${e.message}` };
      maxTotal += check.points;
      console.log(`  ⚠️  ${check.label} — Error: ${e.message}`);
    }
  }

  // Expert checks
  let expert = 0;
  let maxExpert = 0;
  const expertResults = {};

  console.log(`  --- Expert ---`);
  for (const [key, check] of Object.entries(EXPERT_CHECKS)) {
    try {
      const result = await check.run(owner, repo, team, ctx);
      expertResults[key] = { ...result, points: check.points, label: check.label, category: check.category };
      if (result.pass) expert += check.points;
      maxExpert += check.points;
      const icon = result.pass ? "🔴" : "○";
      console.log(`  ${icon} ${check.label} (${result.pass ? check.points : 0}/${check.points}) — ${result.detail}`);
    } catch (e) {
      expertResults[key] = { pass: false, points: check.points, label: check.label, category: check.category, detail: `Error: ${e.message}` };
      maxExpert += check.points;
      console.log(`  ⚠️  ${check.label} — Error: ${e.message}`);
    }
  }

  // Bonus checks
  let bonus = 0;
  let maxBonus = 0;
  const bonusResults = {};

  console.log(`  --- Bonus ---`);
  for (const [key, check] of Object.entries(BONUS_CHECKS)) {
    try {
      const result = await check.run(owner, repo, team, ctx);
      bonusResults[key] = { ...result, points: check.points, label: check.label, category: check.category };
      if (result.pass) bonus += check.points;
      maxBonus += check.points;
      const icon = result.pass ? "⭐" : "☆";
      console.log(`  ${icon} ${check.label} (${result.pass ? check.points : 0}/${check.points}) — ${result.detail}`);
    } catch (e) {
      bonusResults[key] = { pass: false, points: check.points, label: check.label, category: check.category, detail: `Error: ${e.message}` };
      maxBonus += check.points;
      console.log(`  ⚠️  ${check.label} — Error: ${e.message}`);
    }
  }

  return {
    team: team.team, members: team.members, repo: team.repo, deploy_url: team.deploy_url,
    total, maxTotal, expert, maxExpert, bonus, maxBonus,
    grandTotal: total + expert + bonus,
    results, expertResults, bonusResults,
  };
}

async function main() {
  const teamsFile = process.argv[2] || "teams.json";
  const teams = JSON.parse(readFileSync(teamsFile, "utf-8"));
  const scores = [];

  for (const team of teams) {
    scores.push(await scoreTeam(team));
  }

  scores.sort((a, b) => b.grandTotal - a.grandTotal);
  scores.forEach((s, i) => (s.rank = i + 1));

  const output = {
    generated_at: new Date().toISOString(),
    total_possible: Object.values(CHECKS).reduce((s, c) => s + c.points, 0),
    expert_possible: Object.values(EXPERT_CHECKS).reduce((s, c) => s + c.points, 0),
    bonus_possible: Object.values(BONUS_CHECKS).reduce((s, c) => s + c.points, 0),
    teams: scores,
  };

  mkdirSync("docs", { recursive: true });
  const outFile = teamsFile === "teams.json" ? "docs/scores.json" : "docs/scores-test.json";
  writeFileSync(outFile, JSON.stringify(output, null, 2));
  console.log(`\n📊 Scores written to ${outFile}`);
  console.log(`\n🏆 Leaderboard:`);
  for (const s of scores) {
    const extraStr = (s.expert > 0 || s.bonus > 0) ? ` (+${s.expert + s.bonus} extra)` : "";
    console.log(`  #${s.rank} ${s.team} — ${s.total}/${s.maxTotal} pts${extraStr}`);
  }
}

main().catch(console.error);

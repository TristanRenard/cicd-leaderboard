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
// Anti-cheat helpers
// ---------------------------------------------------------------------------

/** Check that a workflow step actually runs a real command, not just echo */
function stepIsReal(content, keywords) {
  const lines = content.split("\n");
  for (const kw of keywords) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].toLowerCase().trim();
      // Check for "uses:" with known actions
      if (line.startsWith("uses:") && line.includes(kw)) return { found: true, how: `action: ${kw}` };
      // Check for "run:" lines that actually invoke the tool (not just echo)
      if (line.startsWith("run:") || line.startsWith("- ")) {
        const runContent = line.replace(/^run:\s*\|?\s*/, "").replace(/^-\s*/, "");
        if (runContent.includes(kw) && !runContent.match(/^\s*echo\b/)) {
          return { found: true, how: `command: ${kw}` };
        }
      }
      // Multi-line run blocks
      if (line === "run: |" || line === "run: >") {
        for (let j = i + 1; j < lines.length && (lines[j].startsWith("  ") || lines[j].startsWith("\t")); j++) {
          const subline = lines[j].toLowerCase().trim();
          if (subline.includes(kw) && !subline.match(/^\s*echo\b/)) {
            return { found: true, how: `command: ${kw}` };
          }
        }
      }
    }
  }
  return { found: false };
}

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
    if (!trimmed) continue; // skip blank lines

    if (lang === "python") {
      if (trimmed.startsWith("#")) { comments++; }
      else if (trimmed.startsWith('"""') || trimmed.startsWith("'''")) {
        // Toggle block comment
        const delim = trimmed.slice(0, 3);
        if (inBlock) { comments++; inBlock = false; }
        else if (trimmed.indexOf(delim, 3) !== -1) { comments++; } // single-line docstring
        else { comments++; inBlock = true; }
      } else if (inBlock) { comments++; }
      else { code++; }
    } else {
      // JS/TS
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
    run: async (owner, repo) => {
      const runs = await gh(`/repos/${owner}/${repo}/actions/runs?branch=main&per_page=1`);
      if (!runs?.workflow_runs?.length) return { pass: false, detail: "No runs found" };
      const last = runs.workflow_runs[0];
      return {
        pass: last.conclusion === "success",
        detail: `Last run: ${last.conclusion || last.status} (#${last.run_number})`,
      };
    },
  },

  lint_pass: {
    points: 5,
    category: "fundamentals",
    label: "Lint step in pipeline",
    run: async (owner, repo, _team, ctx) => {
      // Anti-cheat: must actually run a linter, not just mention the word
      const realLinters = ["ruff", "flake8", "pylint", "eslint", "prettier", "black"];
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, realLinters);
        if (result.found) {
          return { pass: true, detail: `Real linter in ${wf.path} (${result.how})` };
        }
      }
      return { pass: false, detail: "No real linter execution found in workflows" };
    },
  },

  no_secrets_in_code: {
    points: 5,
    category: "fundamentals",
    label: "No hardcoded secrets",
    run: async (owner, repo) => {
      const files = [
        "main.py", "app.js", "app.py",
        "database/database.py", "database/database.js",
        "routers/todo.py", "routes/todo.js",
        "config.py", "config.js", "settings.py",
      ];
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
        // Must have actual assertions AND import something from the project
        const hasAssert = lower.includes("assert") || lower.includes("expect(") || lower.includes("expect (");
        const hasImport = lower.includes("import") || lower.includes("require(");
        const hasEndpoint = lower.includes("/todos") || lower.includes("client") || lower.includes("request(");
        if (hasAssert && (hasImport || hasEndpoint)) realTests++;
      }

      if (realTests === 0) return { pass: false, detail: `${testFiles.length} test file(s) but no real assertions/imports` };

      // Check tests run in CI
      const testRunners = ["pytest", "jest", "vitest", "mocha", "npm test", "npm run test"];
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, testRunners);
        if (result.found) {
          return { pass: true, detail: `${realTests} real test file(s), run in CI (${result.how})` };
        }
      }
      return { pass: false, detail: `${realTests} real test file(s) but not run in CI` };
    },
  },

  tests_pass: {
    points: 5,
    category: "fundamentals",
    label: "Tests pass",
    run: async (owner, repo) => {
      const runs = await gh(`/repos/${owner}/${repo}/actions/runs?branch=main&per_page=1`);
      if (!runs?.workflow_runs?.length) return { pass: false, detail: "No runs" };
      const last = runs.workflow_runs[0];
      if (last.conclusion !== "success") return { pass: false, detail: "Pipeline not green" };

      const jobs = await gh(`/repos/${owner}/${repo}/actions/runs/${last.id}/jobs`);
      if (!jobs?.jobs) return { pass: false, detail: "Cannot read jobs" };
      const testJob = jobs.jobs.find((j) => {
        const n = j.name.toLowerCase();
        return n.includes("test") || n.includes("ci") || n.includes("build");
      });
      return {
        pass: testJob?.conclusion === "success",
        detail: testJob ? `Job "${testJob.name}": ${testJob.conclusion}` : "No test job found",
      };
    },
  },

  coverage_70: {
    points: 10,
    category: "fundamentals",
    label: "Coverage ≥ 70%",
    run: async (owner, repo, _team, ctx) => {
      // Check for real coverage commands in workflows
      const covCommands = ["--cov", "pytest-cov", "--coverage", "coverage run", "c8", "nyc"];
      let hasCoverage = false;
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, covCommands);
        if (result.found) { hasCoverage = true; break; }
      }

      if (!hasCoverage) return { pass: false, detail: "No coverage step found in CI" };

      const runs = await gh(`/repos/${owner}/${repo}/actions/runs?branch=main&per_page=1`);
      if (!runs?.workflow_runs?.length) return { pass: false, detail: "No runs" };
      const isGreen = runs.workflow_runs[0].conclusion === "success";

      return {
        pass: hasCoverage && isGreen,
        detail: `Coverage in CI, pipeline ${isGreen ? "green ✅" : "red ❌"}`,
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

      // Anti-cheat: must have real app instructions, not just FROM+CMD echo
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
      const dockerKeywords = ["docker/build-push-action", "docker build", "docker/build"];
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, dockerKeywords);
        if (result.found) {
          return { pass: true, detail: `Docker build in ${wf.path} (${result.how})` };
        }
      }
      return { pass: false, detail: "No docker build step in CI" };
    },
  },

  swagger_docs: {
    points: 5,
    category: "fundamentals",
    label: "API documentation (Swagger)",
    run: async (_owner, _repo, team) => {
      if (!team.deploy_url) return { pass: false, detail: "No deploy_url — cannot check Swagger" };
      // Try common Swagger/OpenAPI endpoints
      const endpoints = ["/docs", "/api-docs", "/swagger", "/api/docs"];
      for (const ep of endpoints) {
        try {
          const url = team.deploy_url.replace(/\/+$/, "") + ep;
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 15000);
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
      // Anti-cheat: must use real security tools/actions
      const realTools = [
        "aquasecurity/trivy-action", "trivy ", "trivy fs", "trivy image",
        "gitleaks/gitleaks-action", "gitleaks detect",
        "bandit -r", "bandit ",
        "pip-audit", "safety check",
        "npm audit", "snyk test",
        "github/codeql-action", "semgrep",
      ];
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, realTools);
        if (result.found) {
          return { pass: true, detail: `Security scan: ${result.how} in ${wf.path}` };
        }
      }
      return { pass: false, detail: "No real security scan found in workflows" };
    },
  },

  ghcr_published: {
    points: 10,
    category: "intermediate",
    label: "Image on GHCR",
    run: async (owner, repo) => {
      // Check GitHub packages API
      const packages = await gh(`/repos/${owner}/${repo}/packages?package_type=container`);
      if (packages && Array.isArray(packages) && packages.length > 0) {
        return { pass: true, detail: `${packages.length} package(s) on GHCR` };
      }
      // Fallback: check org-level packages
      const orgPackages = await gh(`/orgs/${owner}/packages?package_type=container`);
      if (orgPackages && Array.isArray(orgPackages)) {
        const match = orgPackages.find((p) => p.repository?.name === repo);
        if (match) return { pass: true, detail: `Package "${match.name}" found in org` };
      }
      // Check user-level packages
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
      // Anti-cheat: must use a real quality tool action or command
      const realTools = [
        "sonarcloud-github-action", "SonarSource/sonarcloud",
        "sonar-scanner", "sonar.projectKey",
        "codeclimate/action", "paambaati/codeclimate-action",
        "codecov/codecov-action",
      ];
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, realTools);
        if (result.found) {
          return { pass: true, detail: `Quality gate: ${result.how}` };
        }
        // Also check for these in uses: directly (actions are valid even without run:)
        if (realTools.some((t) => wf.content.toLowerCase().includes(t.toLowerCase()))) {
          return { pass: true, detail: `Quality tool configured in ${wf.path}` };
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

        // Anti-cheat: response must contain our app's signature
        const body = await res.text();
        const isOurApp =
          body.includes("Enhanced") ||
          body.includes("Todo") ||
          body.includes("todo");
        if (!isOurApp) {
          return { pass: false, detail: `${team.deploy_url} → HTTP 200 but not our Todo API (wrong app?)` };
        }
        return { pass: true, detail: `${team.deploy_url} → HTTP ${res.status} ✅ (Todo API verified)` };
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
      if (!prot || prot.message) return { pass: false, detail: "No branch protection" };
      const prRequired = prot.required_pull_request_reviews;
      return {
        pass: !!prRequired,
        detail: prRequired ? "PR required before merge ✅" : "Protection exists but PR not required",
      };
    },
  },

  auto_deploy: {
    points: 10,
    category: "advanced",
    label: "Auto-deploy on push to main",
    run: async (owner, repo, _team, ctx) => {
      const deployKeywords = [
        "render.com", "api.render.com", "fly deploy", "flyctl deploy",
        "railway", "deploy", "ssh", "rsync",
      ];
      for (const wf of ctx.workflows) {
        const lower = wf.content.toLowerCase();
        // Must trigger on push to main
        const triggersOnMain = (lower.includes("push") && lower.includes("main")) ||
          lower.includes("branches: [main]") || lower.includes("branches: [ main ]") ||
          lower.includes("branches:\n") ;
        if (!triggersOnMain) continue;

        const result = stepIsReal(wf.content, deployKeywords);
        if (result.found) {
          return { pass: true, detail: `Deploy on push to main: ${result.how} in ${wf.path}` };
        }
      }
      return { pass: false, detail: "No auto-deploy workflow found" };
    },
  },

  multi_env: {
    points: 10,
    category: "advanced",
    label: "Multiple environments",
    run: async (owner, repo, _team, ctx) => {
      for (const wf of ctx.workflows) {
        const lower = wf.content.toLowerCase();
        const hasStaging = lower.includes("environment: staging") || /environment:\s*\n\s*name:\s*staging/.test(lower);
        const hasProd = lower.includes("environment: production") || lower.includes("environment: prod") || /environment:\s*\n\s*name:\s*production/.test(lower) || /environment:\s*\n\s*name:\s*prod/.test(lower);
        if (hasStaging && hasProd) {
          return { pass: true, detail: `Staging + production environments in ${wf.path}` };
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
      const runs = await gh(`/repos/${owner}/${repo}/actions/runs?branch=main&status=success&per_page=3`);
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
    run: async (owner, repo) => {
      // Anti-cheat: file must have actual config, not be empty
      const depbot = await ghRaw(owner, repo, ".github/dependabot.yml") || await ghRaw(owner, repo, ".github/dependabot.yaml");
      if (depbot && depbot.includes("package-ecosystem")) {
        return { pass: true, detail: "dependabot config with valid setup" };
      }
      const renovate = await ghRaw(owner, repo, "renovate.json") || await ghRaw(owner, repo, ".github/renovate.json");
      if (renovate && renovate.includes("extends")) {
        return { pass: true, detail: "renovate.json with valid config" };
      }
      return { pass: false, detail: "No valid dependency update config" };
    },
  },
};

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
 * Anti-cheat: only accepts badges from trusted dynamic providers.
 */
async function parseCoverageBadge(owner, repo) {
  const readme = await ghRaw(owner, repo, "README.md");
  if (!readme) return null;

  // Find all image URLs in the README
  const imgRegex = /!\[[^\]]*\]\(([^)]+)\)/g;
  const htmlImgRegex = /<img[^>]+src="([^"]+)"/g;
  const urls = [];
  let m;
  while ((m = imgRegex.exec(readme))) urls.push(m[1]);
  while ((m = htmlImgRegex.exec(readme))) urls.push(m[1]);

  for (const url of urls) {
    // Check if it's from a trusted provider
    const provider = TRUSTED_BADGE_PROVIDERS.find((p) => p.pattern.test(url));
    if (!provider) continue;

    // Fetch the badge SVG and parse the percentage
    try {
      const res = await fetch(url, { headers: { Accept: "image/svg+xml" } });
      if (!res.ok) continue;
      const svg = await res.text();

      // Extract percentage from SVG text content (e.g., "92%", "85.3%")
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
      // Check that at least 80% of commits follow conventional format
      // Also check squash merge bodies (each line starting with conventional prefix counts)
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
          // Check if it's a squash merge with conventional commits in the body
          const lines = msg.split("\n").filter((l) => l.trim());
          const bodyConventional = lines.filter((l) => conventionalRegex.test(l.replace(/^\*\s*/, ""))).length;
          if (bodyConventional >= 2) conventional++; // Squash with ≥2 conventional sub-commits counts
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

      // Must have at least 2 badges (images that look like badges)
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
          // Must return JSON with a status field
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
    run: async (_owner, _repo, _team, ctx) => {
      if (!ctx.workflows || ctx.workflows.length === 0) return { pass: false, detail: "No workflows" };
      const perfTools = ["k6", "artillery", "autocannon", "loadtest", "vegeta", "wrk", "ab ", "hey ", "bombardier", "locust"];
      for (const wf of ctx.workflows) {
        const lower = wf.content.toLowerCase();
        for (const tool of perfTools) {
          if (lower.includes(tool)) {
            // Verify it's in a run: step, not just a comment
            const lines = wf.content.split("\n");
            for (const line of lines) {
              const trimmed = line.trim().toLowerCase();
              if ((trimmed.startsWith("run:") || trimmed.startsWith("- run:")) && trimmed.includes(tool.trim())) {
                return { pass: true, detail: `Found ${tool.trim()} in ${wf.name}` };
              }
            }
            // Also check "uses:" for k6/artillery actions
            if (lower.includes("grafana/k6-action") || lower.includes("artilleryio/action")) {
              return { pass: true, detail: `Found perf action in ${wf.name}` };
            }
          }
        }
      }
      return { pass: false, detail: "No k6/artillery/autocannon/loadtest found in workflows" };
    },
  },

  auto_changelog: {
    points: 5,
    category: "bonus",
    label: "Automated changelog",
    run: async (owner, repo, _team, ctx) => {
      // Check for release-please, semantic-release, or conventional-changelog in workflows or package.json
      if (ctx.workflows) {
        for (const wf of ctx.workflows) {
          const lower = wf.content.toLowerCase();
          if (lower.includes("release-please") || lower.includes("semantic-release") || lower.includes("conventional-changelog") || lower.includes("auto-changelog") || lower.includes("standard-version")) {
            const tool = ["release-please", "semantic-release", "conventional-changelog", "auto-changelog", "standard-version"].find(t => lower.includes(t));
            return { pass: true, detail: `Found ${tool} in ${wf.name}` };
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
        // Auto-generated changelogs typically have version headers with dates
        const versionHeaders = (changelog.match(/^##?\s+\[?\d+\.\d+/gm) || []).length;
        if (versionHeaders >= 2) {
          return { pass: true, detail: `CHANGELOG.md has ${versionHeaders} version entries` };
        }
      }
      return { pass: false, detail: "No release-please/semantic-release/conventional-changelog found" };
    },
  },
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function scoreTeam(team) {
  // Clean repo name (remove trailing .git if present)
  const cleanRepo = team.repo.replace(/\.git$/, "");
  const [owner, repo] = cleanRepo.split("/");
  console.log(`\n🔍 Scoring ${team.team} (${team.repo})...`);

  // Pre-fetch workflows (shared across checks)
  const { tree, workflows } = await getWorkflows(owner, repo);
  const coverageBadge = await parseCoverageBadge(owner, repo);
  const ctx = { tree, workflows, coverageBadge };

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
    total, maxTotal, bonus, maxBonus, grandTotal: total + bonus,
    results, bonusResults,
  };
}

async function main() {
  const teams = JSON.parse(readFileSync("teams.json", "utf-8"));
  const scores = [];

  for (const team of teams) {
    scores.push(await scoreTeam(team));
  }

  scores.sort((a, b) => b.grandTotal - a.grandTotal);
  scores.forEach((s, i) => (s.rank = i + 1));

  const output = {
    generated_at: new Date().toISOString(),
    total_possible: Object.values(CHECKS).reduce((s, c) => s + c.points, 0),
    bonus_possible: Object.values(BONUS_CHECKS).reduce((s, c) => s + c.points, 0),
    teams: scores,
  };

  mkdirSync("docs", { recursive: true });
  writeFileSync("docs/scores.json", JSON.stringify(output, null, 2));
  console.log(`\n📊 Scores written to docs/scores.json`);
  console.log(`\n🏆 Leaderboard:`);
  for (const s of scores) {
    const bonusStr = s.bonus > 0 ? ` (+${s.bonus} bonus)` : "";
    console.log(`  #${s.rank} ${s.team} — ${s.total}/${s.maxTotal} pts${bonusStr}`);
  }
}

main().catch(console.error);

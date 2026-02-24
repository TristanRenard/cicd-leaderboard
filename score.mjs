#!/usr/bin/env node
/**
 * CI/CD Leaderboard Scorer
 *
 * Scans student repos via GitHub API and produces scores.json
 * Usage: GITHUB_TOKEN=xxx node score.mjs
 */

import { readFileSync, writeFileSync, mkdirSync } from "fs"

const TOKEN = process.env.GITHUB_TOKEN
if (!TOKEN) { console.error("GITHUB_TOKEN required"); process.exit(1) }

const API = "https://api.github.com"
const headers = {
  Authorization: `Bearer ${TOKEN}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
}

// ---------------------------------------------------------------------------
// GitHub API helpers
// ---------------------------------------------------------------------------

const gh = async (path) => {
  const res = await fetch(`${API}${path}`, { headers })
  if (!res.ok) return null
  return res.json()
}

const ghRaw = async (owner, repo, path, branch) => {
  const res = await fetch(
    `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`,
    { headers }
  )
  if (!res.ok) return null
  return res.text()
}

// ---------------------------------------------------------------------------
// Anti-cheat helpers
// ---------------------------------------------------------------------------

const stepIsReal = (content, keywords) => {
  const lines = content.split("\n")
  for (const kw of keywords) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].toLowerCase().trim()
      if (line.startsWith("uses:") && line.includes(kw)) return { found: true, how: `action: ${kw}` }
      if (line.startsWith("run:") || line.startsWith("- ")) {
        const runContent = line.replace(/^run:\s*\|?\s*/, "").replace(/^-\s*/, "")
        if (runContent.includes(kw) && !runContent.match(/^\s*echo\b/)) {
          return { found: true, how: `command: ${kw}` }
        }
      }
      if (line === "run: |" || line === "run: >") {
        for (let j = i + 1; j < lines.length && (lines[j].startsWith("  ") || lines[j].startsWith("\t")); j++) {
          const subline = lines[j].toLowerCase().trim()
          if (subline.includes(kw) && !subline.match(/^\s*echo\b/)) {
            return { found: true, how: `command: ${kw}` }
          }
        }
      }
    }
  }
  return { found: false }
}

const countComments = (content, lang) => {
  const lines = content.split("\n")
  let comments = 0
  let code = 0
  let inBlock = false

  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue

    if (lang === "python") {
      if (trimmed.startsWith("#")) { comments++ }
      else if (trimmed.startsWith('"""') || trimmed.startsWith("'''")) {
        const delim = trimmed.slice(0, 3)
        if (inBlock) { comments++; inBlock = false }
        else if (trimmed.indexOf(delim, 3) !== -1) { comments++ }
        else { comments++; inBlock = true }
      } else if (inBlock) { comments++ }
      else { code++ }
    } else {
      if (inBlock) {
        comments++
        if (trimmed.includes("*/")) inBlock = false
      } else if (trimmed.startsWith("//")) { comments++ }
      else if (trimmed.startsWith("/*")) {
        comments++
        inBlock = !trimmed.includes("*/")
      } else { code++ }
    }
  }
  return { comments, code, total: comments + code }
}

const getWorkflows = async (owner, repo, branch) => {
  const tree = await gh(`/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`)
  if (!tree?.tree) return { tree: null, workflows: [] }
  const wfPaths = tree.tree
    .filter((f) => f.path.startsWith(".github/workflows/") && (f.path.endsWith(".yml") || f.path.endsWith(".yaml")))
    .map((f) => f.path)
  const workflows = []
  for (const p of wfPaths) {
    const content = await ghRaw(owner, repo, p, branch)
    if (content) workflows.push({ path: p, content })
  }
  return { tree, workflows }
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

const CHECKS = {
  pipeline_exists: {
    points: 5,
    category: "fundamentals",
    label: "Pipeline exists",
    run: async (owner, repo, _team, ctx) => ({
      pass: ctx.workflows.length > 0,
      detail: `${ctx.workflows.length} workflow(s) found`,
    }),
  },

  pipeline_green: {
    points: 5,
    category: "fundamentals",
    label: "Pipeline green on branch",
    run: async (owner, repo, team) => {
      const runs = await gh(`/repos/${owner}/${repo}/actions/runs?branch=${team.branch}&per_page=1`)
      if (!runs?.workflow_runs?.length) return { pass: false, detail: "No runs found" }
      const last = runs.workflow_runs[0]
      return {
        pass: last.conclusion === "success",
        detail: `Last run: ${last.conclusion || last.status} (#${last.run_number})`,
      }
    },
  },

  lint_pass: {
    points: 5,
    category: "fundamentals",
    label: "Lint step in pipeline",
    run: async (owner, repo, _team, ctx) => {
      const realLinters = ["ruff", "flake8", "pylint", "eslint", "prettier", "black"]
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, realLinters)
        if (result.found) return { pass: true, detail: `Real linter in ${wf.path} (${result.how})` }
      }
      return { pass: false, detail: "No real linter execution found in workflows" }
    },
  },

  no_secrets_in_code: {
    points: 5,
    category: "fundamentals",
    label: "No hardcoded secrets",
    run: async (owner, repo, team) => {
      const files = [
        "main.py", "app.js", "app.py",
        "database/database.py", "database/database.js",
        "routers/todo.py", "routes/todo.js",
        "config.py", "config.js", "settings.py",
      ]
      const patterns = [
        /(?:SECRET_KEY|API_KEY|DB_PASSWORD|PASSWORD|TOKEN)\s*=\s*["'][^"']{6,}["']/i,
        /sk-proj-[a-zA-Z0-9]+/,
        /super_secret/i,
        /admin123/,
      ]
      for (const file of files) {
        const content = await ghRaw(owner, repo, file, team.branch)
        if (!content) continue
        for (const p of patterns) {
          if (p.test(content)) return { pass: false, detail: `Secret found in ${file}` }
        }
      }
      return { pass: true, detail: "No hardcoded secrets detected" }
    },
  },

  tests_exist: {
    points: 10,
    category: "fundamentals",
    label: "Tests exist in pipeline",
    run: async (owner, repo, team, ctx) => {
      if (!ctx.tree?.tree) return { pass: false, detail: "Cannot read repo" }

      const testFiles = ctx.tree.tree.filter(
        (f) =>
          f.path.match(/test[_s]?.*\.(py|js|ts)$/i) ||
          f.path.match(/.*\.test\.(js|ts)$/i) ||
          f.path.match(/.*\.spec\.(js|ts)$/i) ||
          f.path.match(/.*_test\.py$/i)
      )

      if (testFiles.length === 0) return { pass: false, detail: "No test files found" }

      let realTests = 0
      for (const tf of testFiles.slice(0, 5)) {
        const content = await ghRaw(owner, repo, tf.path, team.branch)
        if (!content) continue
        const lower = content.toLowerCase()
        const hasAssert = lower.includes("assert") || lower.includes("expect(") || lower.includes("expect (")
        const hasImport = lower.includes("import") || lower.includes("require(")
        const hasEndpoint = lower.includes("/todos") || lower.includes("client") || lower.includes("request(")
        if (hasAssert && (hasImport || hasEndpoint)) realTests++
      }

      if (realTests === 0) return { pass: false, detail: `${testFiles.length} test file(s) but no real assertions/imports` }

      const testRunners = ["pytest", "jest", "vitest", "mocha", "npm test", "npm run test"]
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, testRunners)
        if (result.found) return { pass: true, detail: `${realTests} real test file(s), run in CI (${result.how})` }
      }
      return { pass: false, detail: `${realTests} real test file(s) but not run in CI` }
    },
  },

  tests_pass: {
    points: 5,
    category: "fundamentals",
    label: "Tests pass",
    run: async (owner, repo, team) => {
      const runs = await gh(`/repos/${owner}/${repo}/actions/runs?branch=${team.branch}&per_page=1`)
      if (!runs?.workflow_runs?.length) return { pass: false, detail: "No runs" }
      const last = runs.workflow_runs[0]
      if (last.conclusion !== "success") return { pass: false, detail: "Pipeline not green" }

      const jobs = await gh(`/repos/${owner}/${repo}/actions/runs/${last.id}/jobs`)
      if (!jobs?.jobs) return { pass: false, detail: "Cannot read jobs" }
      const testJob = jobs.jobs.find((j) => {
        const n = j.name.toLowerCase()
        return n.includes("test") || n.includes("ci") || n.includes("build")
      })
      return {
        pass: testJob?.conclusion === "success",
        detail: testJob ? `Job "${testJob.name}": ${testJob.conclusion}` : "No test job found",
      }
    },
  },

  coverage_70: {
    points: 10,
    category: "fundamentals",
    label: "Coverage ≥ 70%",
    run: async (owner, repo, team, ctx) => {
      const covCommands = ["--cov", "pytest-cov", "--coverage", "coverage run", "c8", "nyc"]
      let hasCoverage = false
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, covCommands)
        if (result.found) { hasCoverage = true; break }
      }

      if (!hasCoverage) return { pass: false, detail: "No coverage step found in CI" }

      const runs = await gh(`/repos/${owner}/${repo}/actions/runs?branch=${team.branch}&per_page=1`)
      if (!runs?.workflow_runs?.length) return { pass: false, detail: "No runs" }
      const isGreen = runs.workflow_runs[0].conclusion === "success"

      return {
        pass: hasCoverage && isGreen,
        detail: `Coverage in CI, pipeline ${isGreen ? "green ✅" : "red ❌"}`,
      }
    },
  },

  dockerfile_exists: {
    points: 5,
    category: "fundamentals",
    label: "Dockerfile exists",
    run: async (owner, repo, team) => {
      const content = await ghRaw(owner, repo, "Dockerfile", team.branch)
      if (!content) return { pass: false, detail: "No Dockerfile at root" }

      const lower = content.toLowerCase()
      const hasInstall = lower.includes("pip install") || lower.includes("npm") || lower.includes("yarn") || lower.includes("requirements")
      const hasCopy = lower.includes("copy") || lower.includes("add")
      if (!hasInstall || !hasCopy) {
        return { pass: false, detail: "Dockerfile exists but doesn't install dependencies or copy app code" }
      }
      return { pass: true, detail: "Valid Dockerfile found" }
    },
  },

  docker_builds: {
    points: 5,
    category: "fundamentals",
    label: "Docker build in CI",
    run: async (owner, repo, _team, ctx) => {
      const dockerKeywords = ["docker/build-push-action", "docker build", "docker/build"]
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, dockerKeywords)
        if (result.found) return { pass: true, detail: `Docker build in ${wf.path} (${result.how})` }
      }
      return { pass: false, detail: "No docker build step in CI" }
    },
  },

  swagger_docs: {
    points: 5,
    category: "fundamentals",
    label: "API documentation (Swagger)",
    run: async (_owner, _repo, team) => {
      if (!team.deploy_url) return { pass: false, detail: "No deploy_url — cannot check Swagger" }
      const endpoints = ["/docs", "/api-docs", "/swagger", "/api/docs"]
      for (const ep of endpoints) {
        try {
          const url = team.deploy_url.replace(/\/+$/, "") + ep
          const controller = new AbortController()
          const timeout = setTimeout(() => controller.abort(), 15000)
          const res = await fetch(url, { signal: controller.signal })
          clearTimeout(timeout)
          if (res.ok) {
            const body = await res.text()
            if (body.includes("swagger") || body.includes("openapi") || body.includes("Swagger") || body.includes("ReDoc") || body.includes("FastAPI")) {
              return { pass: true, detail: `Swagger found at ${ep}` }
            }
          }
        } catch { /* continue */ }
      }
      return { pass: false, detail: "No Swagger/OpenAPI docs found" }
    },
  },

  comment_ratio: {
    points: 5,
    category: "fundamentals",
    label: "Code commented (≥ 5%)",
    run: async (owner, repo, team, ctx) => {
      if (!ctx.tree?.tree) return { pass: false, detail: "Cannot read repo" }

      const sourceFiles = ctx.tree.tree.filter((f) => {
        const p = f.path.toLowerCase()
        return (
          (p.endsWith(".py") || p.endsWith(".js") || p.endsWith(".ts")) &&
          !p.includes("node_modules") &&
          !p.includes("test") &&
          !p.includes("__pycache__") &&
          !p.startsWith(".")
        )
      })

      if (sourceFiles.length === 0) return { pass: false, detail: "No source files found" }

      let totalComments = 0
      let totalCode = 0

      for (const f of sourceFiles.slice(0, 20)) {
        const content = await ghRaw(owner, repo, f.path, team.branch)
        if (!content) continue
        const lang = f.path.endsWith(".py") ? "python" : "js"
        const { comments, code } = countComments(content, lang)
        totalComments += comments
        totalCode += code
      }

      const total = totalComments + totalCode
      if (total === 0) return { pass: false, detail: "No code found" }
      const ratio = Math.round((totalComments / total) * 100)
      return {
        pass: ratio >= 5,
        detail: `${totalComments} comment lines / ${total} total (${ratio}%)`,
      }
    },
  },

  security_scan: {
    points: 10,
    category: "intermediate",
    label: "Security scan in CI",
    run: async (owner, repo, _team, ctx) => {
      const realTools = [
        "aquasecurity/trivy-action", "trivy ", "trivy fs", "trivy image",
        "gitleaks/gitleaks-action", "gitleaks detect",
        "bandit -r", "bandit ",
        "pip-audit", "safety check",
        "npm audit", "snyk test",
        "github/codeql-action", "semgrep",
      ]
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, realTools)
        if (result.found) return { pass: true, detail: `Security scan: ${result.how} in ${wf.path}` }
      }
      return { pass: false, detail: "No real security scan found in workflows" }
    },
  },

  ghcr_published: {
    points: 10,
    category: "intermediate",
    label: "Image on GHCR",
    run: async (owner, repo) => {
      const packages = await gh(`/repos/${owner}/${repo}/packages?package_type=container`)
      if (packages && Array.isArray(packages) && packages.length > 0) {
        return { pass: true, detail: `${packages.length} package(s) on GHCR` }
      }
      const orgPackages = await gh(`/orgs/${owner}/packages?package_type=container`)
      if (orgPackages && Array.isArray(orgPackages)) {
        const match = orgPackages.find((p) => p.repository?.name === repo)
        if (match) return { pass: true, detail: `Package "${match.name}" found in org` }
      }
      const userPackages = await gh(`/users/${owner}/packages?package_type=container`)
      if (userPackages && Array.isArray(userPackages)) {
        const match = userPackages.find((p) => p.repository?.name === repo)
        if (match) return { pass: true, detail: `Package "${match.name}" found for user` }
      }
      return { pass: false, detail: "No container packages found on GHCR" }
    },
  },

  quality_gate: {
    points: 10,
    category: "intermediate",
    label: "Quality gate (SonarCloud etc.)",
    run: async (owner, repo, _team, ctx) => {
      const realTools = [
        "sonarcloud-github-action", "SonarSource/sonarcloud",
        "sonar-scanner", "sonar.projectKey",
        "codeclimate/action", "paambaati/codeclimate-action",
        "codecov/codecov-action",
      ]
      for (const wf of ctx.workflows) {
        const result = stepIsReal(wf.content, realTools)
        if (result.found) return { pass: true, detail: `Quality gate: ${result.how}` }
        if (realTools.some((t) => wf.content.toLowerCase().includes(t.toLowerCase()))) {
          return { pass: true, detail: `Quality tool configured in ${wf.path}` }
        }
      }
      return { pass: false, detail: "No quality gate configured" }
    },
  },

  deployed: {
    points: 10,
    category: "intermediate",
    label: "App deployed (HTTP 200)",
    run: async (_owner, _repo, team) => {
      if (!team.deploy_url) return { pass: false, detail: "No deploy_url in teams.json" }
      try {
        const controller = new AbortController()
        const timeout = setTimeout(() => controller.abort(), 30000)
        const res = await fetch(team.deploy_url, { signal: controller.signal })
        clearTimeout(timeout)
        if (!res.ok) return { pass: false, detail: `${team.deploy_url} → HTTP ${res.status}` }

        const body = await res.text()
        const isOurApp = body.includes("Enhanced") || body.includes("Todo") || body.includes("todo")
        if (!isOurApp) {
          return { pass: false, detail: `${team.deploy_url} → HTTP 200 but not our Todo API (wrong app?)` }
        }
        return { pass: true, detail: `${team.deploy_url} → HTTP ${res.status} ✅ (Todo API verified)` }
      } catch (e) {
        return { pass: false, detail: `${team.deploy_url} → ${e.message}` }
      }
    },
  },

  branch_protection: {
    points: 5,
    category: "advanced",
    label: "Branch protection",
    run: async (owner, repo, team) => {
      const prot = await gh(`/repos/${owner}/${repo}/branches/${team.branch}/protection`)
      if (!prot || prot.message) return { pass: false, detail: `No branch protection on ${team.branch}` }
      const prRequired = prot.required_pull_request_reviews
      return {
        pass: !!prRequired,
        detail: prRequired ? "PR required before merge ✅" : "Protection exists but PR not required",
      }
    },
  },

  auto_deploy: {
    points: 10,
    category: "advanced",
    label: "Auto-deploy on push to branch",
    run: async (owner, repo, team, ctx) => {
      const deployKeywords = [
        "render.com", "api.render.com", "fly deploy", "flyctl deploy",
        "railway", "deploy", "ssh", "rsync",
      ]
      for (const wf of ctx.workflows) {
        const lower = wf.content.toLowerCase()
        const triggersOnBranch =
          (lower.includes("push") && lower.includes(team.branch)) ||
          lower.includes(`branches: [${team.branch}]`) ||
          lower.includes(`branches: [ ${team.branch} ]`) ||
          lower.includes("branches:\n")
        if (!triggersOnBranch) continue

        const result = stepIsReal(wf.content, deployKeywords)
        if (result.found) {
          return { pass: true, detail: `Deploy on push to ${team.branch}: ${result.how} in ${wf.path}` }
        }
      }
      return { pass: false, detail: "No auto-deploy workflow found" }
    },
  },

  multi_env: {
    points: 10,
    category: "advanced",
    label: "Multiple environments",
    run: async (owner, repo, _team, ctx) => {
      for (const wf of ctx.workflows) {
        const lower = wf.content.toLowerCase()
        const hasStaging = lower.includes("environment: staging") || /environment:\s*\n\s*name:\s*staging/.test(lower)
        const hasProd = lower.includes("environment: production") || lower.includes("environment: prod") || /environment:\s*\n\s*name:\s*production/.test(lower) || /environment:\s*\n\s*name:\s*prod/.test(lower)
        if (hasStaging && hasProd) return { pass: true, detail: `Staging + production environments in ${wf.path}` }
      }
      return { pass: false, detail: "No multiple environments (need both staging + production)" }
    },
  },

  pipeline_fast: {
    points: 5,
    category: "advanced",
    label: "Pipeline < 3 minutes",
    run: async (owner, repo, team) => {
      const runs = await gh(`/repos/${owner}/${repo}/actions/runs?branch=${team.branch}&status=success&per_page=3`)
      if (!runs?.workflow_runs?.length) return { pass: false, detail: "No successful runs" }
      let totalMs = 0
      let count = 0
      for (const run of runs.workflow_runs) {
        const start = new Date(run.created_at)
        const end = new Date(run.updated_at)
        totalMs += end - start
        count++
      }
      const avgMin = totalMs / count / 60000
      return {
        pass: avgMin < 3,
        detail: `Average: ${avgMin.toFixed(1)} min (last ${count} runs)`,
      }
    },
  },

  dependabot: {
    points: 5,
    category: "advanced",
    label: "Dependabot/Renovate configured",
    run: async (owner, repo, team) => {
      const depbot = await ghRaw(owner, repo, ".github/dependabot.yml", team.branch) || await ghRaw(owner, repo, ".github/dependabot.yaml", team.branch)
      if (depbot && depbot.includes("package-ecosystem")) {
        return { pass: true, detail: "dependabot config with valid setup" }
      }
      const renovate = await ghRaw(owner, repo, "renovate.json", team.branch) || await ghRaw(owner, repo, ".github/renovate.json", team.branch)
      if (renovate && renovate.includes("extends")) {
        return { pass: true, detail: "renovate.json with valid config" }
      }
      return { pass: false, detail: "No valid dependency update config" }
    },
  },
}

// ---------------------------------------------------------------------------
// Coverage badge helper
// ---------------------------------------------------------------------------

const TRUSTED_BADGE_PROVIDERS = [
  { pattern: /codecov\.io\/gh\/[^/]+\/[^/]+/, name: "Codecov" },
  { pattern: /coveralls\.io\/repos\/github\/[^/]+\/[^/]+/, name: "Coveralls" },
  { pattern: /sonarcloud\.io\/api\/project_badges\/measure.*metric=coverage/, name: "SonarCloud" },
  { pattern: /codeclimate\.com\/github\/[^/]+\/[^/]+\/badges/, name: "CodeClimate" },
  { pattern: /app\.codacy\.com\/project\/badge\/Coverage/, name: "Codacy" },
]

const parseCoverageBadge = async (owner, repo, branch) => {
  const readme = await ghRaw(owner, repo, "README.md", branch)
  if (!readme) return null

  const imgRegex = /!\[[^\]]*\]\(([^)]+)\)/g
  const htmlImgRegex = /<img[^>]+src="([^"]+)"/g
  const urls = []
  let m
  while ((m = imgRegex.exec(readme))) urls.push(m[1])
  while ((m = htmlImgRegex.exec(readme))) urls.push(m[1])

  for (const url of urls) {
    const provider = TRUSTED_BADGE_PROVIDERS.find((p) => p.pattern.test(url))
    if (!provider) continue

    try {
      const res = await fetch(url, { headers: { Accept: "image/svg+xml" } })
      if (!res.ok) continue
      const svg = await res.text()
      const pctMatch = svg.match(/(\d{1,3}(?:\.\d+)?)\s*%/)
      if (pctMatch) return { coverage: parseFloat(pctMatch[1]), provider: provider.name, url }
    } catch {
      continue
    }
  }

  return null
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
      const badge = ctx.coverageBadge
      if (!badge) return { pass: false, detail: "No trusted coverage badge in README" }
      return { pass: badge.coverage >= 80, detail: `${badge.coverage}% via ${badge.provider}` }
    },
  },

  coverage_90: {
    points: 5,
    category: "bonus",
    label: "Coverage ≥ 90%",
    run: async (owner, repo, _team, ctx) => {
      const badge = ctx.coverageBadge
      if (!badge) return { pass: false, detail: "No trusted coverage badge in README" }
      return { pass: badge.coverage >= 90, detail: `${badge.coverage}% via ${badge.provider}` }
    },
  },

  coverage_95: {
    points: 5,
    category: "bonus",
    label: "Coverage ≥ 95%",
    run: async (owner, repo, _team, ctx) => {
      const badge = ctx.coverageBadge
      if (!badge) return { pass: false, detail: "No trusted coverage badge in README" }
      return { pass: badge.coverage >= 95, detail: `${badge.coverage}% via ${badge.provider}` }
    },
  },

  conventional_commits: {
    points: 5,
    category: "bonus",
    label: "Conventional commits",
    run: async (owner, repo, team) => {
      const commits = await gh(`/repos/${owner}/${repo}/commits?sha=${team.branch}&per_page=20`)
      if (!commits || !Array.isArray(commits) || commits.length === 0) {
        return { pass: false, detail: "No commits found" }
      }
      const conventionalRegex = /^(feat|fix|docs|style|refactor|test|chore|ci|build|perf|revert)(\(.+\))?!?:\s/
      let conventional = 0
      for (const c of commits) {
        const msg = c.commit.message
        if (conventionalRegex.test(msg)) {
          conventional++
        } else {
          const lines = msg.split("\n").filter((l) => l.trim())
          const bodyConventional = lines.filter((l) => conventionalRegex.test(l.replace(/^\*\s*/, ""))).length
          if (bodyConventional >= 2) conventional++
        }
      }
      const pct = Math.round((conventional / commits.length) * 100)
      return {
        pass: pct >= 80,
        detail: `${conventional}/${commits.length} conventional (${pct}%)`,
      }
    },
  },

  readme_badges: {
    points: 5,
    category: "bonus",
    label: "README with badges",
    run: async (owner, repo, team) => {
      const readme = await ghRaw(owner, repo, "README.md", team.branch)
      if (!readme) return { pass: false, detail: "No README.md" }

      const badgePatterns = [
        /!\[.*?\]\(https?:\/\/.*?badge.*?\)/gi,
        /!\[.*?\]\(https?:\/\/.*?shields\.io.*?\)/gi,
        /!\[.*?\]\(https?:\/\/.*?github\.com\/.*?actions\/workflows.*?\)/gi,
        /!\[.*?\]\(https?:\/\/.*?codecov\.io.*?\)/gi,
        /!\[.*?\]\(https?:\/\/.*?sonarcloud\.io.*?\)/gi,
      ]

      const allBadges = new Set()
      for (const p of badgePatterns) {
        let m
        while ((m = p.exec(readme))) allBadges.add(m[0])
      }

      return {
        pass: allBadges.size >= 2,
        detail: `${allBadges.size} badge(s) found`,
      }
    },
  },
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const scoreTeam = async (team) => {
  const cleanRepo = team.repo.replace(/\.git$/, "")
  const [owner, repo] = cleanRepo.split("/")
  const branch = team.branch ?? "main"
  const teamWithBranch = { ...team, branch }

  console.log(`\n🔍 Scoring ${team.team} (${team.repo} @ ${branch})...`)

  const { tree, workflows } = await getWorkflows(owner, repo, branch)
  const coverageBadge = await parseCoverageBadge(owner, repo, branch)
  const ctx = { tree, workflows, coverageBadge }

  const results = {}
  let total = 0
  let maxTotal = 0

  console.log(`  --- Core checks ---`)
  for (const [key, check] of Object.entries(CHECKS)) {
    try {
      const result = await check.run(owner, repo, teamWithBranch, ctx)
      results[key] = { ...result, points: check.points, label: check.label, category: check.category }
      if (result.pass) total += check.points
      maxTotal += check.points
      const icon = result.pass ? "✅" : "❌"
      console.log(`  ${icon} ${check.label} (${result.pass ? check.points : 0}/${check.points}) — ${result.detail}`)
    } catch (e) {
      results[key] = { pass: false, points: check.points, label: check.label, category: check.category, detail: `Error: ${e.message}` }
      maxTotal += check.points
      console.log(`  ⚠️  ${check.label} — Error: ${e.message}`)
    }
  }

  let bonus = 0
  let maxBonus = 0
  const bonusResults = {}

  console.log(`  --- Bonus ---`)
  for (const [key, check] of Object.entries(BONUS_CHECKS)) {
    try {
      const result = await check.run(owner, repo, teamWithBranch, ctx)
      bonusResults[key] = { ...result, points: check.points, label: check.label, category: check.category }
      if (result.pass) bonus += check.points
      maxBonus += check.points
      const icon = result.pass ? "⭐" : "☆"
      console.log(`  ${icon} ${check.label} (${result.pass ? check.points : 0}/${check.points}) — ${result.detail}`)
    } catch (e) {
      bonusResults[key] = { pass: false, points: check.points, label: check.label, category: check.category, detail: `Error: ${e.message}` }
      maxBonus += check.points
      console.log(`  ⚠️  ${check.label} — Error: ${e.message}`)
    }
  }

  return {
    team: team.team, members: team.members, repo: team.repo, branch, deploy_url: team.deploy_url,
    total, maxTotal, bonus, maxBonus, grandTotal: total + bonus,
    results, bonusResults,
  }
}

const main = async () => {
  const teams = JSON.parse(readFileSync("teams.json", "utf-8"))
  const scores = []

  for (const team of teams) {
    scores.push(await scoreTeam(team))
  }

  scores.sort((a, b) => b.grandTotal - a.grandTotal)
  scores.forEach((s, i) => (s.rank = i + 1))

  const output = {
    generated_at: new Date().toISOString(),
    total_possible: Object.values(CHECKS).reduce((s, c) => s + c.points, 0),
    bonus_possible: Object.values(BONUS_CHECKS).reduce((s, c) => s + c.points, 0),
    teams: scores,
  }

  mkdirSync("docs", { recursive: true })
  writeFileSync("docs/scores.json", JSON.stringify(output, null, 2))
  console.log(`\n📊 Scores written to docs/scores.json`)
  console.log(`\n🏆 Leaderboard:`)
  for (const s of scores) {
    const bonusStr = s.bonus > 0 ? ` (+${s.bonus} bonus)` : ""
    console.log(`  #${s.rank} ${s.team} — ${s.total}/${s.maxTotal} pts${bonusStr}`)
  }
}

main().catch(console.error)

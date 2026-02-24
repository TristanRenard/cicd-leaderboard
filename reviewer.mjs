#!/usr/bin/env node
/**
 * CI/CD Code Reviewer — AI-powered code & documentation review
 *
 * Fetches student repos, sends code to an LLM, scores quality & docs.
 * Results saved to docs/reviews.json (used by the leaderboard).
 *
 * Usage:
 *   GITHUB_TOKEN=xxx OPENAI_API_KEY=xxx node reviewer.mjs
 *
 * Optional env:
 *   OPENAI_BASE_URL  — custom OpenAI-compatible endpoint (default: https://api.openai.com/v1)
 *   REVIEW_MODEL     — model to use (default: gpt-4o-mini)
 */

import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_BASE_URL = process.env.OPENAI_BASE_URL || "https://api.openai.com/v1";
const MODEL = process.env.REVIEW_MODEL || "gpt-4o-mini";

if (!GITHUB_TOKEN) { console.error("❌ GITHUB_TOKEN required"); process.exit(1); }
if (!OPENAI_API_KEY) { console.error("❌ OPENAI_API_KEY required"); process.exit(1); }

const GH_HEADERS = {
  Authorization: `Bearer ${GITHUB_TOKEN}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
};

// ---------------------------------------------------------------------------
// GitHub helpers
// ---------------------------------------------------------------------------

async function gh(path) {
  const res = await fetch(`https://api.github.com${path}`, { headers: GH_HEADERS });
  if (!res.ok) return null;
  return res.json();
}

async function ghRaw(owner, repo, path, branch = "main") {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
  const res = await fetch(url);
  if (!res.ok) return null;
  return res.text();
}

async function getRepoTree(owner, repo) {
  const data = await gh(`/repos/${owner}/${repo}/git/trees/main?recursive=1`);
  if (!data?.tree) return [];
  return data.tree.filter((f) => f.type === "blob");
}

// ---------------------------------------------------------------------------
// Source file fetching
// ---------------------------------------------------------------------------

const SOURCE_EXTS = [".py", ".js", ".ts", ".mjs"];
const SKIP_DIRS = ["node_modules", "__pycache__", ".git", ".github", "dist", "build", ".venv", "venv"];

function isSourceFile(path) {
  if (SKIP_DIRS.some((d) => path.includes(`${d}/`))) return false;
  return SOURCE_EXTS.some((ext) => path.endsWith(ext));
}

async function fetchSourceFiles(owner, repo) {
  const tree = await getRepoTree(owner, repo);
  const sourceFiles = tree.filter((f) => isSourceFile(f.path));

  // Limit to ~50 files / 100KB to avoid token explosion
  const files = [];
  let totalSize = 0;
  const MAX_SIZE = 100_000;
  const MAX_FILES = 50;

  for (const f of sourceFiles) {
    if (files.length >= MAX_FILES || totalSize >= MAX_SIZE) break;
    const content = await ghRaw(owner, repo, f.path);
    if (content) {
      const trimmed = content.slice(0, 5000); // max 5KB per file
      files.push({ path: f.path, content: trimmed });
      totalSize += trimmed.length;
    }
  }

  return files;
}

// ---------------------------------------------------------------------------
// LLM review
// ---------------------------------------------------------------------------

const RUBRIC = readFileSync(join(__dirname, "reviewer-prompt.md"), "utf-8");

async function reviewTeam(team, sourceFiles, readme) {
  const fileList = sourceFiles
    .map((f) => `--- ${f.path} ---\n${f.content}`)
    .join("\n\n");

  const prompt = `${RUBRIC}

## Team: ${team.team}
## Repo: ${team.repo}

### README.md
${readme || "(No README found)"}

### Source Files
${fileList || "(No source files found)"}

Now review this team. Output ONLY valid JSON matching the format in the rubric. Add a "tips" array with 2-3 actionable suggestions. Include relevant tips:
- If eval() present: mention RCE vulnerability
- If /debug endpoint: mention it exposes secrets
- If README is default: suggest real setup instructions + badges
- If no Swagger: suggest adding it (FastAPI built-in, swagger-jsdoc for Express)
- If hardcoded secrets: suggest .env
- If no .env.example: suggest adding one
- If squash merges: suggest conventional commit PR titles`;

  const res = await fetch(`${OPENAI_BASE_URL}/chat/completions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: MODEL,
      messages: [
        { role: "system", content: "You are a fair, consistent code reviewer for a CI/CD course. Output ONLY valid JSON, no markdown fences." },
        { role: "user", content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 1500,
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    console.error(`  ⚠️  LLM error for ${team.team}: ${res.status} ${err.slice(0, 200)}`);
    return null;
  }

  const data = await res.json();
  const raw = data.choices?.[0]?.message?.content?.trim();
  if (!raw) return null;

  // Strip markdown fences if present
  const cleaned = raw.replace(/^```json?\s*/i, "").replace(/\s*```$/i, "");

  try {
    return JSON.parse(cleaned);
  } catch (e) {
    console.error(`  ⚠️  Invalid JSON from LLM for ${team.team}:`, cleaned.slice(0, 300));
    return null;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const teams = JSON.parse(readFileSync(join(__dirname, "teams.json"), "utf-8"));
  const results = [];

  console.log(`🔍 Reviewing ${teams.length} teams with ${MODEL}...\n`);

  for (const team of teams) {
    if (!team.repo) {
      console.log(`⏭️  ${team.team} — no repo, skipping`);
      results.push({
        team: team.team,
        repo: "",
        code_quality: { score: 0, details: "No repo configured" },
        documentation: { score: 0, details: "No repo configured" },
        total: 0,
        summary: "No repository",
        tips: [],
      });
      continue;
    }

    const repo = team.repo.replace(/\.git$/, "");
    const [owner, repoName] = repo.split("/");
    console.log(`📖 ${team.team} (${repo})...`);

    // Fetch source code + README
    const sourceFiles = await fetchSourceFiles(owner, repoName);
    const readme = await ghRaw(owner, repoName, "README.md");

    console.log(`   ${sourceFiles.length} source files fetched`);

    const review = await reviewTeam(team, sourceFiles, readme);
    if (review) {
      review.team = team.team;
      review.repo = repo;
      results.push(review);
      console.log(`   ✅ ${review.total}/20`);
    } else {
      results.push({
        team: team.team,
        repo,
        code_quality: { score: 0, details: "Review failed" },
        documentation: { score: 0, details: "Review failed" },
        total: 0,
        summary: "Review error",
        tips: [],
      });
      console.log(`   ❌ Review failed`);
    }

    // Small delay to avoid rate limits
    await new Promise((r) => setTimeout(r, 1000));
  }

  // Save results
  const output = {
    generated_at: new Date().toISOString(),
    model: MODEL,
    teams: results,
  };

  mkdirSync(join(__dirname, "docs"), { recursive: true });
  const outPath = join(__dirname, "docs", "reviews.json");
  writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`\n💾 Saved to ${outPath}`);

  // Summary
  console.log("\n📊 Summary:");
  const sorted = [...results].sort((a, b) => b.total - a.total);
  for (const r of sorted) {
    const bar = "█".repeat(r.total) + "░".repeat(20 - r.total);
    console.log(`  ${bar} ${r.total}/20  ${r.team}`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });

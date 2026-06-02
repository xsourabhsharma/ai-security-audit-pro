#!/usr/bin/env node
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, "..");
const cli = path.join(root, "scripts", "security-audit.mjs");

async function main() {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "security-audit-pro-selftest-"));
  try {
    await writeFixture(temp);
    const reportPath = path.join(temp, "report.json");
    const result = await runNode([
      cli,
      "--target", temp,
      "--json",
      "--out", reportPath,
      "--no-tools"
    ], root);

    if (result.error || result.code !== 0) {
      throw new Error(`CLI self-test scan failed: ${result.error || result.stderr || result.stdout}`);
    }

    const report = JSON.parse(await fs.readFile(reportPath, "utf8"));
    const ids = new Set(report.findings.map((finding) => finding.id));
    const categories = new Set(report.findings.map((finding) => finding.category));

    assertHasCategory(categories, "Authorization review hotspot");
    assertHasCategory(categories, "Token/session security");
    assertHasCategory(categories, "Client-side exposure");
    assertHasCategory(categories, "Client-side token storage");
    assertHasCategory(categories, "CI/CD security");
    assertHasIdPrefix(ids, "idor-bola-review-");
    assertHasIdPrefix(ids, "privilege-field-body-");
    assertHasIdPrefix(ids, "jwt-decode-without-verify-");
    assertHasIdPrefix(ids, "public-sensitive-env-");
    assertHasIdPrefix(ids, "browser-token-storage-");
    assertHasIdPrefix(ids, "gha-pr-target-write-all-");

    console.log("security-audit-pro selftest passed");
  } finally {
    await fs.rm(temp, { recursive: true, force: true }).catch(() => {});
  }
}

async function writeFixture(temp) {
  await fs.mkdir(path.join(temp, "src"), { recursive: true });
  await fs.mkdir(path.join(temp, ".github", "workflows"), { recursive: true });
  await fs.writeFile(path.join(temp, "package.json"), JSON.stringify({
    name: "security-audit-pro-selftest-fixture",
    dependencies: { express: "latest", jsonwebtoken: "latest" }
  }, null, 2));

  const jwtDecode = ["jwt", "decode"].join(".");
  const localStorageSetItem = ["localStorage", "setItem"].join(".");
  const publicSecretName = ["NEXT_PUBLIC", "PAYMENT", "SECRET"].join("_");
  const prTarget = ["pull_request", "target"].join("_");
  const appGetCandidate = ["app.", "get", '("/candidate/:id", async (req, res) => {'].join("");
  const appPostUser = ["app.", "post", '("/admin/user/:id", async (req, res) => {'].join("");
  const requestParamId = ["req", "params", "id"].join(".");
  const requestBodyRole = ["req", "body", "role"].join(".");
  await fs.writeFile(path.join(temp, "src", "app.js"), [
    'import express from "express";',
    'import jwt from "jsonwebtoken";',
    "",
    "const app = express();",
    "",
    appGetCandidate,
    `  const candidate = await prisma.candidate.findUnique({ where: { id: ${requestParamId} } });`,
    "  res.json(candidate);",
    "});",
    "",
    appPostUser,
    `  await prisma.user.update({ where: { id: ${requestParamId} }, data: { role: ${requestBodyRole} } });`,
    "  res.json({ ok: true });",
    "});",
    "",
    'app.get("/claims", (req, res) => {',
    `  const claims = ${jwtDecode}(req.headers.authorization);`,
    "  res.json(claims);",
    "});",
    "",
    `window.${localStorageSetItem}("accessToken", token);`,
    `const ${publicSecretName} = "redacted-test-value";`,
    ""
  ].join("\n"));

  await fs.writeFile(path.join(temp, ".github", "workflows", "review.yml"), [
    "name: review",
    "on:",
    `  ${prTarget}:`,
    "permissions: write-all",
    "jobs:",
    "  review:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: some/action@main",
    '      - run: echo "${{ github.event.pull_request.title }}"',
    ""
  ].join("\n"));
}

function assertHasCategory(categories, category) {
  if (!categories.has(category)) {
    throw new Error(`Expected finding category was not detected: ${category}`);
  }
}

function assertHasIdPrefix(ids, prefix) {
  if (![...ids].some((id) => id.startsWith(prefix))) {
    throw new Error(`Expected finding id prefix was not detected: ${prefix}`);
  }
}

function runNode(args, cwd) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    const child = spawn(process.execPath, args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (error) => {
      resolve({ error: error.message, stdout, stderr, code: -1 });
    });
    child.on("close", (code) => {
      resolve({ stdout, stderr, code });
    });
  });
}

main().catch((error) => {
  console.error(`security-audit-pro selftest failed: ${error.message}`);
  process.exitCode = 1;
});

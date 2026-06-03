#!/usr/bin/env node
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import tls from "node:tls";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pluginRoot = path.resolve(__dirname, "..");
const rulesPath = path.join(pluginRoot, "assets", "audit-rules.json");
const discoveryWordlistPath = path.join(pluginRoot, "assets", "web-paths-small.txt");
const bundledToolDirs = uniquePaths([
  path.join(pluginRoot, "tools"),
  path.join(pluginRoot, "tools", "bin"),
  path.join(pluginRoot, "tools", "nuclei"),
  path.join(process.cwd(), "tools"),
  path.join(process.cwd(), "tools", "bin"),
  path.join(process.cwd(), "tools", "nuclei"),
  path.join(os.homedir(), "go", "bin"),
  path.join(os.homedir(), ".local", "bin"),
  path.join(os.homedir(), "AppData", "Roaming", "Python", "Python314", "Scripts"),
  process.env.SECURITY_AUDIT_TOOLS_DIR
].filter(Boolean));

const severityRank = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const textExtensions = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".py", ".go", ".rs",
  ".php", ".rb", ".java", ".kt", ".cs", ".html", ".css", ".scss", ".vue",
  ".svelte", ".md", ".yml", ".yaml", ".toml", ".ini", ".env", ".sh", ".ps1",
  ".Dockerfile"
]);

const sourceCodeExtensions = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rs", ".php",
  ".rb", ".java", ".kt", ".cs", ".html", ".vue", ".svelte"
]);

const excludedDirs = new Set([
  ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt", "coverage",
  ".turbo", ".cache", ".venv", "venv", "__pycache__", "target", "bin", "obj"
]);

function parseArgs(argv) {
  const args = {
    target: ".",
    mode: "passive",
    out: "",
    htmlOut: "",
    pdfOut: "",
    diffBase: "",
    profile: "balanced",
    scopeFile: "",
    json: false,
    authorized: process.env.SECURITY_AUDIT_AUTHORIZED === "1",
    maxFiles: 2500,
    maxBytes: 750000,
    runTools: true
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--target" || arg === "-t") {
      args.target = argv[++i];
    } else if (arg === "--mode" || arg === "-m") {
      args.mode = argv[++i];
    } else if (arg === "--out" || arg === "-o") {
      args.out = argv[++i];
    } else if (arg === "--html-out") {
      args.htmlOut = argv[++i];
    } else if (arg === "--pdf-out") {
      args.pdfOut = argv[++i];
    } else if (arg === "--diff-base") {
      args.diffBase = argv[++i];
    } else if (arg === "--profile") {
      args.profile = argv[++i];
    } else if (arg === "--scope-file") {
      args.scopeFile = argv[++i];
    } else if (arg === "--json") {
      args.json = true;
    } else if (arg === "--authorized") {
      args.authorized = true;
    } else if (arg === "--max-files") {
      args.maxFiles = Number(argv[++i]);
    } else if (arg === "--max-bytes") {
      args.maxBytes = Number(argv[++i]);
    } else if (arg === "--no-tools") {
      args.runTools = false;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!["passive", "standard", "active"].includes(args.mode)) {
    throw new Error("--mode must be passive, standard, or active");
  }
  if (!["safe", "balanced", "deep"].includes(args.profile)) {
    throw new Error("--profile must be safe, balanced, or deep");
  }
  return args;
}

function usage() {
  return `Security Audit Pro

Usage:
  node scripts/security-audit.mjs --target <path-or-url> [--mode passive|standard|active] [--out report.md] [--json]

Modes:
  passive   Local checks and one fetch of the supplied URL.
  standard  Adds shallow exposure checks for authorized targets.
  active    May invoke installed DAST tools. Use only with explicit authorization.

Options:
  --no-tools       Skip external scanner commands.
  --authorized     Required for standard/active URL probing.
  --profile NAME   Active URL profile: safe, balanced, or deep. Default: balanced.
  --scope-file F   Auth/business/API scope file to include in the report.
  --diff-base REF  Local project mode: scan changed files from REF instead of every collected file.
  --html-out FILE  Also write a self-contained HTML report.
  --pdf-out FILE   Also write a PDF report when Python reportlab is available.
  --max-files N    Limit local file scan count. Default: 2500.
  --max-bytes N    Skip files larger than N bytes. Default: 750000.
`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }

  const rules = JSON.parse(await fs.readFile(rulesPath, "utf8"));
  const startedAt = new Date().toISOString();
  const report = {
    tool: "security-audit-pro",
    startedAt,
    mode: args.mode,
    profile: args.profile,
    authorized: args.authorized,
    target: args.target,
    findings: [],
    checks: [],
    skipped: [],
    tools: [],
    coverage: [],
    reviewedSurfaces: [],
    inventory: {}
  };

  await loadScopeFile(args, report);

  if (isUrl(args.target)) {
    await auditUrl(args.target, args, rules, report);
  } else {
    await auditPath(path.resolve(args.target), args, rules, report);
  }

  sortFindings(report.findings);
  const markdown = renderMarkdown(report);
  const output = args.json ? JSON.stringify(report, null, 2) : markdown;

  if (args.out) {
    await fs.writeFile(path.resolve(args.out), output, "utf8");
    console.log(`Wrote ${args.json ? "JSON" : "Markdown"} report: ${path.resolve(args.out)}`);
  } else {
    console.log(output);
  }

  if (args.htmlOut) {
    await fs.writeFile(path.resolve(args.htmlOut), renderHtml(report, markdown), "utf8");
    console.log(`Wrote HTML report: ${path.resolve(args.htmlOut)}`);
  }
  if (args.pdfOut) {
    await writePdfReport(path.resolve(args.pdfOut), markdown);
    console.log(`Wrote PDF report: ${path.resolve(args.pdfOut)}`);
  }
}

function isUrl(value) {
  return /^https?:\/\//i.test(value);
}

async function loadScopeFile(args, report) {
  if (!args.scopeFile) {
    recordCoverage(report, "Authenticated and business-logic testing", "scope file", "not-configured", "No --scope-file was supplied.");
    report.skipped.push("Authenticated, role-based, and business-logic testing need --scope-file plus dedicated test accounts/workflows.");
    return;
  }

  const file = path.resolve(args.scopeFile);
  const text = await fs.readFile(file, "utf8").catch(() => "");
  if (!text) {
    report.skipped.push(`Scope file could not be read: ${file}`);
    recordCoverage(report, "Authenticated and business-logic testing", "scope file", "failed", "Scope file could not be read.");
    return;
  }

  const summary = summarizeScopeFile(text);
  report.inventory.scopeFile = file;
  report.inventory.authScope = summary;
  report.checks.push("Authenticated/business-logic scope file loaded");
  recordCoverage(report, "Authenticated and business-logic testing", "scope file", "planned", "Scope file loaded; role and workflow checks can be executed when credentials are supplied out-of-band.");
}

function summarizeScopeFile(text) {
  const lines = text.split(/\r?\n/);
  const values = {};
  for (const line of lines) {
    const match = line.match(/^\s*[-*]?\s*([^:#]{3,80}):\s*(.+?)\s*$/);
    if (!match) continue;
    const key = match[1].trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
    if (!values[key]) values[key] = match[2].trim();
  }

  const roles = lines
    .map((line) => line.match(/role\s*\d*\s*name:\s*(.+)$/i)?.[1]?.trim())
    .filter(Boolean);
  const workflows = [
    "registration_login_password_reset",
    "profile_or_account_settings",
    "user_to_user_object_access",
    "payments_credits_subscriptions_refunds_or_orders",
    "file_upload_download_import_export",
    "admin_or_staff_actions",
    "notifications_email_webhooks_or_callbacks",
    "rate_limits_or_quota_sensitive_flows"
  ].filter((key) => values[key]);

  return {
    primaryUrl: values.primary_url || values.target_url || "",
    roles: unique(roles),
    workflows,
    outOfScope: values.out_of_scope_domains_paths_tenants_or_third_party_services || "",
    maxRate: values.maximum_request_rate_or_concurrency || "",
    testWindow: values.preferred_test_window_and_timezone || ""
  };
}

async function auditPath(root, args, rules, report) {
  const stat = await fs.stat(root).catch(() => null);
  if (!stat) {
    throw new Error(`Target path not found: ${root}`);
  }

  report.inventory.kind = "local-project";
  report.inventory.root = root;
  report.checks.push("Local file inventory");

  const files = await collectFiles(root, args.maxFiles, args.maxBytes);
  let scanFiles = files;
  if (args.diffBase) {
    scanFiles = await filterDiffFiles(root, files, args.diffBase, report);
  }
  report.inventory.scannedFiles = scanFiles.length;
  report.inventory.collectedFiles = files.length;
  if (files.truncated) {
    report.skipped.push(`File scan stopped at --max-files=${args.maxFiles}.`);
  }

  await detectProjectStack(root, files, report);
  await scanLocalPatterns(root, scanFiles, rules, report);
  await scanSecretPatterns(root, scanFiles, rules, report);
  await checkSensitiveLocalFiles(root, report);
  await detectApiArtifacts(root, files, report);
  await analyzeWebRoutes(root, scanFiles, report);
  await analyzeAuthorizationAndBusinessLogicHotspots(root, scanFiles, report);
  await scanAuthTokenAndSessionHotspots(root, scanFiles, report);
  await scanClientExposurePatterns(root, scanFiles, report);
  await scanCiCdSecurityHotspots(root, files, report);
  addLocalReviewedSurfaces(report);

  if (args.runTools) {
    await runLocalToolChecks(root, report);
  } else {
    report.skipped.push("External scanners skipped by --no-tools.");
  }
}

async function filterDiffFiles(root, files, diffBase, report) {
  const result = await runCommand("git", ["diff", "--name-only", "--diff-filter=ACMR", diffBase, "--"], root, 30000);
  report.checks.push("Git diff scope resolution");
  if (result.error || result.code !== 0) {
    report.skipped.push(`Diff scope could not be resolved from ${diffBase}; scanning all collected files. ${result.error || result.stderr.slice(0, 160)}`);
    return files;
  }
  const changed = new Set(result.stdout.split(/\r?\n/).filter(Boolean).map((item) => path.normalize(item)));
  report.inventory.diffBase = diffBase;
  report.inventory.diffFiles = changed.size;
  const scoped = files.filter((file) => changed.has(path.normalize(path.relative(root, file))));
  if (!scoped.length) {
    report.skipped.push(`No source-like files from --diff-base ${diffBase} matched the scanner file inventory.`);
  }
  return scoped;
}

async function collectFiles(root, maxFiles, maxBytes) {
  const files = [];
  files.truncated = false;

  async function walk(dir) {
    if (files.length >= maxFiles) {
      files.truncated = true;
      return;
    }

    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (files.length >= maxFiles) {
        files.truncated = true;
        return;
      }

      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!excludedDirs.has(entry.name)) {
          await walk(full);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        const isDockerfile = entry.name === "Dockerfile";
        const isEnv = entry.name.startsWith(".env");
        if (!textExtensions.has(ext) && !isDockerfile && !isEnv) {
          continue;
        }
        const stat = await fs.stat(full).catch(() => null);
        if (stat && stat.size <= maxBytes) {
          files.push(full);
        }
      }
    }
  }

  await walk(root);
  return files;
}

async function detectProjectStack(root, files, report) {
  const names = new Set(files.map((file) => path.basename(file)));
  const extensions = new Set(files.map((file) => path.extname(file)).filter(Boolean));
  const stacks = [];

  if (names.has("package.json")) stacks.push("javascript/typescript");
  if (names.has("requirements.txt") || names.has("pyproject.toml")) stacks.push("python");
  if (names.has("go.mod")) stacks.push("go");
  if (names.has("Cargo.toml")) stacks.push("rust");
  if (names.has("composer.json")) stacks.push("php");
  if (extensions.has(".csproj")) stacks.push("dotnet");

  report.inventory.stacks = stacks;
  report.inventory.lockfiles = [...names].filter((name) => [
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt", "poetry.lock",
    "Pipfile.lock", "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock"
  ].includes(name));

  const packageJson = path.join(root, "package.json");
  const packageData = await readJson(packageJson);
  if (packageData) {
    const deps = {
      dependencies: Object.keys(packageData.dependencies || {}).length,
      devDependencies: Object.keys(packageData.devDependencies || {}).length
    };
    report.inventory.nodeDependencies = deps;
    const allDeps = {
      ...(packageData.dependencies || {}),
      ...(packageData.devDependencies || {})
    };
    for (const framework of ["next", "express", "react", "vue", "svelte", "fastify", "koa"]) {
      if (allDeps[framework]) {
        report.inventory.frameworks = [...(report.inventory.frameworks || []), framework];
      }
    }
  }

  report.checks.push("Project stack and lockfile detection");
}

async function scanLocalPatterns(root, files, rules, report) {
  report.checks.push("Static high-signal source pattern scan");
  const compiled = rules.localPatterns.map((rule) => ({
    ...rule,
    matcher: new RegExp(rule.regex, rule.flags ? `${rule.flags}g` : "g")
  }));

  for (const file of files.filter(isSourceCodeFile)) {
    const rel = path.relative(root, file);
    const text = await fs.readFile(file, "utf8").catch(() => "");
    if (!text) continue;
    const lines = text.split(/\r?\n/);

    for (const rule of compiled) {
      for (let index = 0; index < lines.length; index += 1) {
        if (isRuleMetadataLine(lines[index])) continue;
        rule.matcher.lastIndex = 0;
        if (rule.matcher.test(lines[index])) {
          addFinding(report, {
            id: rule.id,
            title: rule.message,
            severity: rule.severity,
            category: "Local source pattern",
            location: `${rel}:${index + 1}`,
            evidence: trimEvidence(lines[index]),
            owasp: rule.owasp,
            cwe: rule.cwe,
            remediation: remediationForRule(rule.id)
          });
        }
      }
    }
  }
}

async function detectApiArtifacts(root, files, report) {
  report.checks.push("API definition artifact detection");
  const apiFiles = [];
  for (const file of files) {
    const rel = path.relative(root, file).replaceAll("\\", "/");
    const name = path.basename(file).toLowerCase();
    if (
      name.includes("openapi") ||
      name.includes("swagger") ||
      name.endsWith(".graphql") ||
      name.endsWith(".graphqls") ||
      name.includes("postman_collection")
    ) {
      apiFiles.push(rel);
    }
  }
  report.inventory.apiArtifacts = apiFiles.slice(0, 25);
  if (apiFiles.length) {
    addFinding(report, {
      id: "api-artifacts-present",
      title: "API definition artifacts found",
      severity: "info",
      category: "API security",
      location: apiFiles.slice(0, 5).join(", "),
      evidence: `${apiFiles.length} API definition file(s) detected.`,
      owasp: "API9:2023 Improper Inventory Management",
      remediation: "Use these definitions to run API-specific auth, object authorization, rate-limit, schema validation, and ZAP API scans."
    });
  }
}

async function analyzeWebRoutes(root, files, report) {
  report.checks.push("Route and authorization hotspot inventory");
  const endpoints = [];
  const routePatterns = [
    {
      stack: "express",
      regex: /\b(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/i
    },
    {
      stack: "fastapi-or-flask",
      regex: /@\w+\.(get|post|put|patch|delete|route)\s*\(\s*['"`]([^'"`]+)['"`]/i
    },
    {
      stack: "django",
      regex: /\bpath\s*\(\s*['"`]([^'"`]+)['"`]/i
    }
  ];
  const authKeywords = /\b(auth|authorize|permission|policy|isAuthenticated|requireUser|requireAuth|currentUser|jwt|session|csrf|Depends|Security|login_required)\b/i;

  for (const file of files.filter(isSourceCodeFile)) {
    const rel = path.relative(root, file);
    const text = await fs.readFile(file, "utf8").catch(() => "");
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      for (const pattern of routePatterns) {
        const match = lines[index].match(pattern.regex);
        if (!match) continue;
        const method = pattern.stack === "django" ? "route" : match[1].toLowerCase();
        const route = pattern.stack === "django" ? match[1] : match[2];
        const location = `${rel}:${index + 1}`;
        const start = Math.max(0, index - 6);
        const end = Math.min(lines.length, index + 12);
        const neighborhood = lines.slice(start, end).join("\n");
        const hasNearbyAuth = authKeywords.test(neighborhood);
        endpoints.push({ method, route, location, stack: pattern.stack, hasNearbyAuth });

        if (["post", "put", "patch", "delete"].includes(method) && !hasNearbyAuth) {
          addFinding(report, {
            id: `route-auth-hotspot-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
            title: "State-changing route needs authorization and CSRF review",
            severity: "low",
            category: "Authorization review hotspot",
            location,
            evidence: trimEvidence(lines[index]),
            owasp: "A01:2021 Broken Access Control",
            cwe: "CWE-862",
            remediation: "Verify authentication, object-level authorization, tenant boundaries, and CSRF protections for this state-changing route. Suppress if a framework-level guard covers it.",
            confidence: "low"
          });
        }
      }
    }
  }

  report.inventory.endpoints = endpoints.slice(0, 100);
  if (endpoints.length > 100) {
    report.skipped.push(`Endpoint inventory truncated at 100 of ${endpoints.length} detected routes.`);
  }
}

async function analyzeAuthorizationAndBusinessLogicHotspots(root, files, report) {
  report.checks.push("Authorization, IDOR/BOLA, and mass-assignment hotspot scan");
  const routeRegexes = [
    /\b(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/i,
    /@\w+\.(get|post|put|patch|delete|route)\s*\(\s*['"`]([^'"`]+)['"`]/i,
    /\bpath\s*\(\s*['"`]([^'"`]+)['"`]/i
  ];
  const objectRoute = /(?:[:/{<](?:id|userId|accountId|candidateId|studentId|roll|rollNo|rroll|orderId|paymentId|fileId|documentId|photoId)\b|\/(?:user|users|account|accounts|candidate|student|students|payment|payments|order|orders|file|files|download|photo|photos)\b)/i;
  const objectLookup = /\b(req\.params|request\.path_params|params\.|findById|findUnique|findFirst|findOne|where\s*:\s*\{|ObjectId\s*\(|SELECT\b[^;\n]+\bWHERE\b|\.doc\s*\(|\.collection\s*\()/i;
  const authzControl = /\b(authorize|authorized|permission|policy|canAccess|canView|canEdit|isOwner|ownerId|tenantId|orgId|organizationId|schoolId|createdBy|belongsTo|currentUser|current_user|req\.user|request\.user|session\.user|principal|acl|rbac|abac|Depends\s*\(|Security\s*\(|login_required)\b/i;
  const massAssignment = /\b(Object\.assign\s*\([^,\n]+,\s*(req|request)\.(body|json)|\.(create|update|updateMany|findOneAndUpdate)\s*\([^;\n]*(req|request)\.(body|json)|\bnew\s+\w+\s*\(\s*(req|request)\.(body|json)\s*\))/i;
  const privilegeFieldFromBody = /\b(role|roles|isAdmin|isSuperuser|permissions|scopes|verified|status)\b\s*[:=]\s*(req|request)\.(body|json|data)\b/i;

  for (const file of files.filter(isSourceCodeFile)) {
    const rel = path.relative(root, file);
    const text = await fs.readFile(file, "utf8").catch(() => "");
    if (!text) continue;
    const lines = text.split(/\r?\n/);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const routeMatch = routeRegexes.map((regex) => line.match(regex)).find(Boolean);
      if (routeMatch) {
        const route = routeMatch[2] || routeMatch[1] || "";
        const block = lineWindow(lines, index, 0, 45);
        if ((objectRoute.test(route) || objectLookup.test(block)) && objectLookup.test(block) && !authzControl.test(block)) {
          addFinding(report, {
            id: `idor-bola-review-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
            title: "Object lookup route needs IDOR/BOLA authorization review",
            severity: "medium",
            category: "Authorization review hotspot",
            location: `${rel}:${index + 1}`,
            evidence: trimEvidence(line),
            owasp: "API1:2023 Broken Object Level Authorization",
            cwe: "CWE-639",
            confidence: "low",
            remediation: "Verify this route checks authenticated user, tenant, role, and object ownership before returning or mutating records selected by path/body identifiers."
          });
        }
      }

      if (massAssignment.test(line)) {
        addFinding(report, {
          id: `mass-assignment-review-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "Mass-assignment hotspot uses request body directly",
          severity: "medium",
          category: "Authorization review hotspot",
          location: `${rel}:${index + 1}`,
          evidence: trimEvidence(line),
          owasp: "API3:2023 Broken Object Property Level Authorization",
          cwe: "CWE-915",
          confidence: "medium",
          remediation: "Map allowed fields explicitly, reject privilege and ownership fields from client input, and add tests for role/status/owner manipulation attempts."
        });
      }

      if (privilegeFieldFromBody.test(line)) {
        addFinding(report, {
          id: `privilege-field-body-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "Privilege or account-state field appears client-controlled",
          severity: "high",
          category: "Authorization review hotspot",
          location: `${rel}:${index + 1}`,
          evidence: trimEvidence(line),
          owasp: "API3:2023 Broken Object Property Level Authorization",
          cwe: "CWE-915",
          confidence: "medium",
          remediation: "Never accept role, permission, verification, or account-state fields directly from ordinary client requests. Derive them server-side from trusted authorization logic."
        });
      }
    }
  }
}

async function scanAuthTokenAndSessionHotspots(root, files, report) {
  report.checks.push("JWT, token storage, and session-hardening hotspot scan");
  const jwtDecode = /\bjwt\.decode\s*\(/i;
  const jwtIgnoreExpiration = /\bjwt\.verify\s*\([^;\n]*ignoreExpiration\s*:\s*true/i;
  const weakJwtSecret = /\bjwt\.(sign|verify)\s*\([^;\n]+,\s*["'](?:secret|changeme|password|default|test|dev|123456)["']/i;
  const webStorageToken = /\b(localStorage|sessionStorage)\.(setItem|getItem)\s*\([^;\n]*(token|jwt|accessToken|refreshToken|idToken|session)/i;
  const documentCookieToken = /\bdocument\.cookie\s*=[^;\n]*(token|jwt|accessToken|refreshToken|session)/i;
  const httpOnlyFalse = /\bhttpOnly\s*:\s*false\b/i;
  const insecureCookie = /\bsecure\s*:\s*false\b/i;

  for (const file of files.filter(isSourceCodeFile)) {
    const rel = path.relative(root, file);
    const text = await fs.readFile(file, "utf8").catch(() => "");
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const location = `${rel}:${index + 1}`;

      if (jwtDecode.test(line) && !/\bverify\s*\(/i.test(lineWindow(lines, index, 0, 4))) {
        addFinding(report, {
          id: `jwt-decode-without-verify-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "JWT decoded without nearby signature verification",
          severity: "high",
          category: "Token/session security",
          location,
          evidence: trimEvidence(line),
          owasp: "A07:2021 Identification and Authentication Failures",
          cwe: "CWE-347",
          confidence: "medium",
          remediation: "Use jwt.verify with expected algorithm, issuer, audience, expiry, and key selection before trusting claims. Treat decode-only claims as untrusted display data."
        });
      }

      if (jwtIgnoreExpiration.test(line)) {
        addFinding(report, {
          id: `jwt-ignore-expiration-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "JWT verification ignores token expiration",
          severity: "high",
          category: "Token/session security",
          location,
          evidence: trimEvidence(line),
          owasp: "A07:2021 Identification and Authentication Failures",
          cwe: "CWE-613",
          confidence: "high",
          remediation: "Remove ignoreExpiration in production paths and enforce short token lifetimes plus server-side revocation for high-risk sessions."
        });
      }

      if (weakJwtSecret.test(line)) {
        addFinding(report, {
          id: `weak-jwt-secret-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "JWT uses a weak literal signing secret",
          severity: "critical",
          category: "Token/session security",
          location,
          evidence: redactSecret(trimEvidence(line)),
          owasp: "A02:2021 Cryptographic Failures",
          cwe: "CWE-798",
          confidence: "high",
          remediation: "Rotate tokens signed with the weak secret, load a high-entropy key from a secret manager, and pin allowed JWT algorithms."
        });
      }

      if (webStorageToken.test(line) || documentCookieToken.test(line)) {
        addFinding(report, {
          id: `browser-token-storage-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "Browser-accessible token storage needs XSS/session review",
          severity: "medium",
          category: "Client-side token storage",
          location,
          evidence: trimEvidence(line),
          owasp: "A07:2021 Identification and Authentication Failures",
          cwe: "CWE-922",
          confidence: "medium",
          remediation: "Prefer secure HttpOnly cookies for session-bearing tokens where practical, reduce token lifetime, and ensure CSP/XSS defenses are strong when browser-readable tokens are unavoidable."
        });
      }

      if ((httpOnlyFalse.test(line) || insecureCookie.test(line)) && /cookie|session|token/i.test(lineWindow(lines, index, 3, 3))) {
        addFinding(report, {
          id: `insecure-cookie-option-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "Session cookie appears configured with weak security options",
          severity: "high",
          category: "Token/session security",
          location,
          evidence: trimEvidence(line),
          owasp: "A07:2021 Identification and Authentication Failures",
          cwe: "CWE-614",
          confidence: "medium",
          remediation: "Set Secure and HttpOnly on session cookies, use SameSite=Lax or Strict by default, and scope Domain/Path narrowly."
        });
      }
    }
  }
}

async function scanClientExposurePatterns(root, files, report) {
  report.checks.push("Client-side public config and GraphQL exposure signal scan");
  const publicSensitiveEnv = /\b((?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC)_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE|CLIENT_SECRET)[A-Z0-9_]*)\b\s*[:=]\s*["'][^"']{6,}["']/i;
  const publicApiKeyName = /\b((?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC)_[A-Z0-9_]*(?:API_KEY|KEY)[A-Z0-9_]*)\b\s*[:=]\s*["'][^"']{8,}["']/i;
  const graphqlIntrospectionSignal = /\b(__schema|__type|IntrospectionQuery|getIntrospectionQuery|introspection)\b/i;
  const graphqlRuntimeContext = /\b(fetch|GraphQLClient|ApolloClient|createHttpLink|graphqlHTTP|createYoga|express-graphql|urql|relay|useQuery|useMutation|query\s*\(|mutate\s*\(|app\.use\s*\([^;\n]*graphql)\b/i;

  for (const file of files.filter(isSourceCodeFile)) {
    const rel = path.relative(root, file);
    const text = await fs.readFile(file, "utf8").catch(() => "");
    if (!text) continue;
    const lines = text.split(/\r?\n/);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const sensitive = line.match(publicSensitiveEnv);
      if (sensitive) {
        addFinding(report, {
          id: `public-sensitive-env-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "Sensitive-looking public frontend environment variable",
          severity: "high",
          category: "Client-side exposure",
          location: `${rel}:${index + 1}`,
          evidence: `Public variable ${sensitive[1]} is assigned a value; value redacted.`,
          owasp: "A02:2021 Cryptographic Failures",
          cwe: "CWE-200",
          confidence: "medium",
          remediation: "Move secrets, private tokens, and privileged credentials to server-side configuration. Public frontend variables are shipped to browsers and must be treated as public."
        });
      }

      const apiKey = line.match(publicApiKeyName);
      if (apiKey) {
        addFinding(report, {
          id: `public-api-key-env-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "Public frontend API key should be restricted",
          severity: "low",
          category: "Client-side exposure",
          location: `${rel}:${index + 1}`,
          evidence: `Public variable ${apiKey[1]} is assigned a value; value redacted.`,
          owasp: "A05:2021 Security Misconfiguration",
          cwe: "CWE-200",
          confidence: "medium",
          remediation: "Confirm the key is intended to be public and restrict it by domain, app, API scope, quota, and billing protections."
        });
      }

      const graphqlNeighborhood = lineWindow(lines, index, 8, 8);
      if (graphqlIntrospectionSignal.test(line) && graphqlRuntimeContext.test(graphqlNeighborhood) && !isScannerRuleOrReportText(line)) {
        addFinding(report, {
          id: `graphql-introspection-signal-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "GraphQL introspection or schema exposure needs review",
          severity: "medium",
          category: "API security",
          location: `${rel}:${index + 1}`,
          evidence: trimEvidence(line),
          owasp: "API9:2023 Improper Inventory Management",
          cwe: "CWE-200",
          confidence: "low",
          remediation: "Verify production GraphQL introspection, schema dumps, and GraphiQL-style consoles are disabled or authenticated unless intentionally public."
        });
      }
    }
  }
}

async function scanCiCdSecurityHotspots(root, files, report) {
  report.checks.push("CI/CD workflow security hotspot scan");
  const workflowFiles = files.filter((file) => {
    const rel = path.relative(root, file).replaceAll("\\", "/");
    return rel.startsWith(".github/workflows/") && /\.(ya?ml)$/i.test(file);
  });
  report.inventory.githubWorkflowFiles = workflowFiles.length;
  if (!workflowFiles.length) return;

  for (const file of workflowFiles) {
    const rel = path.relative(root, file).replaceAll("\\", "/");
    const text = await fs.readFile(file, "utf8").catch(() => "");
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    const hasPullRequestTarget = /\bpull_request_target\b/i.test(text);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const location = `${rel}:${index + 1}`;

      if (hasPullRequestTarget && /permissions\s*:\s*write-all/i.test(line)) {
        addFinding(report, {
          id: `gha-pr-target-write-all-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "pull_request_target workflow grants write-all permissions",
          severity: "high",
          category: "CI/CD security",
          location,
          evidence: trimEvidence(line),
          owasp: "A08:2021 Software and Data Integrity Failures",
          cwe: "CWE-266",
          confidence: "high",
          remediation: "Use least-privilege permissions and avoid write tokens in pull_request_target workflows that process untrusted pull request content."
        });
      }

      if (hasPullRequestTarget && /github\.event\.pull_request\.(head|title|body|user)|pull_request\.head\.ref/i.test(lineWindow(lines, index, 3, 3)) && /\brun\s*:|actions\/checkout/i.test(lineWindow(lines, index, 3, 3))) {
        addFinding(report, {
          id: `gha-pr-target-untrusted-input-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "pull_request_target workflow may execute untrusted PR input",
          severity: "high",
          category: "CI/CD security",
          location,
          evidence: trimEvidence(line),
          owasp: "A08:2021 Software and Data Integrity Failures",
          cwe: "CWE-829",
          confidence: "medium",
          remediation: "Do not checkout or execute untrusted PR head content in pull_request_target with privileged tokens. Use pull_request with read-only permissions or a two-stage trusted workflow."
        });
      }

      const floatingAction = line.match(/\buses\s*:\s*([^@\s]+)@(?:main|master|latest)\b/i);
      if (floatingAction) {
        addFinding(report, {
          id: `gha-floating-action-${rel}-${index + 1}`.replace(/[^a-z0-9_-]+/gi, "-"),
          title: "GitHub Action uses a floating ref",
          severity: "low",
          category: "CI/CD security",
          location,
          evidence: trimEvidence(line),
          owasp: "A08:2021 Software and Data Integrity Failures",
          cwe: "CWE-829",
          confidence: "high",
          remediation: "Pin third-party actions to immutable commit SHAs or a trusted release process to reduce supply-chain takeover risk."
        });
      }
    }
  }
}

function lineWindow(lines, index, before, after) {
  const start = Math.max(0, index - before);
  const end = Math.min(lines.length, index + after + 1);
  return lines.slice(start, end).join("\n");
}

function isScannerRuleOrReportText(line) {
  return /graphqlIntrospectionSignal|graphqlRuntimeContext|spa-graphql-introspection-signal|GraphQL introspection\/schema|Public JavaScript references GraphQL|__schema\|__type\|IntrospectionQuery/i.test(line);
}

function isSourceCodeFile(file) {
  return sourceCodeExtensions.has(path.extname(file));
}

function isRuleMetadataLine(line) {
  return /^\s*["']?regex["']?\s*:/.test(line);
}

async function scanSecretPatterns(root, files, rules, report) {
  report.checks.push("Redacted secret pattern scan");
  const compiled = rules.secretPatterns.map((rule) => ({
    ...rule,
    matcher: new RegExp(rule.regex, rule.flags ? `${rule.flags}g` : "g")
  }));

  for (const file of files) {
    const rel = path.relative(root, file);
    const text = await fs.readFile(file, "utf8").catch(() => "");
    if (!text) continue;
    const lines = text.split(/\r?\n/);

    for (const rule of compiled) {
      for (let index = 0; index < lines.length; index += 1) {
        rule.matcher.lastIndex = 0;
        const match = rule.matcher.exec(lines[index]);
        if (match) {
          addFinding(report, {
            id: rule.id,
            title: rule.message,
            severity: rule.severity,
            category: "Secret exposure",
            location: `${rel}:${index + 1}`,
            evidence: redactSecret(match[0]),
            owasp: "A02:2021 Cryptographic Failures",
            cwe: "CWE-798",
            remediation: "Revoke and rotate the credential, remove it from history if committed, and load secrets through a managed secret store or runtime environment."
          });
        }
      }
    }
  }
}

async function checkSensitiveLocalFiles(root, report) {
  report.checks.push("Sensitive local file presence check");
  const sensitive = [
    [".env", "high", "Environment file exists in the project root. Ensure it is not committed or served."],
    [".env.local", "high", "Local environment file exists. Ensure it is ignored and never deployed as static content."],
    ["id_rsa", "critical", "Private SSH key-like file exists in project scope."],
    [".npmrc", "medium", ".npmrc may contain registry tokens; verify it does not include secrets."],
    ["firebase-service-account.json", "critical", "Service account file may contain cloud credentials."]
  ];

  for (const [name, severity, message] of sensitive) {
    const file = path.join(root, name);
    const stat = await fs.stat(file).catch(() => null);
    if (stat?.isFile()) {
      addFinding(report, {
        id: `sensitive-file-${name}`,
        title: message,
        severity,
        category: "Sensitive file",
        location: name,
        evidence: "File exists; contents were not printed.",
        remediation: "Confirm this file is excluded from version control and deployment artifacts. Rotate any credential that may have been exposed."
      });
    }
  }
}

async function runLocalToolChecks(root, report) {
  report.checks.push("External scanner availability check");
  const toolChecks = [
    {
      name: "npm audit",
      when: async () => exists(path.join(root, "package-lock.json")) && hasCommand("npm"),
      command: "npm",
      args: ["audit", "--json"],
      parser: parseNpmAudit
    },
    {
      name: "pnpm audit",
      when: async () => exists(path.join(root, "pnpm-lock.yaml")) && hasCommand("pnpm"),
      command: "pnpm",
      args: ["audit", "--json"],
      parser: parseNpmAudit
    },
    {
      name: "yarn npm audit",
      when: async () => exists(path.join(root, "yarn.lock")) && hasCommand("yarn"),
      command: "yarn",
      args: ["npm", "audit", "--json"],
      parser: parseNpmAudit
    },
    {
      name: "osv-scanner",
      when: async () => hasCommand("osv-scanner"),
      command: "osv-scanner",
      args: ["scan", "source", "-r", "--format", "json", root],
      parser: parseOsvScanner
    },
    {
      name: "semgrep",
      when: async () => hasCommand("semgrep"),
      command: "semgrep",
      args: ["scan", "--config", "p/owasp-top-ten", "--json", "--quiet", root],
      parser: parseSemgrep
    },
    {
      name: "gitleaks",
      when: async () => hasCommand("gitleaks"),
      command: "gitleaks",
      args: async () => {
        const reportPath = path.join(os.tmpdir(), `security-audit-gitleaks-${Date.now()}.json`);
        return {
          args: ["dir", root, "--redact", "--report-format", "json", "--report-path", reportPath, "--no-banner"],
          outputFile: reportPath
        };
      },
      parser: parseGitleaks
    },
    {
      name: "trufflehog filesystem",
      when: async () => hasCommand("trufflehog"),
      command: "trufflehog",
      args: ["filesystem", "--json", "--no-update", root],
      parser: parseTrufflehog
    },
    {
      name: "pip-audit",
      when: async () => (exists(path.join(root, "requirements.txt")) || exists(path.join(root, "pyproject.toml"))) && hasCommand("pip-audit"),
      command: "pip-audit",
      args: ["--format", "json"],
      parser: parsePipAudit
    },
    {
      name: "bandit",
      when: async () => report.inventory.stacks?.includes("python") && hasCommand("bandit"),
      command: "bandit",
      args: ["-r", root, "-f", "json", "-q"],
      parser: parseBandit
    },
    {
      name: "cargo audit",
      when: async () => exists(path.join(root, "Cargo.lock")) && hasCommand("cargo"),
      command: "cargo",
      args: ["audit", "--json"],
      parser: parseCargoAudit
    },
    {
      name: "govulncheck",
      when: async () => exists(path.join(root, "go.mod")) && hasCommand("govulncheck"),
      command: "govulncheck",
      args: ["-json", "./..."],
      parser: parseGovulncheck
    },
    {
      name: "composer audit",
      when: async () => exists(path.join(root, "composer.lock")) && hasCommand("composer"),
      command: "composer",
      args: ["audit", "--format=json"],
      parser: parseComposerAudit
    }
  ];

  for (const check of toolChecks) {
    if (!(await check.when())) {
      report.skipped.push(`${check.name} not run; command or required lockfile was not available.`);
      report.tools.push({ name: check.name, status: "missing-or-not-applicable" });
      continue;
    }

    const resolvedArgs = typeof check.args === "function" ? await check.args() : { args: check.args };
    const result = await runCommand(check.command, resolvedArgs.args, root, 180000);
    if (result.error) {
      report.skipped.push(`${check.name} failed: ${result.error}`);
      report.tools.push({ name: check.name, status: "failed" });
      continue;
    }
    report.checks.push(`${check.name} executed`);
    report.tools.push({ name: check.name, status: "executed", exitCode: result.code });
    let stdout = result.stdout;
    if (resolvedArgs.outputFile) {
      stdout = await fs.readFile(resolvedArgs.outputFile, "utf8").catch(() => "");
      await fs.rm(resolvedArgs.outputFile, { force: true }).catch(() => {});
    }
    check.parser(stdout, result.stderr, report);
  }
}

async function auditUrl(rawUrl, args, rules, report) {
  const url = new URL(rawUrl);
  if ((args.mode === "standard" || args.mode === "active") && !args.authorized) {
    throw new Error("URL standard/active mode requires --authorized or SECURITY_AUDIT_AUTHORIZED=1. Use passive mode for unauthenticated public checks.");
  }
  report.inventory.kind = "url";
  report.inventory.origin = url.origin;
  report.checks.push("HTTP response and security header check");

  const responseInfo = await fetchUrl(url.toString());
  if (responseInfo.error) {
    addFinding(report, {
      id: "url-fetch-failed",
      title: "Could not fetch target URL",
      severity: "info",
      category: "HTTP",
      location: url.toString(),
      evidence: responseInfo.error,
      remediation: "Verify the URL, network access, and whether the service requires VPN or authentication."
    });
    return;
  }

  report.inventory.status = responseInfo.status;
  report.inventory.finalUrl = responseInfo.finalUrl;
  checkSecurityHeaders(url, responseInfo, rules, report);
  checkCookies(responseInfo, report);
  checkCors(responseInfo, report);
  checkResponseBodySignals(responseInfo, report);

  if (url.protocol === "https:") {
    await checkHttpToHttpsRedirect(url, report);
    await checkTls(url, report);
  } else {
    addFinding(report, {
      id: "http-not-https",
      title: "Target URL uses HTTP instead of HTTPS",
      severity: "medium",
      category: "Transport security",
      location: url.toString(),
      evidence: "The supplied URL starts with http://.",
      owasp: "A02:2021 Cryptographic Failures",
      remediation: "Redirect HTTP to HTTPS in production and serve sensitive flows only over TLS."
    });
  }

  if (args.mode === "standard" || args.mode === "active") {
    await checkAdjacentApiHeadersAndCookies(url, report);
    await checkSecurityTxtAvailability(url, report);
    await checkClientBundleRiskSignals(url, responseInfo, report);
  }

  if (args.mode === "standard" || args.mode === "active") {
    await checkExposurePaths(url, rules, report);
    await checkHttpMethods(url, report);
    await checkCorsReflection(url, report);
    await checkApiDiscoveryPaths(url, report);
  } else {
    report.skipped.push("Common exposure-path checks skipped in passive mode.");
    report.skipped.push("HTTP method, CORS reflection, and API discovery checks skipped in passive mode.");
  }

  if (args.mode === "active" && args.runTools) {
    await runUrlToolChecks(url, args, report);
  } else if (args.mode === "active") {
    report.skipped.push("Active external tools skipped by --no-tools.");
  } else {
    report.skipped.push("Active DAST tools skipped because mode is not active.");
  }
  addUrlReviewedSurfaces(report);
}

async function fetchUrl(target, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(target, {
      method: options.method || "GET",
      redirect: options.redirect || "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "SecurityAuditPro/0.1 defensive-audit",
        ...(options.headers || {})
      }
    });
    const body = await response.text().catch(() => "");
    return {
      status: response.status,
      finalUrl: response.url,
      headers: Object.fromEntries(response.headers.entries()),
      setCookie: response.headers.getSetCookie ? response.headers.getSetCookie() : collectSetCookieFallback(response.headers),
      bodySample: body.slice(0, options.maxBody || 50000)
    };
  } catch (error) {
    return { error: error.message };
  } finally {
    clearTimeout(timer);
  }
}

function collectSetCookieFallback(headers) {
  const value = headers.get("set-cookie");
  return value ? [value] : [];
}

async function fetchText(target, maxBytes = 3000000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(target, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "SecurityAuditPro/0.1 defensive-audit"
      }
    });
    const text = await response.text().catch(() => "");
    return {
      status: response.status,
      finalUrl: response.url,
      headers: Object.fromEntries(response.headers.entries()),
      text: text.slice(0, maxBytes),
      truncated: text.length > maxBytes
    };
  } catch (error) {
    return { error: error.message, text: "" };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchRawHeaders(target) {
  const targetUrl = new URL(target);
  const module = targetUrl.protocol === "https:" ? await import("node:https") : await import("node:http");
  return new Promise((resolve) => {
    const request = module.request(targetUrl, {
      method: "HEAD",
      timeout: 15000,
      headers: {
        "User-Agent": "SecurityAuditPro/0.1 defensive-audit"
      }
    }, (response) => {
      response.resume();
      resolve({
        status: response.statusCode,
        rawHeaders: response.rawHeaders || [],
        headers: response.headers || {}
      });
    });
    request.on("timeout", () => {
      request.destroy();
      resolve({ error: "request timed out", rawHeaders: [], headers: {} });
    });
    request.on("error", (error) => {
      resolve({ error: error.message, rawHeaders: [], headers: {} });
    });
    request.end();
  });
}

function rawHeaderValues(rawHeaders, headerName) {
  const values = [];
  for (let index = 0; index < rawHeaders.length - 1; index += 2) {
    if (String(rawHeaders[index]).toLowerCase() === headerName.toLowerCase()) {
      values.push(String(rawHeaders[index + 1]));
    }
  }
  return values;
}

async function checkHttpToHttpsRedirect(url, report) {
  report.checks.push("HTTP to HTTPS redirect enforcement check");
  const httpUrl = new URL(url.toString());
  httpUrl.protocol = "http:";
  const responseInfo = await fetchUrl(httpUrl.toString(), {
    redirect: "manual",
    maxBody: 2000
  });
  if (responseInfo.error) {
    report.skipped.push(`HTTP redirect check failed for ${httpUrl.toString()}: ${responseInfo.error}`);
    return;
  }
  const location = responseInfo.headers?.location || "";
  const redirectsToHttps = responseInfo.status >= 300 && responseInfo.status < 400 && /^https:\/\//i.test(location);
  if (!redirectsToHttps) {
    addFinding(report, {
      id: "http-without-https-redirect",
      title: "HTTP works without HTTPS redirect",
      severity: "medium",
      category: "Transport security",
      location: httpUrl.toString(),
      evidence: `HTTP ${responseInfo.status}; Location header: ${location || "(none)"}`,
      owasp: "A02:2021 Cryptographic Failures",
      cwe: "CWE-319",
      confidence: "high",
      remediation: "Redirect all HTTP requests to HTTPS with a permanent 301 or 308 redirect before serving portal content."
    });
  }
}

async function checkAdjacentApiHeadersAndCookies(url, report) {
  report.checks.push("Adjacent API header and XSRF cookie check");
  const basePath = normalizedBasePath(url.pathname);
  const httpsEndpoint = new URL(`${basePath}/api/auth/login-capabilities`, url.origin).toString();
  const raw = await fetchRawHeaders(httpsEndpoint);
  const cspValues = rawHeaderValues(raw.rawHeaders || [], "Content-Security-Policy");
  const frameValues = rawHeaderValues(raw.rawHeaders || [], "X-Frame-Options");
  if (cspValues.length > 1 || frameValues.length > 1) {
    addFinding(report, {
      id: "conflicting-duplicate-security-headers",
      title: "Conflicting duplicate security headers",
      severity: "medium",
      category: "HTTP security header",
      location: httpsEndpoint,
      evidence: `CSP values: ${summarizeHeaderValues(cspValues)}; X-Frame-Options values: ${summarizeHeaderValues(frameValues)}`,
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-16",
      confidence: "high",
      remediation: "Consolidate security headers at one layer so API responses emit one consistent CSP and one consistent X-Frame-Options/frame-ancestors policy."
    });
  }

  const httpsInfo = await fetchUrl(httpsEndpoint, { redirect: "manual", maxBody: 2000 });
  const httpEndpoint = new URL(httpsEndpoint);
  httpEndpoint.protocol = "http:";
  const httpInfo = await fetchUrl(httpEndpoint.toString(), { redirect: "manual", maxBody: 2000 });
  const httpsXsrf = (httpsInfo.setCookie || []).find((cookie) => /^XSRF-TOKEN=/i.test(cookie));
  const httpXsrf = (httpInfo.setCookie || []).find((cookie) => /^XSRF-TOKEN=/i.test(cookie));
  if (httpsXsrf || httpXsrf) {
    const issues = [];
    if (httpsXsrf && !/;\s*samesite=/i.test(httpsXsrf)) issues.push("HTTPS XSRF-TOKEN missing SameSite");
    if (httpXsrf && !/;\s*secure\b/i.test(httpXsrf)) issues.push("HTTP XSRF-TOKEN set without Secure");
    if (httpXsrf && !/;\s*samesite=/i.test(httpXsrf)) issues.push("HTTP XSRF-TOKEN missing SameSite");
    if (issues.length) {
      addFinding(report, {
        id: "xsrf-cookie-hardening-gap",
        title: "XSRF cookie weakness",
        severity: "medium",
        category: "Session security",
        location: httpsEndpoint,
        evidence: issues.join("; "),
        owasp: "A01:2021 Broken Access Control",
        cwe: "CWE-352",
        confidence: "high",
        remediation: "Set SameSite on XSRF cookies, avoid setting security cookies over HTTP, and verify state-changing requests require the expected X-XSRF-TOKEN header."
      });
    }
  }
}

function summarizeHeaderValues(values) {
  if (!values.length) return "(none)";
  return values.map((value) => value.slice(0, 160)).join(" || ");
}

async function checkSecurityTxtAvailability(url, report) {
  report.checks.push("security.txt availability check");
  const basePath = normalizedBasePath(url.pathname);
  const scopedSecurityTxt = new URL(`${basePath}/.well-known/security.txt`, url.origin).toString();
  const rootSecurityTxt = new URL("/.well-known/security.txt", url.origin).toString();
  const scoped = await fetchUrl(scopedSecurityTxt, { redirect: "manual", maxBody: 5000 });
  const root = await fetchUrl(rootSecurityTxt, { redirect: "manual", maxBody: 5000 });
  const scopedLooksLikeSpa = scoped.status === 200 && /<app-root|<html|CBSE|Verification|Re-evaluation/i.test(scoped.bodySample || "");
  const rootUnavailable = root.status >= 500 || root.status === 404;
  if (scopedLooksLikeSpa || rootUnavailable) {
    addFinding(report, {
      id: "security-txt-unavailable",
      title: "No useful security.txt disclosure contact",
      severity: "info",
      category: "Information disclosure",
      location: scopedSecurityTxt,
      evidence: `Scoped security.txt status ${scoped.status || "unknown"}${scopedLooksLikeSpa ? " returned SPA/HTML content" : ""}; root security.txt status ${root.status || "unknown"}`,
      owasp: "A05:2021 Security Misconfiguration",
      confidence: "high",
      remediation: "Publish a valid RFC 9116 security.txt at /.well-known/security.txt with contact and policy details for responsible disclosure."
    });
  }
}

async function checkClientBundleRiskSignals(url, responseInfo, report) {
  report.checks.push("Public SPA bundle risk signal check");
  const initialAssetUrls = extractScriptAssetUrls(responseInfo.finalUrl || url.toString(), responseInfo.bodySample || "");
  if (!initialAssetUrls.length) {
    report.skipped.push("Public SPA bundle risk signal check did not find JavaScript assets in the fetched HTML.");
    return;
  }
  const origin = new URL(responseInfo.finalUrl || url.toString()).origin;
  const seen = new Set(initialAssetUrls);
  const queue = [...initialAssetUrls];
  const bundles = [];
  while (queue.length && bundles.length < 60) {
    const assetUrl = queue.shift();
    const fetched = await fetchText(assetUrl);
    if (fetched.error || !fetched.text) continue;
    bundles.push({ url: assetUrl, text: fetched.text, truncated: fetched.truncated });
    for (const nextUrl of extractJavaScriptReferences(assetUrl, fetched.text)) {
      if (seen.has(nextUrl)) continue;
      if (new URL(nextUrl).origin !== origin) continue;
      seen.add(nextUrl);
      queue.push(nextUrl);
    }
  }
  const combined = bundles.map((bundle) => bundle.text).join("\n");
  if (!combined) return;

  const consoleLogCount = (combined.match(/console\.log\s*\(/g) || []).length;
  const sensitiveLogTerms = [
    "Payment payload",
    "Payment initiation response",
    "Final Confirmation payload",
    "payment state",
    "application state",
    "candidate"
  ].filter((term) => combined.includes(term));
  if (consoleLogCount && sensitiveLogTerms.length) {
    addFinding(report, {
      id: "production-debug-logging-js",
      title: "Production debug logging in JS",
      severity: "medium",
      category: "Information disclosure",
      location: bundles.find((bundle) => sensitiveLogTerms.some((term) => bundle.text.includes(term)))?.url || initialAssetUrls[0],
      evidence: `${consoleLogCount} console.log call(s) observed; sensitive log labels include: ${sensitiveLogTerms.slice(0, 8).join(", ")}`,
      owasp: "A09:2021 Security Logging and Monitoring Failures",
      cwe: "CWE-532",
      confidence: "high",
      remediation: "Remove production console logging around candidate, application, and payment workflows, or gate diagnostics behind a secure server-side support flow."
    });
  }

  const endpointNeedles = [
    "candidate/full-profile/rroll",
    "fetch/application/rroll",
    "photoUpload/download-url",
    "candidate/photocopy/download-url",
    "payment/reconcile",
    "payment/all",
    "grievance/list",
    "photocopy/statistics"
  ];
  const exposedEndpoints = endpointNeedles.filter((needle) => combined.includes(needle));
  if (exposedEndpoints.length) {
    addFinding(report, {
      id: "sensitive-endpoint-map-public-js",
      title: "Sensitive endpoint map exposed in public JS",
      severity: "low",
      category: "Information disclosure",
      location: bundles.find((bundle) => exposedEndpoints.some((needle) => bundle.text.includes(needle)))?.url || initialAssetUrls[0],
      evidence: exposedEndpoints.join(", "),
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-200",
      confidence: "high",
      remediation: "Assume client-side routes are public and enforce strict server-side authorization, object ownership checks, and rate limits on every listed API endpoint."
    });
  }

  if (/AES-GCM/i.test(combined) && /SHA-256/i.test(combined) && /123456789/.test(combined)) {
    addFinding(report, {
      id: "client-side-password-transform",
      title: "Client-side password transform is not real protection",
      severity: "low",
      category: "Client-side security",
      location: bundles.find((bundle) => /AES-GCM/i.test(bundle.text) && /SHA-256/i.test(bundle.text) && /123456789/.test(bundle.text))?.url || initialAssetUrls[0],
      evidence: "Public bundle references AES-GCM, SHA-256, and a fixed suffix used in the client-side transform.",
      owasp: "A02:2021 Cryptographic Failures",
      cwe: "CWE-311",
      confidence: "high",
      remediation: "Treat client-side transforms only as defense-in-depth. Enforce HTTPS, strong CSP, secure authentication, server-side validation, and protection before the browser transform step."
    });
  }

  checkIdentityWorkflowSignals(combined, bundles, initialAssetUrls, report);
  checkPaymentWorkflowSignals(combined, bundles, initialAssetUrls, origin, report);
  checkSpaAuthAndConfigSignals(combined, bundles, initialAssetUrls, report);
}

function checkIdentityWorkflowSignals(combined, bundles, initialAssetUrls, report) {
  const aadhaarSignal =
    /\baadhaar(Name|Number)?\b/i.test(combined) &&
    /\b(dob|dateOfBirth|gender)\b/i.test(combined) &&
    /auth\/login|\/login\b/i.test(combined);
  const userIdSignal = /\b(userId|userid|rollNo|rroll)\b/i.test(combined);
  const digilockerSignal = /digilocker/i.test(combined);
  if (aadhaarSignal && userIdSignal && digilockerSignal) {
    addFinding(report, {
      id: "identity-binding-needs-validation",
      title: "Aadhaar/DigiLocker identity binding needs server-side validation",
      severity: "high",
      category: "Authentication business logic",
      location: bundles.find((bundle) => /aadhaar|digilocker/i.test(bundle.text) && /auth\/login|\/login\b/i.test(bundle.text))?.url || initialAssetUrls[0],
      evidence: "Public bundle sends roll/user identity and Aadhaar/DigiLocker identity fields through the login flow; client code cannot prove server-side binding.",
      owasp: "A07:2021 Identification and Authentication Failures",
      cwe: "CWE-287",
      confidence: "low",
      remediation: "Verify server-side binding between verified Aadhaar/DigiLocker identity and the submitted candidate record. Reject valid-but-unrelated identities and add regression tests for mismatched Aadhaar-to-roll combinations."
    });
  }

  const placeholderPatterns = [
    /\bDIGILOCKER_PLACEHOLDER_MOBILE\s*=\s*["']9{1,}0*["']/i,
    /\bmobileNo\b[^;\n]{0,120}["']9000000000["']/i,
    /\bmobileNo\b[^;\n]{0,120}\bPLACEHOLDER/i
  ];
  if (placeholderPatterns.some((pattern) => pattern.test(combined))) {
    addFinding(report, {
      id: "hardcoded-identity-mobile-placeholder",
      title: "Hardcoded identity mobile placeholder in login flow",
      severity: "medium",
      category: "Authentication business logic",
      location: bundles.find((bundle) => placeholderPatterns.some((pattern) => pattern.test(bundle.text)))?.url || initialAssetUrls[0],
      evidence: "Public bundle assigns a fixed placeholder mobile number in the identity-verification login path.",
      owasp: "A07:2021 Identification and Authentication Failures",
      cwe: "CWE-287",
      confidence: "high",
      remediation: "Do not send or trust a fixed mobile number in identity workflows. Derive contact data server-side from the verified identity assertion or omit it when it is not required."
    });
  }
}

function checkPaymentWorkflowSignals(combined, bundles, initialAssetUrls, origin, report) {
  const returnUrlMatches = [...combined.matchAll(/\b(?:sbiReturnUrl|returnUrl|callbackUrl|successUrl)\s*:\s*["'](https?:\/\/[^"']+)["']/gi)];
  const mismatched = [];
  for (const match of returnUrlMatches) {
    try {
      const configured = new URL(match[1]);
      if (configured.origin !== origin) {
        mismatched.push(`${configured.hostname} != ${new URL(origin).hostname}`);
      }
    } catch {
      // Ignore malformed URLs.
    }
  }
  if (mismatched.length && /payment|sbi|orderRefNumber|createOrder/i.test(combined)) {
    addFinding(report, {
      id: "payment-return-url-host-mismatch",
      title: "Payment return URL host differs from current portal host",
      severity: "medium",
      category: "Payment workflow",
      location: bundles.find((bundle) => /sbiReturnUrl|returnUrl|callbackUrl|successUrl/i.test(bundle.text) && /payment|sbi|createOrder/i.test(bundle.text))?.url || initialAssetUrls[0],
      evidence: `Configured payment return host differs from target host (${unique(mismatched).join(", ")}).`,
      owasp: "A04:2021 Insecure Design",
      cwe: "CWE-840",
      confidence: "high",
      remediation: "Align payment return URLs with the active production host, validate return/callback targets server-side, and reject client-controlled or stale-host payment return parameters."
    });
  }
}

function checkSpaAuthAndConfigSignals(combined, bundles, initialAssetUrls, report) {
  const tokenStoragePattern = /\b(localStorage|sessionStorage)\.(setItem|getItem)\s*\([^)]*(token|jwt|accessToken|refreshToken|idToken|session)/i;
  if (tokenStoragePattern.test(combined)) {
    addFinding(report, {
      id: "spa-browser-token-storage",
      title: "SPA bundle uses browser-accessible token storage",
      severity: "medium",
      category: "Client-side token storage",
      location: bundles.find((bundle) => tokenStoragePattern.test(bundle.text))?.url || initialAssetUrls[0],
      evidence: "Public JavaScript bundle references localStorage/sessionStorage token access patterns.",
      owasp: "A07:2021 Identification and Authentication Failures",
      cwe: "CWE-922",
      confidence: "medium",
      remediation: "Prefer HttpOnly Secure SameSite cookies for session-bearing tokens where practical, keep token lifetime short, and harden CSP/XSS controls if browser-readable tokens are unavoidable."
    });
  }

  const secretLikeNames = unique([...combined.matchAll(/\b((?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC)_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE|CLIENT_SECRET)[A-Z0-9_]*|[A-Za-z0-9_]*(?:Secret|PrivateKey|ClientSecret|AccessToken|RefreshToken|Password)[A-Za-z0-9_]*)\b\s*[:=]\s*["'][^"']{8,}["']/g)].map((match) => match[1])).slice(0, 10);
  if (secretLikeNames.length) {
    addFinding(report, {
      id: "spa-secret-like-public-config",
      title: "Secret-like configuration name appears in public JS bundle",
      severity: "high",
      category: "Client-side exposure",
      location: bundles.find((bundle) => secretLikeNames.some((name) => bundle.text.includes(name)))?.url || initialAssetUrls[0],
      evidence: `Secret-like public config names observed: ${secretLikeNames.join(", ")}. Values redacted.`,
      owasp: "A02:2021 Cryptographic Failures",
      cwe: "CWE-200",
      confidence: "medium",
      remediation: "Verify these values are not real secrets. Move privileged credentials server-side and rotate any secret that has shipped in public JavaScript."
    });
  }

  if (/\b(graphql|apollo|urql|relay)\b/i.test(combined) && /\b(__schema|__type|IntrospectionQuery|getIntrospectionQuery|graphiql)\b/i.test(combined)) {
    addFinding(report, {
      id: "spa-graphql-introspection-signal",
      title: "GraphQL introspection/schema signal in public frontend",
      severity: "medium",
      category: "API security",
      location: bundles.find((bundle) => /\b(__schema|__type|IntrospectionQuery|getIntrospectionQuery|graphiql)\b/i.test(bundle.text))?.url || initialAssetUrls[0],
      evidence: "Public JavaScript references GraphQL introspection/schema terms.",
      owasp: "API9:2023 Improper Inventory Management",
      cwe: "CWE-200",
      confidence: "low",
      remediation: "Confirm production GraphQL introspection, schema download, and GraphiQL-style consoles are disabled or authenticated unless the schema is intentionally public."
    });
  }
}

function normalizedBasePath(pathname) {
  const clean = String(pathname || "/").replace(/\/+$/, "");
  return clean || "/";
}

function extractScriptAssetUrls(baseUrl, html) {
  const urls = new Set();
  const assetRegex = /<(?:script|link)\b[^>]+(?:src|href)=["']([^"']+\.js(?:\?[^"']*)?)["'][^>]*>/gi;
  let match;
  while ((match = assetRegex.exec(html))) {
    try {
      urls.add(new URL(match[1], baseUrl).toString());
    } catch {
      // Ignore malformed asset URLs.
    }
  }
  return [...urls];
}

function extractJavaScriptReferences(baseUrl, text) {
  const urls = new Set();
  const jsRefRegex = /["']([^"']+\.js(?:\?[^"']*)?)["']/gi;
  let match;
  while ((match = jsRefRegex.exec(text))) {
    try {
      urls.add(new URL(match[1], baseUrl).toString());
    } catch {
      // Ignore malformed JavaScript references.
    }
  }
  return [...urls];
}

function checkSecurityHeaders(url, responseInfo, rules, report) {
  const headers = responseInfo.headers;
  const lower = new Map(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));

  for (const rule of rules.headers.requiredOrRecommended) {
    if (rule.httpsOnly && url.protocol !== "https:") continue;
    const value = lower.get(rule.name.toLowerCase());
    if (!value) {
      addFinding(report, {
        id: `missing-header-${rule.name.toLowerCase()}`,
        title: `Missing ${rule.name} header`,
        severity: rule.severity,
        category: "HTTP security header",
        location: responseInfo.finalUrl,
        evidence: `${rule.name} was not present in the response.`,
        owasp: rule.owasp,
        remediation: rule.advice
      });
      continue;
    }

    if (rule.name.toLowerCase() === "content-security-policy") {
      const csp = value.toLowerCase();
      if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'") || !csp.includes("frame-ancestors")) {
        addFinding(report, {
          id: "weak-csp",
          title: "Content-Security-Policy is present but weak",
          severity: "medium",
          category: "HTTP security header",
          location: responseInfo.finalUrl,
          evidence: value.slice(0, 240),
          owasp: "A05:2021 Security Misconfiguration",
          remediation: "Tighten script-src, avoid unsafe-inline/unsafe-eval where possible, and add frame-ancestors to reduce XSS and clickjacking impact."
        });
      }
    }

    if (rule.expected && value.toLowerCase() !== rule.expected.toLowerCase()) {
      addFinding(report, {
        id: `unexpected-header-${rule.name.toLowerCase()}`,
        title: `${rule.name} header has unexpected value`,
        severity: rule.severity,
        category: "HTTP security header",
        location: responseInfo.finalUrl,
        evidence: value,
        owasp: rule.owasp,
        remediation: rule.advice
      });
    }
  }

  for (const rule of rules.headers.deprecatedOrLeaky) {
    const value = lower.get(rule.name.toLowerCase());
    if (value) {
      addFinding(report, {
        id: `leaky-header-${rule.name.toLowerCase()}`,
        title: `${rule.name} header discloses technology details`,
        severity: rule.severity,
        category: "Information disclosure",
        location: responseInfo.finalUrl,
        evidence: value,
        remediation: rule.advice
      });
    }
  }
}

function checkCookies(responseInfo, report) {
  report.checks.push("Cookie flag check");
  for (const cookie of responseInfo.setCookie || []) {
    const lower = cookie.toLowerCase();
    const name = cookie.split("=")[0];
    const missing = [];
    if (!lower.includes("httponly")) missing.push("HttpOnly");
    if (!lower.includes("secure") && responseInfo.finalUrl.startsWith("https://")) missing.push("Secure");
    if (!lower.includes("samesite")) missing.push("SameSite");
    if (missing.length) {
      addFinding(report, {
        id: `cookie-flags-${name}`,
        title: `Cookie ${name} is missing security flags`,
        severity: "medium",
        category: "Session security",
        location: responseInfo.finalUrl,
        evidence: `${name} missing ${missing.join(", ")}`,
        owasp: "A07:2021 Identification and Authentication Failures",
        remediation: "Set HttpOnly for session cookies, Secure on HTTPS, and SameSite=Lax or Strict unless the application requires cross-site cookies."
      });
    }
  }
}

function checkCors(responseInfo, report) {
  report.checks.push("CORS header check");
  const headers = responseInfo.headers;
  const allowOrigin = headers["access-control-allow-origin"];
  const allowCreds = headers["access-control-allow-credentials"];
  if (allowOrigin === "*" && String(allowCreds).toLowerCase() === "true") {
    addFinding(report, {
      id: "cors-wildcard-credentials",
      title: "CORS allows wildcard origin with credentials",
      severity: "high",
      category: "CORS",
      location: responseInfo.finalUrl,
      evidence: "Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true",
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-942",
      remediation: "Use an allowlist of trusted origins and avoid credentialed cross-origin requests unless required."
    });
  } else if (allowOrigin === "*") {
    addFinding(report, {
      id: "cors-wildcard",
      title: "CORS allows any origin",
      severity: "low",
      category: "CORS",
      location: responseInfo.finalUrl,
      evidence: "Access-Control-Allow-Origin: *",
      owasp: "A05:2021 Security Misconfiguration",
      remediation: "Restrict CORS to known origins for non-public APIs."
    });
  }
}

function checkResponseBodySignals(responseInfo, report) {
  report.checks.push("Response body disclosure signal check");
  const body = responseInfo.bodySample || "";
  const signals = [
    {
      id: "stack-trace-python",
      regex: /Traceback \(most recent call last\):|File ".+?", line \d+/i,
      title: "Python stack trace may be exposed",
      severity: "high"
    },
    {
      id: "stack-trace-node",
      regex: /at [\w.<anonymous>]+ \(.+:\d+:\d+\)|Node\.js v\d+\.\d+\.\d+/i,
      title: "Node.js stack trace may be exposed",
      severity: "high"
    },
    {
      id: "sql-error-disclosure",
      regex: /SQL syntax|mysql_fetch|PostgreSQL.*ERROR|ORA-\d{5}|SQLite\/JDBCDriver/i,
      title: "Database error details may be exposed",
      severity: "high"
    },
    {
      id: "source-map-reference",
      regex: /sourceMappingURL=/i,
      title: "Client-side source map reference found",
      severity: "low"
    }
  ];

  for (const signal of signals) {
    const match = body.match(signal.regex);
    if (match) {
      addFinding(report, {
        id: signal.id,
        title: signal.title,
        severity: signal.severity,
        category: "Information disclosure",
        location: responseInfo.finalUrl,
        evidence: trimEvidence(match[0]),
        owasp: "A05:2021 Security Misconfiguration",
        remediation: "Disable verbose production errors, avoid serving debug artifacts, and return generic error pages for users while logging details server-side."
      });
    }
  }
}

async function checkTls(url, report) {
  report.checks.push("TLS certificate check");
  const result = await new Promise((resolve) => {
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: url.hostname,
      timeout: 10000
    }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      socket.end();
      resolve({ cert, protocol });
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ error: "TLS connection timed out" });
    });
    socket.on("error", (error) => resolve({ error: error.message }));
  });

  if (result.error) {
    addFinding(report, {
      id: "tls-check-failed",
      title: "TLS check failed",
      severity: "info",
      category: "Transport security",
      location: url.origin,
      evidence: result.error,
      remediation: "Verify certificate chain, SNI, and network access."
    });
    return;
  }

  report.inventory.tlsProtocol = result.protocol;
  if (result.cert?.valid_to) {
    const expires = new Date(result.cert.valid_to);
    const days = Math.floor((expires.getTime() - Date.now()) / 86400000);
    report.inventory.certificateExpires = expires.toISOString();
    if (days < 14) {
      addFinding(report, {
        id: "tls-cert-expiring",
        title: "TLS certificate expires soon",
        severity: days < 0 ? "high" : "medium",
        category: "Transport security",
        location: url.origin,
        evidence: `Certificate expires in ${days} days.`,
        remediation: "Renew the certificate and verify automated renewal is working."
      });
    }
  }
}

async function checkExposurePaths(url, rules, report) {
  report.checks.push("Shallow exposure-path check");
  for (const item of rules.exposurePaths) {
    const target = new URL(item.path, url.origin).toString();
    const info = await fetchUrl(target);
    if (info.error) continue;
    if (info.status >= 200 && info.status < 300) {
      const isSecurityTxt = item.path.includes("security.txt");
      addFinding(report, {
        id: `exposure-${item.path.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`,
        title: isSecurityTxt ? "security.txt is present" : item.message,
        severity: item.severity,
        category: isSecurityTxt ? "Security contact" : "Exposed path",
        location: target,
        evidence: `HTTP ${info.status}`,
        owasp: isSecurityTxt ? undefined : "A05:2021 Security Misconfiguration",
        remediation: isSecurityTxt
          ? "Keep security contact instructions current."
          : "Block access to sensitive files and endpoints at the web server, framework router, and deployment artifact layers."
      });
    }
    await delay(250);
  }
}

async function checkHttpMethods(url, report) {
  report.checks.push("HTTP method safety check");
  recordCoverage(report, "HTTP method surface", "OPTIONS/TRACE", "reviewed", "Checked advertised methods and direct TRACE behavior.");
  const optionsInfo = await fetchUrl(url.toString(), { method: "OPTIONS" });
  if (!optionsInfo.error) {
    const allow = optionsInfo.headers.allow || optionsInfo.headers["access-control-allow-methods"] || "";
    report.inventory.allowedMethods = allow;
    if (/\bTRACE\b/i.test(allow)) {
      addFinding(report, {
        id: "http-trace-advertised",
        title: "TRACE method is advertised",
        severity: "medium",
        category: "HTTP method exposure",
        location: url.origin,
        evidence: `Allow: ${allow}`,
        owasp: "A05:2021 Security Misconfiguration",
        remediation: "Disable TRACE at the web server or edge proxy."
      });
    }
    if (/\b(PUT|DELETE|PATCH)\b/i.test(allow)) {
      addFinding(report, {
        id: "state-changing-methods-advertised",
        title: "State-changing HTTP methods are advertised",
        severity: "info",
        category: "HTTP method exposure",
        location: url.origin,
        evidence: `Allow: ${allow}`,
        remediation: "Verify these methods require authentication, object authorization, CSRF protection where browser-reachable, and request validation."
      });
    }
  }

  const traceInfo = await fetchUrl(url.toString(), { method: "TRACE" });
  if (!traceInfo.error && traceInfo.status < 400) {
    addFinding(report, {
      id: "http-trace-enabled",
      title: "TRACE method appears enabled",
      severity: "high",
      category: "HTTP method exposure",
      location: url.origin,
      evidence: `TRACE returned HTTP ${traceInfo.status}.`,
      owasp: "A05:2021 Security Misconfiguration",
      remediation: "Disable TRACE and verify the edge proxy blocks it consistently."
    });
  }
}

async function checkCorsReflection(url, report) {
  report.checks.push("CORS reflection probe");
  const origin = "https://security-audit-pro.invalid";
  const info = await fetchUrl(url.toString(), { headers: { Origin: origin } });
  if (info.error) {
    report.skipped.push(`CORS reflection probe failed: ${info.error}`);
    recordCoverage(report, "CORS dynamic behavior", "Origin reflection", "failed", info.error);
    return;
  }
  recordCoverage(report, "CORS dynamic behavior", "Origin reflection", "reviewed", "Sent a harmless synthetic Origin header and inspected CORS response headers.");
  const allowOrigin = info.headers["access-control-allow-origin"] || "";
  const allowCreds = String(info.headers["access-control-allow-credentials"] || "").toLowerCase();
  if (allowOrigin === origin && allowCreds === "true") {
    addFinding(report, {
      id: "cors-reflects-origin-with-credentials",
      title: "CORS reflects arbitrary Origin with credentials",
      severity: "high",
      category: "CORS",
      location: url.origin,
      evidence: `Access-Control-Allow-Origin reflected ${origin} and credentials are enabled.`,
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-942",
      remediation: "Replace dynamic Origin reflection with a strict allowlist and avoid credentialed CORS unless required."
    });
  } else if (allowOrigin === origin) {
    addFinding(report, {
      id: "cors-reflects-origin",
      title: "CORS reflects arbitrary Origin",
      severity: "medium",
      category: "CORS",
      location: url.origin,
      evidence: `Access-Control-Allow-Origin reflected ${origin}.`,
      owasp: "A05:2021 Security Misconfiguration",
      cwe: "CWE-942",
      remediation: "Use an explicit allowlist of trusted origins."
    });
  }
}

async function checkApiDiscoveryPaths(url, report) {
  report.checks.push("API documentation discovery check");
  const paths = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/graphql",
    "/graphiql"
  ];
  const discovered = [];
  for (const item of paths) {
    const target = new URL(item, url.origin).toString();
    const info = await fetchUrl(target);
    if (info.error) continue;
    if (info.status >= 200 && info.status < 300) {
      const apiInfo = summarizeApiDocument(info.bodySample, info.headers["content-type"]);
      discovered.push({ url: target, status: info.status, ...apiInfo });
      addFinding(report, {
        id: `api-doc-${item.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`,
        title: apiInfo.kind === "graphql" ? "GraphQL endpoint is reachable" : "API documentation/schema endpoint is reachable",
        severity: "medium",
        category: "API security",
        location: target,
        evidence: apiInfo.evidence || `HTTP ${info.status}`,
        owasp: "API9:2023 Improper Inventory Management",
        remediation: "Verify the endpoint is intended to be public, does not expose internal schemas, and requires authentication where appropriate."
      });
    }
    await delay(150);
  }
  if (discovered.length) report.inventory.discoveredApiDocs = discovered;
  recordCoverage(report, "API surface discovery", "Common schema endpoints", discovered.length ? "reviewed" : "reviewed-no-findings", `${discovered.length} API documentation/schema endpoint(s) found.`);
}

function summarizeApiDocument(body, contentType = "") {
  const text = body || "";
  const data = parseJson(text);
  if (data?.openapi || data?.swagger) {
    const paths = Object.keys(data.paths || {});
    return {
      kind: "openapi",
      pathCount: paths.length,
      evidence: `${data.openapi ? `OpenAPI ${data.openapi}` : `Swagger ${data.swagger}`}; ${paths.length} path(s).`
    };
  }
  if (/graphql/i.test(contentType) || /\b(query|mutation|__schema|GraphQL)\b/i.test(text)) {
    return { kind: "graphql", evidence: "GraphQL-like response or endpoint marker detected." };
  }
  return { kind: "unknown", evidence: `Response content-type: ${contentType || "unknown"}` };
}

async function runUrlToolChecks(url, args, report) {
  report.checks.push("Active scanner availability check");
  const profile = activeProfile(args.profile);
  await runHttpxProbe(url, report);
  if (url.protocol === "https:") {
    await runSslyzeScan(url, report);
  } else {
    report.skipped.push("SSLyze TLS scan skipped because target URL is not HTTPS.");
    recordCoverage(report, "Deep TLS posture", "SSLyze", "not-applicable", "Target is not HTTPS.");
  }
  await runKatanaCrawler(url, profile, report);
  await runFfufContentDiscovery(url, profile, report);

  if (await hasCommand("nuclei")) {
    const result = await runCommand("nuclei", [
      "-u", url.toString(),
      "-severity", profile.nucleiSeverity,
      "-pt", "http,ssl",
      "-ept", "headless,code,javascript,dns,tcp,workflow,websocket,whois",
      "-etags", "dos,bruteforce,fuzz,intrusive,destructive",
      "-jsonl",
      "-rate-limit", String(profile.rateLimit),
      "-bs", "5",
      "-c", String(profile.nucleiConcurrency),
      "-pc", "5",
      "-mhe", "10",
      "-retries", "1",
      "-timeout", String(profile.nucleiTimeout),
      "-duc",
      "-silent",
      "-no-color"
    ], process.cwd(), profile.nucleiCommandTimeout);
    if (result.error) {
      report.skipped.push(`nuclei failed: ${result.error}`);
      recordTool(report, "nuclei", "failed");
      recordCoverage(report, "Template-based DAST", "Nuclei", "failed", result.error);
    } else {
      parseNuclei(result.stdout, report);
      report.checks.push("nuclei executed in active mode");
      recordTool(report, "nuclei", "executed", result.code);
      recordCoverage(report, "Template-based DAST", "Nuclei", "reviewed", "Ran medium/high/critical templates with low rate limits.");
    }
  } else {
    report.skipped.push("nuclei not run; command not available.");
    recordTool(report, "nuclei", "missing-or-not-applicable");
    recordCoverage(report, "Template-based DAST", "Nuclei", "missing", "nuclei command was not available.");
  }

  const zapRan = await runZapDocker(url, report);
  if (!zapRan) await runZapStandalone(url, report);
}

async function runHttpxProbe(url, report) {
  if (!(await hasCommand("httpx"))) {
    report.skipped.push("httpx not run; command not available.");
    recordTool(report, "httpx", "missing-or-not-applicable");
    recordCoverage(report, "HTTP fingerprinting", "httpx", "missing", "httpx command was not available.");
    return;
  }

  const result = await runCommand("httpx", [
    "-u", url.toString(),
    "-json",
    "-status-code",
    "-title",
    "-tech-detect",
    "-web-server",
    "-location",
    "-cdn",
    "-ip",
    "-cname",
    "-probe",
    "-silent",
    "-no-color",
    "-duc",
    "-rl", "2",
    "-timeout", "6",
    "-retries", "1"
  ], process.cwd(), 60000);

  if (result.error) {
    report.skipped.push(`httpx failed: ${result.error}`);
    recordTool(report, "httpx", "failed");
    recordCoverage(report, "HTTP fingerprinting", "httpx", "failed", result.error);
    return;
  }

  parseHttpx(result.stdout, report);
  report.checks.push("httpx fingerprint probe executed in active mode");
  recordTool(report, "httpx", "executed", result.code);
  recordCoverage(report, "HTTP fingerprinting", "httpx", "reviewed", "Collected status, title, server, CDN, IP, CNAME, and technology hints.");
}

function activeProfile(name) {
  const profiles = {
    safe: {
      rateLimit: 2,
      nucleiSeverity: "medium,high,critical",
      nucleiTimeout: 5,
      nucleiCommandTimeout: 120000,
      nucleiConcurrency: 6,
      katanaDepth: 1,
      katanaDuration: "30s",
      katanaMaxPages: 25,
      ffufMaxTime: 90,
      ffufCommandTimeout: 120000
    },
    balanced: {
      rateLimit: 3,
      nucleiSeverity: "medium,high,critical",
      nucleiTimeout: 6,
      nucleiCommandTimeout: 180000,
      nucleiConcurrency: 10,
      katanaDepth: 2,
      katanaDuration: "45s",
      katanaMaxPages: 25,
      ffufMaxTime: 120,
      ffufCommandTimeout: 150000
    },
    deep: {
      rateLimit: 3,
      nucleiSeverity: "low,medium,high,critical",
      nucleiTimeout: 8,
      nucleiCommandTimeout: 240000,
      nucleiConcurrency: 10,
      katanaDepth: 3,
      katanaDuration: "3m",
      katanaMaxPages: 150,
      ffufMaxTime: 300,
      ffufCommandTimeout: 330000
    }
  };
  return profiles[name] || profiles.balanced;
}

async function runSslyzeScan(url, report) {
  if (!(await hasCommand("sslyze"))) {
    report.skipped.push("SSLyze not run; command not available.");
    recordTool(report, "sslyze", "missing-or-not-applicable");
    recordCoverage(report, "Deep TLS posture", "SSLyze", "missing", "sslyze command was not available.");
    return;
  }

  const sslyzeDir = await fs.mkdtemp(path.join(os.tmpdir(), "security-audit-sslyze-"));
  const sslyzeReport = path.join(sslyzeDir, "sslyze.json");
  const target = `${url.hostname}:${url.port || 443}`;
  const result = await runCommand("sslyze", [
    "--json_out", sslyzeReport,
    "--quiet",
    "--slow_connection",
    "--tlsv1",
    "--tlsv1_1",
    "--tlsv1_2",
    "--tlsv1_3",
    "--sslv3",
    "--heartbleed",
    "--robot",
    "--openssl_ccs",
    "--compression",
    "--reneg",
    target
  ], process.cwd(), 300000);
  const sslyzeJson = await fs.readFile(sslyzeReport, "utf8").catch(() => "");
  await fs.rm(sslyzeDir, { recursive: true, force: true }).catch(() => {});

  if (result.error) {
    report.skipped.push(`SSLyze failed: ${result.error}`);
    recordTool(report, "sslyze", "failed");
    recordCoverage(report, "Deep TLS posture", "SSLyze", "failed", result.error);
    return;
  }
  if (!sslyzeJson) {
    report.skipped.push(`SSLyze produced no JSON report. ${result.stderr.slice(0, 160)}`);
    recordTool(report, "sslyze", "failed", result.code);
    recordCoverage(report, "Deep TLS posture", "SSLyze", "failed", "No JSON report was produced.");
    return;
  }

  parseSslyze(sslyzeJson, report);
  report.checks.push("SSLyze deep TLS scan executed in active mode");
  recordTool(report, "sslyze", "executed", result.code);
  recordCoverage(report, "Deep TLS posture", "SSLyze", "reviewed", "Checked legacy protocols, compression, Heartbleed, ROBOT, CCS injection, and renegotiation.");
}

async function runKatanaCrawler(url, profile, report) {
  if (!(await hasCommand("katana"))) {
    report.skipped.push("katana not run; command not available.");
    recordTool(report, "katana", "missing-or-not-applicable");
    recordCoverage(report, "Crawler-assisted attack surface", "katana", "missing", "katana command was not available.");
    return;
  }

  const result = await runCommand("katana", [
    "-u", url.toString(),
    "-d", String(profile.katanaDepth),
    "-jc",
    "-fx",
    "-rl", String(profile.rateLimit),
    "-c", "2",
    "-timeout", "8",
    "-ct", profile.katanaDuration,
    "-mdp", String(profile.katanaMaxPages),
    "-jsonl",
    "-silent",
    "-nc",
    "-duc",
    "-ob",
    "-or"
  ], process.cwd(), 180000);

  if (result.error) {
    report.skipped.push(`katana failed: ${result.error}`);
    recordTool(report, "katana", "failed");
    recordCoverage(report, "Crawler-assisted attack surface", "katana", "failed", result.error);
    return;
  }

  parseKatana(result.stdout, report);
  report.checks.push("katana bounded crawler executed in active mode");
  recordTool(report, "katana", "executed", result.code);
  recordCoverage(report, "Crawler-assisted attack surface", "katana", "reviewed", "Crawled same-scope links and JavaScript-derived endpoints with low rate limits.");
}

async function runFfufContentDiscovery(url, profile, report) {
  if (!(await hasCommand("ffuf"))) {
    report.skipped.push("ffuf not run; command not available.");
    recordTool(report, "ffuf", "missing-or-not-applicable");
    recordCoverage(report, "Common content discovery", "ffuf", "missing", "ffuf command was not available.");
    return;
  }
  if (!(await exists(discoveryWordlistPath))) {
    report.skipped.push(`ffuf not run; wordlist missing at ${discoveryWordlistPath}.`);
    recordTool(report, "ffuf", "missing-or-not-applicable");
    recordCoverage(report, "Common content discovery", "ffuf", "missing", "Bundled discovery wordlist was missing.");
    return;
  }

  const ffufDir = await fs.mkdtemp(path.join(os.tmpdir(), "security-audit-ffuf-"));
  const ffufReport = path.join(ffufDir, "ffuf.json");
  const result = await runCommand("ffuf", [
    "-w", discoveryWordlistPath,
    "-u", `${url.origin}/FUZZ`,
    "-rate", String(profile.rateLimit),
    "-t", "3",
    "-timeout", "6",
    "-maxtime", String(profile.ffufMaxTime),
    "-noninteractive",
    "-s",
    "-json",
    "-mc", "200,204,301,302,307,308,401,403,405,500",
    "-of", "json",
    "-o", ffufReport
  ], process.cwd(), profile.ffufCommandTimeout);
  const ffufJson = await fs.readFile(ffufReport, "utf8").catch(() => "");
  await fs.rm(ffufDir, { recursive: true, force: true }).catch(() => {});

  if (result.error) {
    report.skipped.push(`ffuf failed: ${result.error}`);
    recordTool(report, "ffuf", "failed");
    recordCoverage(report, "Common content discovery", "ffuf", "failed", result.error);
    return;
  }
  if (!ffufJson) {
    report.skipped.push(`ffuf produced no JSON report. ${result.stderr.slice(0, 160)}`);
    recordTool(report, "ffuf", "failed", result.code);
    recordCoverage(report, "Common content discovery", "ffuf", "failed", "No JSON report was produced.");
    return;
  }

  parseFfuf(ffufJson, report);
  report.checks.push("ffuf bounded content discovery executed in active mode");
  recordTool(report, "ffuf", "executed", result.code);
  recordCoverage(report, "Common content discovery", "ffuf", "reviewed", "Checked a bundled high-signal path list at low rate.");
}

async function runZapDocker(url, report) {
  if (!(await hasCommand("docker"))) {
    report.skipped.push("OWASP ZAP Docker baseline not run; docker command not available.");
    recordTool(report, "OWASP ZAP Docker baseline", "missing-or-not-applicable");
    recordCoverage(report, "DAST proxy scan", "OWASP ZAP Docker baseline", "missing", "docker command was not available.");
    return false;
  }

  const zapDir = await fs.mkdtemp(path.join(os.tmpdir(), "security-audit-zap-"));
  const zapReport = path.join(zapDir, "zap-baseline.json");
  const volume = `${zapDir}:/zap/wrk/:rw`;
  const result = await runCommand("docker", [
    "run", "--rm", "-v", volume, "-t", "ghcr.io/zaproxy/zaproxy:stable",
    "zap-baseline.py", "-t", url.toString(), "-J", "zap-baseline.json", "-I"
  ], process.cwd(), 600000);
  const zapJson = await fs.readFile(zapReport, "utf8").catch(() => "");
  await fs.rm(zapDir, { recursive: true, force: true }).catch(() => {});

  if (result.error) {
    report.skipped.push(`OWASP ZAP Docker baseline failed: ${result.error}`);
    recordTool(report, "OWASP ZAP Docker baseline", "failed");
    recordCoverage(report, "DAST proxy scan", "OWASP ZAP Docker baseline", "failed", result.error);
    return false;
  }
  if (!zapJson) {
    report.skipped.push(`OWASP ZAP Docker baseline produced no JSON report. ${result.stderr.slice(0, 160)}`);
    recordTool(report, "OWASP ZAP Docker baseline", "failed", result.code);
    recordCoverage(report, "DAST proxy scan", "OWASP ZAP Docker baseline", "failed", "No JSON report was produced.");
    return false;
  }

  parseZapBaseline(zapJson, report);
  report.checks.push("OWASP ZAP Docker baseline executed in active mode");
  recordTool(report, "OWASP ZAP Docker baseline", "executed", result.code);
  recordCoverage(report, "DAST proxy scan", "OWASP ZAP Docker baseline", "reviewed", "Ran ZAP baseline through Docker.");
  return true;
}

async function runZapStandalone(url, report) {
  const zapCommand = await resolveBundledCommand("zap") ||
    await resolveBundledCommand("zap.bat") ||
    await resolveBundledCommand("zap.sh") ||
    await resolveBundledCommand("zap");

  if (!zapCommand) {
    report.skipped.push("OWASP ZAP standalone not run; zap command not available.");
    recordTool(report, "OWASP ZAP standalone quick scan", "missing-or-not-applicable");
    recordCoverage(report, "DAST proxy scan", "OWASP ZAP standalone quick scan", "missing", "zap command was not available.");
    return false;
  }

  const zapDir = await fs.mkdtemp(path.join(os.tmpdir(), "security-audit-zap-standalone-"));
  const zapReport = path.join(zapDir, "zap-quick.json");
  const zapArgs = [
    "-cmd",
    "-quickurl", url.toString(),
    "-quickout", zapReport,
    "-quickprogress"
  ];
  const result = await runResolvedCommand(zapCommand, zapArgs, process.cwd(), 600000);
  const zapJson = await fs.readFile(zapReport, "utf8").catch(() => "");
  await fs.rm(zapDir, { recursive: true, force: true }).catch(() => {});

  if (result.error) {
    report.skipped.push(`OWASP ZAP standalone quick scan failed: ${result.error}`);
    recordTool(report, "OWASP ZAP standalone quick scan", "failed");
    recordCoverage(report, "DAST proxy scan", "OWASP ZAP standalone quick scan", "failed", result.error);
    return false;
  }
  if (!zapJson) {
    report.skipped.push(`OWASP ZAP standalone quick scan produced no JSON report. ${result.stderr.slice(0, 160)}`);
    recordTool(report, "OWASP ZAP standalone quick scan", "failed", result.code);
    recordCoverage(report, "DAST proxy scan", "OWASP ZAP standalone quick scan", "failed", "No JSON report was produced.");
    return false;
  }

  parseZapBaseline(zapJson, report);
  report.checks.push("OWASP ZAP standalone quick scan executed in active mode");
  recordTool(report, "OWASP ZAP standalone quick scan", "executed", result.code);
  recordCoverage(report, "DAST proxy scan", "OWASP ZAP standalone quick scan", "reviewed", "Ran bundled standalone ZAP Quick Start scan.");
  return true;
}

function addFinding(report, finding) {
  report.findings.push({
    id: finding.id,
    severity: finding.severity || "info",
    title: finding.title,
    category: finding.category || "General",
    location: finding.location || "",
    evidence: finding.evidence || "",
    owasp: finding.owasp || "",
    cwe: finding.cwe || "",
    remediation: finding.remediation || "Review and remediate according to the affected component's security guidance.",
    confidence: finding.confidence || "medium"
  });
}

function recordTool(report, name, status, exitCode) {
  report.tools.push({
    name,
    status,
    ...(exitCode !== undefined ? { exitCode } : {})
  });
}

function recordCoverage(report, area, method, status, notes) {
  report.coverage.push({ area, method, status, notes });
}

function addLocalReviewedSurfaces(report) {
  report.reviewedSurfaces.push(
    {
      surface: "Local source files",
      riskArea: "Injection, deserialization, XSS, command execution",
      outcome: "Reviewed",
      notes: `${report.inventory.scannedFiles || 0} source-like files scanned with high-signal patterns.`
    },
    {
      surface: "Secrets and sensitive files",
      riskArea: "Credential exposure",
      outcome: "Reviewed",
      notes: "Built-in redacted patterns and sensitive root-file checks ran; external secret scanners run when installed."
    },
    {
      surface: "Dependency manifests",
      riskArea: "Known vulnerable components",
      outcome: report.inventory.lockfiles?.length ? "Reviewed" : "Not applicable",
      notes: report.inventory.lockfiles?.length ? `Lockfiles detected: ${report.inventory.lockfiles.join(", ")}.` : "No supported lockfiles detected in inventory."
    },
    {
      surface: "Routes and API definitions",
      riskArea: "Authz, BOLA/IDOR, CSRF, API inventory",
      outcome: "Reviewed",
      notes: `${report.inventory.endpoints?.length || 0} route declarations and ${report.inventory.apiArtifacts?.length || 0} API artifacts inventoried.`
    },
    {
      surface: "Authorization and business logic hotspots",
      riskArea: "IDOR/BOLA, mass assignment, privilege-field tampering",
      outcome: "Reviewed",
      notes: "Route neighborhoods, object lookup patterns, request-body assignment, and privilege-field assignment signals were scanned."
    },
    {
      surface: "Token and session handling",
      riskArea: "JWT verification, weak signing secrets, browser-readable tokens, cookie options",
      outcome: "Reviewed",
      notes: "JWT/session code patterns and client-side token storage signals were scanned."
    },
    {
      surface: "CI/CD workflows",
      riskArea: "pull_request_target, privileged tokens, unpinned actions",
      outcome: report.inventory.githubWorkflowFiles ? "Reviewed" : "Not applicable",
      notes: report.inventory.githubWorkflowFiles ? `${report.inventory.githubWorkflowFiles} GitHub Actions workflow file(s) scanned.` : "No GitHub Actions workflow files detected."
    }
  );
}

function addUrlReviewedSurfaces(report) {
  report.reviewedSurfaces.push(
    {
      surface: "HTTP response",
      riskArea: "Security headers, CORS, cookies, information disclosure",
      outcome: "Reviewed",
      notes: `Fetched ${report.inventory.finalUrl || report.target} with status ${report.inventory.status || "unknown"}.`
    },
    {
      surface: "TLS endpoint",
      riskArea: "Certificate validity and negotiated protocol",
      outcome: report.inventory.tlsProtocol ? "Reviewed" : "Needs follow-up",
      notes: report.inventory.tlsProtocol ? `Negotiated ${report.inventory.tlsProtocol}.` : "TLS was not available or the check failed."
    },
    {
      surface: "Exposure paths",
      riskArea: "Public sensitive files and debug endpoints",
      outcome: report.mode === "passive" ? "Deferred" : "Reviewed",
      notes: report.mode === "passive" ? "Skipped in passive mode." : "Shallow exposure-path checks ran with low request rate."
    },
    {
      surface: "DAST scanners",
      riskArea: "Template-based and crawler-assisted website vulnerabilities",
      outcome: report.mode === "active" ? "Reviewed" : "Deferred",
      notes: report.mode === "active" ? "Active scanner orchestration attempted where tools were installed." : "Requires active mode and explicit authorization."
    },
    {
      surface: "Public SPA bundles",
      riskArea: "Debug logging, endpoint maps, token storage, secret-like config, identity/payment workflow signals",
      outcome: report.checks?.includes("Public SPA bundle risk signal check") ? "Reviewed" : "Deferred",
      notes: "JavaScript bundle discovery runs on fetched pages when script assets are present."
    }
  );
}

function sortFindings(findings) {
  findings.sort((a, b) => {
    const severityDelta = (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
    if (severityDelta) return severityDelta;
    return `${a.location}${a.title}`.localeCompare(`${b.location}${b.title}`);
  });
}

function trimEvidence(line) {
  return line.trim().slice(0, 260);
}

function redactSecret(value) {
  const trimmed = String(value).trim();
  if (trimmed.length <= 12) return "[redacted]";
  return `${trimmed.slice(0, 4)}...[redacted]...${trimmed.slice(-4)}`;
}

function remediationForRule(id) {
  const map = {
    "js-eval": "Remove eval. Use structured parsers, lookup tables, or a constrained expression evaluator.",
    "js-function-constructor": "Remove dynamic Function construction. Replace with explicit functions or a safe parser.",
    "react-dangerous-html": "Render text by default. If HTML is required, sanitize with a mature sanitizer and enforce CSP.",
    "js-innerhtml": "Use textContent or framework escaping. Sanitize trusted HTML before assignment.",
    "node-child-process-exec": "Use execFile/spawn with argument arrays and strict allowlists for user-controlled values.",
    "node-file-read-hotspot": "Constrain file paths to an allowlisted base directory, canonicalize before use, and enforce object authorization before returning file contents.",
    "node-ssrf-hotspot": "If the URL is user-controlled, allowlist schemes and hosts, resolve and block private/link-local ranges after redirects, and set timeouts.",
    "prisma-query-raw-unsafe": "Use parameterized Prisma APIs or tagged templates instead of queryRawUnsafe with concatenated/user-controlled SQL.",
    "mongo-where": "Avoid $where and JavaScript predicates; use structured query operators with server-side validation.",
    "open-redirect-hotspot": "Only redirect to relative paths or allowlisted origins, especially in login, callback, and OAuth flows.",
    "express-cors-wildcard": "Replace wildcard CORS with an environment-specific allowlist.",
    "python-debug-true": "Disable debug mode outside local development and ensure production error handlers are generic.",
    "python-subprocess-shell": "Use subprocess argument arrays with shell=False and validate allowed commands.",
    "python-requests-ssrf-hotspot": "If the URL is user-controlled, allowlist schemes and hosts, resolve and block private/link-local ranges after redirects, and set timeouts.",
    "python-file-open-hotspot": "Constrain file paths to an allowlisted base directory, canonicalize before use, and enforce object authorization before returning file contents.",
    "python-archive-extractall": "Validate each archive member path and link target against the destination before extracting, and reject absolute or traversal paths.",
    "python-pickle-loads": "Avoid pickle for untrusted data. Use JSON or a safe serialization format.",
    "python-yaml-load": "Use yaml.safe_load or explicitly configure SafeLoader.",
    "python-xml-parser-hotspot": "Use hardened XML parsers such as defusedxml or disable external entities, DTDs, and network access on the exact parser instance.",
    "php-eval": "Remove eval and replace with explicit control flow or safe parsing.",
    "php-unserialize": "Avoid unserialize on untrusted data; use JSON or allowed_classes restrictions where unavoidable.",
    "java-xml-parser-hotspot": "Set XXE hardening features on the exact parser factory, install safe resolvers, and fail closed when hardening cannot be applied.",
    "java-process-builder-hotspot": "Pass arguments as arrays, avoid shell interpretation, and allowlist command and argument values."
  };
  return map[id] || "Review this pattern manually and replace it with a safer framework-supported API.";
}

async function exists(file) {
  return Boolean(await fs.stat(file).catch(() => null));
}

async function readJson(file) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    return null;
  }
}

async function hasCommand(command) {
  if (await resolveBundledCommand(command)) return true;
  const checker = process.platform === "win32" ? "where.exe" : "which";
  const args = [command];
  const result = await runCommand(checker, args, process.cwd(), 10000);
  return !result.error && result.code === 0;
}

async function runCommand(command, args, cwd, timeoutMs, spawnOptions = {}) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    resolveCommandForSpawn(command).then((resolvedCommand) => {
      const child = spawn(resolvedCommand, args, {
        cwd,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
        env: commandEnv(),
        ...spawnOptions
      });
    const timer = setTimeout(() => {
      child.kill();
      resolve({ error: `${command} timed out after ${timeoutMs}ms`, stdout, stderr, code: -1 });
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ error: error.message, stdout, stderr, code: -1 });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
    });
  });
}

async function runResolvedCommand(resolvedCommand, args, cwd, timeoutMs) {
  if (process.platform === "win32" && /\.(bat|cmd)$/i.test(resolvedCommand)) {
    const line = `call ${quoteWindowsCmdArg(resolvedCommand)} ${args.map(quoteWindowsCmdArg).join(" ")}`;
    return runCommand("cmd.exe", ["/d", "/c", line], cwd, timeoutMs, { windowsVerbatimArguments: true });
  }
  return runCommand(resolvedCommand, args, cwd, timeoutMs);
}

function quoteWindowsCmdArg(value) {
  const text = String(value);
  return `"${text.replace(/(["^&<>|])/g, "^$1")}"`;
}

async function resolveCommandForSpawn(command) {
  return (await resolveBundledCommand(command)) || command;
}

async function resolveBundledCommand(command) {
  if (path.isAbsolute(command)) {
    return (await isExecutableFile(command)) ? command : "";
  }

  for (const dir of bundledToolDirs) {
    for (const name of executableNames(command)) {
      const candidate = path.join(dir, name);
      if (await isExecutableFile(candidate)) return candidate;
    }
  }
  return "";
}

function executableNames(command) {
  if (process.platform !== "win32" || path.extname(command)) return [command];
  return [`${command}.exe`, `${command}.cmd`, `${command}.bat`, `${command}.ps1`, command];
}

async function isExecutableFile(file) {
  const stat = await fs.stat(file).catch(() => null);
  return Boolean(stat?.isFile());
}

function commandEnv() {
  const env = { ...process.env };
  const current = env.Path || env.PATH || "";
  const extraPath = bundledToolDirs.join(path.delimiter);
  const nextPath = extraPath ? `${extraPath}${path.delimiter}${current}` : current;
  env.PATH = nextPath;
  if (process.platform === "win32") env.Path = nextPath;
  return env;
}

function parseNpmAudit(stdout, stderr, report) {
  const data = parseJson(stdout);
  if (!data) {
    report.skipped.push(`npm audit output was not JSON. ${stderr.slice(0, 120)}`);
    return;
  }
  const vulnerabilities = data.vulnerabilities || {};
  for (const [name, vuln] of Object.entries(vulnerabilities)) {
    const severity = normalizeSeverity(vuln.severity);
    if (severityRank[severity] < severityRank.medium) continue;
    addFinding(report, {
      id: `npm-audit-${name}`,
      title: `Vulnerable npm dependency: ${name}`,
      severity,
      category: "Dependency vulnerability",
      location: "package-lock.json",
      evidence: `${name} ${vuln.range || ""} via ${(vuln.via || []).map((v) => typeof v === "string" ? v : v.name).join(", ")}`.trim(),
      owasp: "A06:2021 Vulnerable and Outdated Components",
      remediation: vuln.fixAvailable ? "Upgrade using npm audit fix or manually update the dependency and test regressions." : "Review upstream advisories and upgrade, patch, replace, or isolate the dependency."
    });
  }
}

function parseGitleaks(stdout, _stderr, report) {
  const data = parseJson(stdout);
  if (!Array.isArray(data)) {
    if (!stdout.trim()) return;
    report.skipped.push("gitleaks output was not a JSON array.");
    return;
  }
  for (const item of data) {
    addFinding(report, {
      id: `gitleaks-${item.RuleID || item.Fingerprint || "secret"}`,
      title: item.Description || "Secret detected by Gitleaks",
      severity: "critical",
      category: "Secret exposure",
      location: `${item.File || "unknown"}:${item.StartLine || "?"}`,
      evidence: item.Secret ? redactSecret(item.Secret) : "Secret value redacted by scanner.",
      owasp: "A02:2021 Cryptographic Failures",
      cwe: "CWE-798",
      remediation: "Revoke and rotate the credential, remove it from history where required, and move secret loading to a managed secret store."
    });
  }
}

function parseTrufflehog(stdout, _stderr, report) {
  const lines = stdout.split(/\r?\n/).filter(Boolean);
  for (const line of lines) {
    const item = parseJson(line);
    if (!item) continue;
    const file = item.SourceMetadata?.Data?.Filesystem?.file || item.SourceMetadata?.Data?.Git?.file || "unknown";
    const verified = Boolean(item.Verified);
    addFinding(report, {
      id: `trufflehog-${item.DetectorName || item.DetectorType || "secret"}`,
      title: `${verified ? "Verified" : "Potential"} secret detected by TruffleHog`,
      severity: verified ? "critical" : "high",
      category: "Secret exposure",
      location: file,
      evidence: item.Raw ? redactSecret(item.Raw) : "Secret value redacted.",
      owasp: "A02:2021 Cryptographic Failures",
      cwe: "CWE-798",
      remediation: "Revoke verified credentials immediately. For unverified findings, validate carefully without exposing the value, then rotate if confirmed."
    });
  }
}

function parsePipAudit(stdout, _stderr, report) {
  const data = parseJson(stdout);
  if (!data) {
    report.skipped.push("pip-audit output was not JSON.");
    return;
  }
  for (const dependency of data.dependencies || []) {
    for (const vuln of dependency.vulns || []) {
      addFinding(report, {
        id: `pip-audit-${vuln.id}`,
        title: `Vulnerable Python dependency: ${dependency.name}`,
        severity: normalizeSeverity(vuln.severity || "medium"),
        category: "Dependency vulnerability",
        location: dependency.name,
        evidence: `${vuln.id}: ${vuln.description || ""}`.slice(0, 260),
        owasp: "A06:2021 Vulnerable and Outdated Components",
        remediation: vuln.fix_versions?.length
          ? `Upgrade ${dependency.name} to ${vuln.fix_versions.join(", ")} or later and test regressions.`
          : `Review ${vuln.id} and upgrade, patch, replace, or isolate ${dependency.name}.`
      });
    }
  }
}

function parseBandit(stdout, _stderr, report) {
  const data = parseJson(stdout);
  if (!data) {
    report.skipped.push("bandit output was not JSON.");
    return;
  }
  for (const item of data.results || []) {
    addFinding(report, {
      id: `bandit-${item.test_id}`,
      title: item.issue_text || item.test_name || "Bandit finding",
      severity: normalizeSeverity(item.issue_severity),
      category: "SAST",
      location: `${item.filename || "unknown"}:${item.line_number || "?"}`,
      evidence: trimEvidence(item.code || item.test_name || ""),
      cwe: item.issue_cwe?.id ? `CWE-${item.issue_cwe.id}` : "",
      remediation: "Validate the Bandit finding against data flow and replace the risky API or configuration with a safer pattern."
    });
  }
}

function parseCargoAudit(stdout, _stderr, report) {
  const data = parseJson(stdout);
  if (!data) {
    report.skipped.push("cargo audit output was not JSON.");
    return;
  }
  for (const item of data.vulnerabilities?.list || []) {
    const advisory = item.advisory || {};
    addFinding(report, {
      id: `cargo-audit-${advisory.id || item.package?.name}`,
      title: `Vulnerable Rust crate: ${item.package?.name || advisory.package || "dependency"}`,
      severity: severityFromCvss(advisory.cvss) || normalizeSeverity(advisory.severity || "medium"),
      category: "Dependency vulnerability",
      location: "Cargo.lock",
      evidence: `${advisory.id || ""} ${advisory.title || ""}`.trim(),
      owasp: "A06:2021 Vulnerable and Outdated Components",
      remediation: advisory.patched_versions
        ? `Upgrade to a patched version: ${advisory.patched_versions}.`
        : "Upgrade to a non-vulnerable crate version or apply the RustSec advisory mitigation."
    });
  }
}

function parseGovulncheck(stdout, _stderr, report) {
  const lines = stdout.split(/\r?\n/).filter(Boolean);
  for (const line of lines) {
    const item = parseJson(line);
    const finding = item?.finding;
    if (!finding) continue;
    addFinding(report, {
      id: `govulncheck-${finding.osv || finding.symbol || "finding"}`,
      title: `Go vulnerability reachable: ${finding.osv || finding.symbol || "finding"}`,
      severity: "high",
      category: "Dependency vulnerability",
      location: finding.trace?.[0]?.position?.filename || "go.mod",
      evidence: `${finding.symbol || ""} ${finding.fixed_version ? `fixed in ${finding.fixed_version}` : ""}`.trim(),
      owasp: "A06:2021 Vulnerable and Outdated Components",
      remediation: finding.fixed_version
        ? `Upgrade the affected module to ${finding.fixed_version} or later.`
        : "Review govulncheck trace and upgrade or refactor away from the vulnerable symbol."
    });
  }
}

function parseComposerAudit(stdout, _stderr, report) {
  const data = parseJson(stdout);
  if (!data) {
    report.skipped.push("composer audit output was not JSON.");
    return;
  }
  const advisories = data.advisories || {};
  for (const [pkgName, pkgAdvisories] of Object.entries(advisories)) {
    const list = Array.isArray(pkgAdvisories) ? pkgAdvisories : Object.values(pkgAdvisories || {});
    for (const advisory of list) {
      addFinding(report, {
        id: `composer-audit-${advisory.cve || advisory.advisoryId || advisory.title || pkgName}`,
        title: `Vulnerable PHP dependency: ${pkgName}`,
        severity: normalizeSeverity(advisory.severity || "medium"),
        category: "Dependency vulnerability",
        location: "composer.lock",
        evidence: `${advisory.cve || ""} ${advisory.title || ""}`.trim(),
        owasp: "A06:2021 Vulnerable and Outdated Components",
        remediation: "Upgrade the affected package to a fixed version listed by Composer or the upstream advisory."
      });
    }
  }
}

function parseOsvScanner(stdout, _stderr, report) {
  const data = parseJson(stdout);
  if (!data) {
    report.skipped.push("osv-scanner output was not JSON.");
    return;
  }
  const results = data.results || [];
  for (const result of results) {
    for (const pkg of result.packages || []) {
      for (const vuln of pkg.vulnerabilities || []) {
        addFinding(report, {
          id: `osv-${vuln.id}`,
          title: `Known vulnerability ${vuln.id} in ${pkg.package?.name || "dependency"}`,
          severity: normalizeSeverity(vuln.database_specific?.severity || "medium"),
          category: "Dependency vulnerability",
          location: result.source?.path || "lockfile",
          evidence: vuln.summary || vuln.id,
          owasp: "A06:2021 Vulnerable and Outdated Components",
          remediation: "Upgrade to a fixed version listed by OSV, or apply the vendor mitigation if no fixed version exists."
        });
      }
    }
  }
}

function parseSemgrep(stdout, _stderr, report) {
  const data = parseJson(stdout);
  if (!data) {
    report.skipped.push("semgrep output was not JSON.");
    return;
  }
  for (const result of data.results || []) {
    const extra = result.extra || {};
    const metadata = extra.metadata || {};
    addFinding(report, {
      id: `semgrep-${result.check_id}`,
      title: extra.message || result.check_id,
      severity: normalizeSeverity(extra.severity || metadata.impact || "medium"),
      category: "SAST",
      location: `${result.path}:${result.start?.line || "?"}`,
      evidence: result.extra?.lines?.trim()?.slice(0, 260) || result.check_id,
      owasp: metadata.owasp?.join?.(", ") || "",
      cwe: metadata.cwe?.join?.(", ") || "",
      remediation: metadata.fix || "Review the Semgrep finding, validate data flow, and apply the recommended secure coding pattern.",
      confidence: normalizeConfidence(metadata.confidence)
    });
  }
}

function parseHttpx(stdout, report) {
  const fingerprints = [];
  for (const line of stdout.split(/\r?\n/).filter(Boolean)) {
    const item = parseJson(line);
    if (!item) continue;
    fingerprints.push({
      url: item.url,
      statusCode: item.status_code,
      title: item.title,
      webserver: item.webserver,
      tech: item.tech || [],
      cdn: item.cdn_name || item.cdn || "",
      ip: item.host_ip || item.a?.[0] || "",
      cname: item.cname || ""
    });
  }
  if (!fingerprints.length) return;
  report.inventory.httpx = fingerprints.slice(0, 20);
  const primary = fingerprints[0];
  const tech = [
    primary.webserver,
    ...(primary.tech || [])
  ].filter(Boolean);
  if (tech.length) {
    addFinding(report, {
      id: "httpx-technology-fingerprint",
      title: "Technology fingerprint detected",
      severity: "info",
      category: "Information disclosure",
      location: primary.url || report.target,
      evidence: unique(tech).slice(0, 12).join(", "),
      remediation: "Minimize precise version disclosure where practical, and ensure exposed components are patched."
    });
  }
}

function parseSslyze(stdout, report) {
  const data = parseJson(stdout);
  if (!data) {
    report.skipped.push("SSLyze output was not JSON.");
    return;
  }

  for (const serverResult of data.server_scan_results || []) {
    const location = serverResult.server_location
      ? `${serverResult.server_location.hostname}:${serverResult.server_location.port}`
      : report.target;
    if (serverResult.scan_status && serverResult.scan_status !== "COMPLETED") {
      report.skipped.push(`SSLyze scan incomplete for ${location}: ${serverResult.scan_status}.`);
      continue;
    }

    const result = serverResult.scan_result || {};
    const tlsSummary = {};
    for (const [key, label, severity] of [
      ["ssl_3_0_cipher_suites", "SSL 3.0", "high"],
      ["tls_1_0_cipher_suites", "TLS 1.0", "medium"],
      ["tls_1_1_cipher_suites", "TLS 1.1", "medium"]
    ]) {
      const suiteResult = result[key]?.result;
      if (!suiteResult) continue;
      const supported = Boolean(suiteResult.is_tls_version_supported);
      tlsSummary[label] = supported ? "supported" : "rejected";
      if (supported) {
        addFinding(report, {
          id: `sslyze-deprecated-${label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
          title: `${label} is supported`,
          severity,
          category: "Transport security",
          location,
          evidence: `${label} accepted ${suiteResult.accepted_cipher_suites?.length || 0} cipher suite(s).`,
          owasp: "A02:2021 Cryptographic Failures",
          remediation: `Disable ${label} and support only modern TLS versions and ciphers.`
        });
      }
    }

    if (result.heartbleed?.result?.is_vulnerable_to_heartbleed) {
      addFinding(report, {
        id: "sslyze-heartbleed",
        title: "Server appears vulnerable to Heartbleed",
        severity: "critical",
        category: "Transport security",
        location,
        evidence: "SSLyze reported Heartbleed vulnerability.",
        cwe: "CWE-119",
        remediation: "Patch OpenSSL immediately, rotate affected private keys and certificates, and investigate possible secret exposure."
      });
    }

    const robotResult = String(result.robot?.result?.robot_result || "");
    if (/vulnerable/i.test(robotResult) && !/not[_\s-]?vulnerable/i.test(robotResult)) {
      addFinding(report, {
        id: "sslyze-robot",
        title: "Server appears vulnerable to ROBOT",
        severity: "high",
        category: "Transport security",
        location,
        evidence: robotResult,
        remediation: "Disable vulnerable RSA key exchange behavior and patch the affected TLS stack."
      });
    }

    if (result.openssl_ccs_injection?.result?.is_vulnerable_to_ccs_injection) {
      addFinding(report, {
        id: "sslyze-openssl-ccs",
        title: "Server appears vulnerable to OpenSSL CCS injection",
        severity: "high",
        category: "Transport security",
        location,
        evidence: "SSLyze reported OpenSSL CCS injection vulnerability.",
        remediation: "Patch OpenSSL and restart the affected service."
      });
    }

    if (result.tls_compression?.result?.supports_compression) {
      addFinding(report, {
        id: "sslyze-tls-compression",
        title: "TLS compression is enabled",
        severity: "medium",
        category: "Transport security",
        location,
        evidence: "SSLyze reported TLS compression support.",
        remediation: "Disable TLS-level compression to reduce CRIME-style risk."
      });
    }

    if (result.session_renegotiation?.result?.is_vulnerable_to_client_renegotiation_dos) {
      addFinding(report, {
        id: "sslyze-renegotiation-dos",
        title: "TLS client renegotiation DoS risk",
        severity: "medium",
        category: "Transport security",
        location,
        evidence: "SSLyze reported vulnerability to client renegotiation denial of service.",
        remediation: "Disable insecure client renegotiation or patch/reconfigure the TLS terminator."
      });
    }

    report.inventory.sslyze = {
      version: data.sslyze_version,
      target: location,
      tlsSummary
    };
  }
}

function parseKatana(stdout, report) {
  const urls = [];
  const apiUrls = [];
  const forms = [];
  for (const line of stdout.split(/\r?\n/).filter(Boolean)) {
    const item = parseJson(line);
    if (!item) continue;
    const endpoint = item.request?.endpoint || item.url || item.response?.url;
    if (endpoint) {
      urls.push(endpoint);
      const endpointPath = safeUrlPathname(endpoint);
      if (/\/(api|graphql|graphiql|rest|rpc)\b/i.test(endpointPath)) apiUrls.push(endpoint);
    }
    if (item.form || item.forms || item.input || item.inputs) forms.push(endpoint || report.target);
  }
  const discoveredUrls = unique(urls).slice(0, 150);
  const discoveredApiUrls = unique(apiUrls).slice(0, 75);
  report.inventory.crawledUrls = discoveredUrls.length;
  if (discoveredUrls.length) report.inventory.discoveredUrls = discoveredUrls;
  if (discoveredApiUrls.length) report.inventory.discoveredApiUrls = discoveredApiUrls;
  if (forms.length) report.inventory.discoveredForms = unique(forms).slice(0, 50);
}

function safeUrlPathname(value) {
  try {
    return new URL(value).pathname;
  } catch {
    return String(value || "");
  }
}

function parseFfuf(stdout, report) {
  const data = parseJson(stdout);
  if (!data) {
    report.skipped.push("ffuf output was not JSON.");
    return;
  }
  const results = Array.isArray(data.results) ? data.results : [];
  report.inventory.contentDiscoveryMatches = results.slice(0, 100).map((item) => ({
    url: item.url,
    status: item.status,
    length: item.length,
    words: item.words
  }));

  for (const item of results) {
    const classification = classifyDiscoveredPath(item.url, item.status);
    if (!classification) continue;
    addFinding(report, {
      id: `ffuf-${classification.id}`,
      title: classification.title,
      severity: classification.severity,
      category: "Exposed path",
      location: item.url,
      evidence: `HTTP ${item.status}, ${item.length || 0} bytes`,
      owasp: "A05:2021 Security Misconfiguration",
      remediation: classification.remediation,
      confidence: classification.confidence || "medium"
    });
  }
}

function classifyDiscoveredPath(rawUrl, status) {
  let pathname = "";
  try {
    pathname = new URL(rawUrl).pathname.toLowerCase();
  } catch {
    pathname = String(rawUrl || "").toLowerCase();
  }
  const statusNumber = Number(status);
  const accessible = statusNumber >= 200 && statusNumber < 300;
  const reachable = accessible || [301, 302, 307, 308, 401, 403, 405, 500].includes(statusNumber);

  const rules = [
    {
      id: "env-file",
      regex: /(^|\/)\.env($|[./_-])/,
      severity: "critical",
      title: "Potential environment file exposed",
      remediation: "Block environment files at the web root and remove secrets from deployed artifacts."
    },
    {
      id: "git-config",
      regex: /(^|\/)\.git\/config$/,
      severity: "high",
      title: "Git metadata may be exposed",
      remediation: "Remove .git directories from web deployments and block dot-directories at the web server."
    },
    {
      id: "phpinfo",
      regex: /\/(phpinfo|info)\.php$/,
      severity: "high",
      title: "phpinfo-style diagnostic page may be exposed",
      remediation: "Remove diagnostic pages from production and restrict operational diagnostics to authenticated staff paths."
    },
    {
      id: "server-status",
      regex: /\/(server-status|server-info)\/?$/,
      severity: "medium",
      title: "Server status endpoint may be exposed",
      remediation: "Restrict server status endpoints to trusted administration networks."
    },
    {
      id: "spring-actuator",
      regex: /\/actuator(\/env|\/heapdump|\/configprops|\/metrics)?\/?$/,
      severity: "high",
      title: "Spring Actuator endpoint may be exposed",
      remediation: "Disable sensitive actuator endpoints or require strong authentication and network restrictions."
    },
    {
      id: "api-docs",
      regex: /\/(swagger-ui|swagger|api-docs|openapi|graphql|graphiql)(\/|$)/,
      severity: "medium",
      title: "API documentation or explorer endpoint is reachable",
      remediation: "Ensure API docs and explorers do not expose sensitive schemas and require authentication where appropriate."
    },
    {
      id: "admin-surface",
      regex: /\/(admin|administrator|wp-admin|manage|dashboard)\/?$/,
      severity: "info",
      title: "Administrative surface is reachable",
      remediation: "Verify the administrative surface enforces strong authentication, MFA where appropriate, and role-based authorization.",
      confidence: "low"
    }
  ];

  for (const rule of rules) {
    if (!rule.regex.test(pathname)) continue;
    if (!accessible && rule.id !== "admin-surface") return null;
    if (!reachable) return null;
    return rule;
  }
  return null;
}

function parseNuclei(stdout, report) {
  const lines = stdout.split(/\r?\n/).filter(Boolean);
  for (const line of lines) {
    const item = parseJson(line);
    if (!item) continue;
    const info = item.info || {};
    addFinding(report, {
      id: `nuclei-${item["template-id"] || item.templateID || info.name}`,
      title: info.name || "Nuclei finding",
      severity: normalizeSeverity(info.severity || "medium"),
      category: "DAST",
      location: item["matched-at"] || item.host || "",
      evidence: item["extracted-results"]?.join?.(", ") || item.matcher_name || item.type || "",
      owasp: info.classification?.["owasp-top-10"] || "",
      cwe: info.classification?.["cwe-id"] || "",
      remediation: info.remediation || "Validate the finding manually, then patch or reconfigure the affected service."
    });
  }
}

function parseZapBaseline(stdout, report) {
  const data = parseJson(stdout);
  if (!data) {
    report.skipped.push("OWASP ZAP baseline output was not JSON.");
    return;
  }
  for (const site of data.site || []) {
    for (const alert of site.alerts || []) {
      const severity = normalizeZapRisk(alert.riskcode, alert.riskdesc);
      if (severityRank[severity] < severityRank.low) continue;
      addFinding(report, {
        id: `zap-${alert.pluginid || alert.alertref || alert.name}`,
        title: alert.name || "OWASP ZAP finding",
        severity,
        category: "DAST",
        location: alert.instances?.[0]?.uri || site["@name"] || "",
        evidence: trimEvidence(alert.desc || alert.evidence || alert.solution || ""),
        cwe: alert.cweid && alert.cweid !== "-1" ? `CWE-${alert.cweid}` : "",
        remediation: alert.solution || "Validate the ZAP finding manually and apply the recommended hardening or code change."
      });
    }
  }
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function normalizeSeverity(value) {
  const text = String(value || "").toLowerCase();
  if (text.includes("critical")) return "critical";
  if (text.includes("high") || text === "error") return "high";
  if (text.includes("medium") || text.includes("moderate") || text === "warning") return "medium";
  if (text.includes("low")) return "low";
  return "info";
}

function normalizeZapRisk(code, desc) {
  const numeric = Number(code);
  if (numeric >= 3) return "high";
  if (numeric === 2) return "medium";
  if (numeric === 1) return "low";
  return normalizeSeverity(desc || "info");
}

function severityFromCvss(cvss) {
  const numeric = Number(cvss);
  if (!Number.isFinite(numeric)) return "";
  if (numeric >= 9) return "critical";
  if (numeric >= 7) return "high";
  if (numeric >= 4) return "medium";
  if (numeric > 0) return "low";
  return "info";
}

function normalizeConfidence(value) {
  const text = String(value || "").toLowerCase();
  if (["high", "medium", "low"].includes(text)) return text;
  return "medium";
}

function renderMarkdown(report) {
  const counts = report.findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {});
  const statusCounts = report.findings.reduce((acc, finding) => {
    const status = findingStatus(finding);
    acc[status] = (acc[status] || 0) + 1;
    return acc;
  }, {});
  const sections = ["critical", "high", "medium", "low", "info"];

  let md = `# AI Security Audit Pro Report for ${reportTargetName(report)}\n\n`;
  md += `Generated: ${report.startedAt}\n\n`;
  md += `Target: \`${report.target}\`\n\n`;
  md += `Mode: \`${report.mode}\`\n\n`;
  md += `Profile: \`${report.profile || "balanced"}\`\n\n`;
  md += `## Report Snapshot\n\n`;
  md += `| Metric | Value |\n|---|---|\n`;
  md += `| Overall assessment | ${overallRiskLabel(counts)} |\n`;
  md += `| Total findings | ${report.findings.length} |\n`;
  md += `| Critical / High / Medium / Low / Info | ${counts.critical || 0} / ${counts.high || 0} / ${counts.medium || 0} / ${counts.low || 0} / ${counts.info || 0} |\n`;
  md += `| Confirmed / Likely / Needs validation | ${statusCounts.Confirmed || 0} / ${statusCounts.Likely || 0} / ${statusCounts["Needs validation"] || 0} |\n`;
  md += `| Authorization flag | ${report.authorized ? "provided" : "not provided"} |\n`;
  md += `| Report ID | ${reportId(report)} |\n\n`;
  md += `## Assessment Conclusion\n\n`;
  md += renderAssessmentConclusion(report, counts, statusCounts);
  md += `\n\n`;
  md += `## Finding Overview\n\n`;
  md += `- Severity counts: Critical ${counts.critical || 0}, High ${counts.high || 0}, Medium ${counts.medium || 0}, Low ${counts.low || 0}, Info ${counts.info || 0}.\n`;
  md += `- Validation status: Confirmed ${statusCounts.Confirmed || 0}, Likely ${statusCounts.Likely || 0}, Needs validation ${statusCounts["Needs validation"] || 0}.\n`;
  md += `Inventory: ${formatInventory(report.inventory)}\n\n`;
  md += `## Scope And Authorization\n\n`;
  md += `${renderScopeAndAuthorization(report)}\n\n`;
  md += `## Key Risk Summary\n\n`;
  md += renderKeyRiskSummary(report);
  md += `\n\n`;
  md += `## Confirmed Vulnerabilities / Risks\n\n`;
  md += renderConfirmedVulnerabilitiesAndRisks(report);
  md += `\n\n`;
  md += `## Threat Model Summary\n\n`;
  md += `${renderThreatModelSummary(report)}\n\n`;

  md += `## Auth And Business Logic Scope\n\n`;
  md += `${renderAuthScope(report)}\n\n`;

  for (const severity of sections) {
    const findings = report.findings.filter((finding) => finding.severity === severity);
    md += `## ${capitalize(severity)} Severity Findings\n\n`;
    if (!findings.length) {
      md += `No ${severity} findings recorded.\n\n`;
      continue;
    }
    findings.forEach((finding, index) => {
      md += renderProfessionalFinding(finding, index + 1, report);
    });
  }

  md += `## Reviewed Surfaces\n\n`;
  md += renderReviewedSurfaces(report);

  md += `## Coverage Matrix\n\n`;
  md += renderCoverageMatrix(report);

  md += `## Checks Run\n\n`;
  for (const check of unique(report.checks)) {
    md += `- ${check}\n`;
  }
  md += `\n## Tool Execution\n\n`;
  if (report.tools?.length) {
    for (const tool of report.tools) {
      md += `- ${tool.name}: ${tool.status}${tool.exitCode !== undefined ? ` (exit ${tool.exitCode})` : ""}\n`;
    }
  } else {
    md += `- No external tools recorded.\n`;
  }
  md += `\n## Skipped Checks And Residual Risk\n\n`;
  if (report.skipped.length) {
    for (const skipped of unique(report.skipped)) {
      md += `- ${skipped}\n`;
    }
  } else {
    md += `- None recorded.\n`;
  }
  md += `\n`;
  return md;
}

function reportTargetName(report) {
  if (report.inventory?.origin) {
    try {
      return new URL(report.inventory.origin).hostname;
    } catch {
      return report.inventory.origin;
    }
  }
  if (isUrl(report.target)) {
    try {
      return new URL(report.target).hostname;
    } catch {
      return report.target;
    }
  }
  return path.basename(report.inventory?.root || report.target || "Target");
}

function renderAssessmentConclusion(report, counts, statusCounts) {
  const total = report.findings.length;
  const highest = ["critical", "high", "medium", "low", "info"].find((severity) => counts[severity]) || "none";
  const lines = [];
  lines.push(`Security Audit Pro completed a ${report.mode} audit using the ${report.profile || "balanced"} profile.`);
  lines.push(`The analysis found ${total} finding(s). Highest observed severity: ${highest === "none" ? "none" : capitalize(highest)}.`);
  lines.push(`Evidence handling: ${statusCounts.Confirmed || 0} confirmed observation(s), ${statusCounts.Likely || 0} likely issue(s), and ${statusCounts["Needs validation"] || 0} item(s) requiring validation.`);
  lines.push("Findings marked Needs validation should be verified with source code, authenticated test accounts, server logs, or controlled staging tests before they are treated as exploitable.");
  return lines.join("\n\n");
}

function renderKeyRiskSummary(report) {
  const important = report.findings
    .filter((finding) => severityRank[finding.severity] >= severityRank.medium)
    .slice(0, 8);
  if (!important.length) {
    return "No critical, high, or medium findings were recorded by the checks that ran.";
  }
  return important.map((finding) => {
    const location = finding.location ? ` at \`${finding.location}\`` : "";
    return `- ${capitalize(finding.severity)}: ${finding.title}${location} (${findingStatus(finding)}).`;
  }).join("\n");
}

function renderConfirmedVulnerabilitiesAndRisks(report) {
  const items = confirmedRiskItems(report);
  if (!items.length) {
    return "No confirmed vulnerabilities or concrete risk observations were recorded by the checks that ran.";
  }
  return items.map((item) => {
    let md = `### ${item.title}\n\n`;
    md += `- Confirmed: ${item.confirmed}\n`;
    md += `- Risk: ${item.risk}\n`;
    md += `- Impact: ${item.impact}\n`;
    md += `- F12 check: ${item.f12}\n`;
    if (item.remediation) md += `- Fix: ${item.remediation}\n`;
    return md;
  }).join("\n");
}

function confirmedRiskItems(report) {
  const byId = new Map(report.findings.map((finding) => [finding.id, finding]));
  const target = report.target || "";
  const items = [];

  if (byId.has("http-without-https-redirect")) {
    const finding = byId.get("http-without-https-redirect");
    items.push({
      id: finding.id,
      title: "HTTP works without HTTPS redirect",
      confirmed: `${finding.location} returns content without a HTTPS redirect (${finding.evidence}).`,
      risk: "First-visit users can be downgraded on unsafe Wi-Fi or proxy networks before HTTPS protection is established.",
      impact: "A network attacker could tamper with the first HTTP response, including JavaScript bootstrapping, which is especially sensitive for identity and payment workflows.",
      f12: `Open ${finding.location}, then DevTools -> Network -> first document -> verify status is 200 and no Location: https://... redirect is present.`,
      remediation: "Redirect HTTP to HTTPS with 301 or 308 before serving any page or asset."
    });
  }

  if (byId.has("weak-csp")) {
    const finding = byId.get("weak-csp");
    items.push({
      id: finding.id,
      title: "Weak CSP on SPA",
      confirmed: `CSP is ${finding.evidence}`,
      risk: "If any HTML or script injection exists, this CSP gives weak containment because it allows unsafe inline JavaScript, eval, data/blob sources, and broad HTTPS loading.",
      impact: "XSS would be more damaging because the page collects sensitive identity and workflow fields.",
      f12: "Run `fetch(location.href).then(r => console.log(r.headers.get('content-security-policy')))` in the Console or inspect Network -> document -> Headers.",
      remediation: "Remove unsafe-inline and unsafe-eval where possible, use nonces/hashes, and define script-src, style-src, object-src, base-uri, frame-ancestors, connect-src, img-src, and font-src."
    });
  }

  if (byId.has("conflicting-duplicate-security-headers")) {
    const finding = byId.get("conflicting-duplicate-security-headers");
    items.push({
      id: finding.id,
      title: "Conflicting duplicate security headers",
      confirmed: `${finding.location} emits duplicate/conflicting browser security headers (${finding.evidence}).`,
      risk: "Proxy and backend layers are inconsistent, which can make browser behavior harder to reason about and can accidentally weaken future deployments.",
      impact: "Header drift may reduce CSP/frame protection on sensitive API or SPA responses.",
      f12: `Open DevTools -> Network -> ${finding.location.replace(/^https?:\/\/[^/]+/, "")} -> Headers -> look for repeated Content-Security-Policy and X-Frame-Options entries.`,
      remediation: "Emit one canonical CSP and one frame policy from a single layer, or make every layer emit exactly the same policy."
    });
  }

  if (byId.has("xsrf-cookie-hardening-gap")) {
    const finding = byId.get("xsrf-cookie-hardening-gap");
    items.push({
      id: finding.id,
      title: "XSRF cookie weakness",
      confirmed: finding.evidence,
      risk: "Downgrade and CSRF-hardening controls are weaker than expected. The API should also be verified to require X-XSRF-TOKEN on state-changing requests.",
      impact: "If another weakness is present, weaker XSRF cookie attributes can make request-forgery or downgrade chains easier.",
      f12: "Application -> Cookies -> check XSRF-TOKEN attributes; Network -> API requests -> Request Headers -> verify X-XSRF-TOKEN appears on state-changing requests.",
      remediation: "Set SameSite, avoid setting security cookies over HTTP, and enforce XSRF token validation server-side."
    });
  }

  if (byId.has("production-debug-logging-js")) {
    const finding = byId.get("production-debug-logging-js");
    items.push({
      id: finding.id,
      title: "Production debug logging in JS",
      confirmed: finding.evidence,
      risk: "Sensitive application or payment workflow data may appear in browser consoles, screenshots, support recordings, or telemetry.",
      impact: "Operational support or user screenshots could expose candidate/payment state that should not be logged client-side.",
      f12: "During an authorized test flow, open Console and watch for payment/application logs; in Sources search for `console.log(\"Payment payload\"` and related payment labels.",
      remediation: "Remove production console logging around candidate, application, and payment flows."
    });
  }

  if (byId.has("sensitive-endpoint-map-public-js")) {
    const finding = byId.get("sensitive-endpoint-map-public-js");
    items.push({
      id: finding.id,
      title: "Sensitive endpoint map exposed in public JS",
      confirmed: finding.evidence,
      risk: "This is not a vulnerability by itself, but it gives attackers the exact API map for IDOR, payment, download, and authorization testing.",
      impact: "Server-side authorization must be strict on every exposed endpoint because endpoint names are public.",
      f12: "Sources -> global search for `candidate/full-profile`, `download-url`, and `payment/reconcile`.",
      remediation: "Treat all frontend-discovered routes as public knowledge and enforce object ownership, authorization, and rate limits server-side."
    });
  }

  if (byId.has("client-side-password-transform")) {
    const finding = byId.get("client-side-password-transform");
    items.push({
      id: finding.id,
      title: "Client-side password transform is not real protection",
      confirmed: finding.evidence,
      risk: "The transform is only defense-in-depth. If HTTP injection or XSS occurs, a password can be captured before the transform runs.",
      impact: "Authentication safety still depends on HTTPS, CSP, server validation, and secure session handling.",
      f12: "Sources -> search for `AES-GCM`, `SHA-256`, and `123456789`.",
      remediation: "Do not rely on client-side encryption/obfuscation as a security boundary; protect the browser runtime and server authentication flow."
    });
  }

  if (byId.has("spa-browser-token-storage")) {
    const finding = byId.get("spa-browser-token-storage");
    items.push({
      id: finding.id,
      title: "Browser-readable token storage in SPA",
      confirmed: finding.evidence,
      risk: "If session-bearing tokens are stored in localStorage or sessionStorage, any XSS in the page can read and exfiltrate them.",
      impact: "A client-side injection bug could become account takeover rather than only page manipulation.",
      f12: "Sources -> global search for `localStorage`, `sessionStorage`, `accessToken`, `refreshToken`, and `jwt`; Application -> Storage should be checked only in an authorized test session without copying token values.",
      remediation: "Prefer HttpOnly Secure SameSite cookies where practical, shorten token lifetime, and harden CSP/XSS controls."
    });
  }

  if (byId.has("spa-secret-like-public-config")) {
    const finding = byId.get("spa-secret-like-public-config");
    items.push({
      id: finding.id,
      title: "Secret-like config in public JavaScript",
      confirmed: finding.evidence,
      risk: "Anything shipped in a public JavaScript bundle must be treated as public. Secret-like config names may indicate leaked credentials or unrestricted keys.",
      impact: "Real secrets must be rotated. Public keys can be abused outside the intended frontend if domain, quota, and API restrictions are missing.",
      f12: "Sources -> global search for the config names listed in the evidence. Do not copy or share full values.",
      remediation: "Move privileged secrets server-side, restrict public keys, and rotate any credential that was exposed."
    });
  }

  if (byId.has("spa-graphql-introspection-signal")) {
    const finding = byId.get("spa-graphql-introspection-signal");
    items.push({
      id: finding.id,
      title: "GraphQL introspection/schema signal in public frontend",
      confirmed: finding.evidence,
      risk: "GraphQL schema visibility can give attackers a map of object types, fields, mutations, and authorization boundaries.",
      impact: "This is most risky when combined with weak object authorization, excessive fields, or unauthenticated schema access.",
      f12: "Sources -> global search for `__schema`, `__type`, `IntrospectionQuery`, and `GraphiQL`; Network -> check whether GraphQL schema access requires authorization.",
      remediation: "Disable or authenticate production introspection/schema tooling unless intentionally public, and enforce authorization per field/object."
    });
  }

  if (byId.has("hardcoded-identity-mobile-placeholder")) {
    const finding = byId.get("hardcoded-identity-mobile-placeholder");
    items.push({
      id: finding.id,
      title: "Hardcoded mobile placeholder in identity login flow",
      confirmed: finding.evidence,
      risk: "A fixed mobile value in an identity-verification path can corrupt audit/contact data or become dangerous if the backend treats it as a verified user attribute.",
      impact: "Impact depends on backend use. It is a confirmed client-side defect and must be validated against server storage, OTP, audit, and authorization behavior.",
      f12: "Sources -> global search for `DIGILOCKER_PLACEHOLDER_MOBILE`, `mobileNo`, and `9000000000`; Network -> authorized test login -> inspect whether the value is sent.",
      remediation: "Remove the fixed placeholder and derive identity/contact attributes server-side from a verified assertion, or omit the field entirely."
    });
  }

  if (byId.has("payment-return-url-host-mismatch")) {
    const finding = byId.get("payment-return-url-host-mismatch");
    items.push({
      id: finding.id,
      title: "Payment return URL host mismatch",
      confirmed: finding.evidence,
      risk: "Payment return/callback host drift can send users or payment status handling to the wrong portal host if the backend trusts stale or client-supplied return URLs.",
      impact: "This can cause payment reconciliation failures or payment-flow confusion. Exploitability depends on backend order creation and callback validation.",
      f12: "Sources -> global search for `sbiReturnUrl` and `returnUrl`; Network -> authorized test payment initiation -> inspect the order payload return URL.",
      remediation: "Align return URLs with the active host and enforce server-side allowlists for every payment return/callback target."
    });
  }

  if (byId.has("security-txt-unavailable")) {
    const finding = byId.get("security-txt-unavailable");
    items.push({
      id: finding.id,
      title: "No useful security.txt; standard file falls back or is unavailable",
      confirmed: finding.evidence,
      risk: "Low risk. It makes responsible disclosure and scanner classification harder.",
      impact: "Researchers may have difficulty finding the correct security contact and policy.",
      f12: `Open ${finding.location} and verify whether it returns valid security.txt content or the SPA HTML page.`,
      remediation: "Publish valid RFC 9116 security.txt at /.well-known/security.txt."
    });
  }

  return items.filter((item) => item.confirmed && (target || item));
}

function renderScopeAndAuthorization(report) {
  return [
    `- Target: \`${report.target}\``,
    `- Mode/profile: ${report.mode} / ${report.profile || "balanced"}`,
    `- Authorization flag: ${report.authorized ? "provided" : "not provided"}`,
    "- Testing boundary: non-destructive defensive checks only; findings are reported with evidence and validation status.",
    "- Report standard: confirmed observations are separated from likely issues and needs-validation items to avoid overstating exploitability."
  ].join("\n");
}

function renderProfessionalFinding(finding, index, report) {
  const status = findingStatus(finding);
  const poc = safePocForFinding(finding, report);
  let md = `### ${index}. ${finding.title}\n\n`;
  md += `- Status: ${status}\n`;
  md += `- Severity: ${capitalize(finding.severity)}\n`;
  md += `- Category: ${finding.category}\n`;
  md += `- Finding: ${finding.title}\n`;
  if (finding.location) md += `- Affected surface: \`${finding.location}\`\n`;
  if (finding.evidence) md += `- Evidence: \`${finding.evidence}\`\n`;
  md += `- Risk: ${findingRisk(finding)}\n`;
  md += `- Impact: ${findingImpact(finding)}\n`;
  if (finding.owasp) md += `- OWASP mapping: ${finding.owasp}\n`;
  if (finding.cwe) md += `- CWE: ${finding.cwe}\n`;
  md += `- Confidence: ${finding.confidence}\n`;
  md += `- Remediation: ${finding.remediation}\n`;
  if (poc) {
    md += `- Safe PoC / validation: ${poc.summary}\n`;
    for (const command of poc.commands || []) {
      md += `  - \`${inlineCode(command)}\`\n`;
    }
    if (poc.note) md += `  - Note: ${poc.note}\n`;
  }
  if (status === "Needs validation") {
    md += `- Validation needed: Confirm server-side behavior with an authenticated test account, source review, or controlled staging proof before relying on this as an exploitable vulnerability.\n`;
  }
  md += `\n`;
  return md;
}

function safePocForFinding(finding, report) {
  const target = finding.location || report.target;
  const origin = report.inventory?.origin || (isUrl(report.target) ? new URL(report.target).origin : report.target);
  const status = findingStatus(finding);
  const baseNote = "Run only against systems you own or are explicitly authorized to test.";

  if (finding.id === "http-without-https-redirect") {
    return {
      summary: "Confirm the HTTP endpoint returns content instead of redirecting to HTTPS.",
      commands: [`curl.exe -I "${target}"`],
      note: "Expected secure behavior is a 301 or 308 Location header pointing to https://."
    };
  }
  if (finding.category === "HTTP security header") {
    return {
      summary: "Confirm the missing or weak browser security header without sending payloads.",
      commands: [`curl.exe -I "${target}"`],
      note: baseNote
    };
  }
  if (finding.category === "Exposed path") {
    return {
      summary: "Confirm reachability using headers/status only; do not print or store sensitive file contents.",
      commands: [`curl.exe -I "${target}"`],
      note: `${baseNote} If this is a secret/config path, validate status and immediately remove exposure rather than downloading the body.`
    };
  }
  if (finding.category === "API security") {
    return {
      summary: "Confirm whether API/schema access is public and whether authorization is required.",
      commands: [`curl.exe -I "${target}"`, `curl.exe -sS "${target}" --max-time 10`],
      note: "Inspect schema contents for internal-only endpoints, object identifiers, auth assumptions, and role-protected operations."
    };
  }
  if (finding.category === "Payment workflow") {
    return {
      summary: "Validate with one authorized non-production or low-risk payment test and inspect server-side order creation.",
      commands: [],
      note: "Do not perform live payment abuse. Confirm the backend allowlists the return host and ignores stale or client-controlled return URL values."
    };
  }
  if (finding.category === "Authorization review hotspot") {
    return {
      summary: "Validate with two controlled test users or tenants and verify object ownership enforcement.",
      commands: [],
      note: "Do not enumerate real user IDs. Use staging fixtures or written-authorized test records and confirm unauthorized object IDs are rejected server-side."
    };
  }
  if (finding.category === "Token/session security") {
    return {
      summary: "Validate token/session handling with source review and controlled test tokens.",
      commands: [],
      note: "Check whether claims are trusted before verification, whether expiry is enforced, and whether weak keys require token rotation. Do not use real user tokens in shared reports."
    };
  }
  if (finding.category === "Client-side token storage") {
    return {
      summary: "Confirm whether session-bearing tokens are readable by browser JavaScript.",
      commands: target && isUrl(target) ? [`curl.exe -sS "${target}" --max-time 10`] : [],
      note: "For local source, inspect the referenced line. For websites, use DevTools only in an authorized test session and avoid copying token values."
    };
  }
  if (finding.category === "Client-side exposure") {
    return {
      summary: "Confirm whether the named public config value is intentionally public and properly restricted.",
      commands: target && isUrl(target) ? [`curl.exe -sS "${target}" --max-time 10`] : [],
      note: "Do not print full values. Rotate any credential that shipped in public JavaScript or public frontend environment variables."
    };
  }
  if (finding.category === "CI/CD security") {
    return {
      summary: "Review the workflow trigger, token permissions, and checked-out code trust boundary.",
      commands: ["git grep -n \"pull_request_target\\|permissions:\\|uses:\" -- .github/workflows"],
      note: "Validate in repository settings and workflow history before changing production CI behavior."
    };
  }
  if (finding.category === "CORS") {
    return {
      summary: "Verify dynamic CORS behavior with a harmless synthetic Origin.",
      commands: [`curl.exe -i -H "Origin: https://security-audit-pro.invalid" "${target}"`],
      note: baseNote
    };
  }
  if (finding.category === "HTTP method exposure") {
    return {
      summary: "Verify advertised and enabled HTTP methods.",
      commands: [`curl.exe -i -X OPTIONS "${origin}"`, `curl.exe -i -X TRACE "${origin}"`],
      note: "TRACE validation is safe but should still be run only when active testing is authorized."
    };
  }
  if (finding.category === "Transport security") {
    const hostPort = hostPortFromTarget(target || report.target);
    return {
      summary: "Re-run a non-destructive TLS posture check.",
      commands: [`sslyze --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 --sslv3 --heartbleed --robot --openssl_ccs --compression --reneg ${hostPort}`],
      note: baseNote
    };
  }
  if (finding.category === "Session security") {
    return {
      summary: "Confirm cookie attributes from response headers.",
      commands: [`curl.exe -I "${target}"`],
      note: "Review Set-Cookie for Secure, HttpOnly, SameSite, Path, Domain, and expiry behavior."
    };
  }
  if (finding.category === "Dependency vulnerability") {
    return {
      summary: "Re-run the relevant dependency scanner and confirm reachability before prioritizing.",
      commands: ["npm audit --json", "osv-scanner scan source -r --format json ."],
      note: "Use the command that matches the project ecosystem and lockfile."
    };
  }
  if (finding.category === "Secret exposure") {
    return {
      summary: "Validate with redacted secret scanning only.",
      commands: ["gitleaks dir . --redact --no-banner", "trufflehog filesystem --json --no-update ."],
      note: "Never print full secret values in shared reports; rotate confirmed credentials."
    };
  }
  if (finding.category === "SAST" || finding.category === "DAST" || status === "Needs validation") {
    if (finding.id === "identity-binding-needs-validation") {
      return {
        summary: "Validate with controlled test identities only; public client code cannot prove server-side identity binding.",
        commands: [],
        note: "Use staging or written-authorized test records. Submit a valid-but-unrelated identity for one candidate and verify the backend rejects it without exposing candidate data."
      };
    }
    return {
      summary: "Validate exploitability with source review, logs, and a harmless staging proof.",
      commands: [],
      note: "Do not escalate to destructive payloads; prove authorization, reachability, and impact safely."
    };
  }
  return {
    summary: "Reproduce the observed behavior with the same non-destructive request used by the scanner.",
    commands: target && isUrl(target) ? [`curl.exe -I "${target}"`] : [],
    note: baseNote
  };
}

function hostPortFromTarget(value) {
  try {
    const url = new URL(value);
    return `${url.hostname}:${url.port || (url.protocol === "https:" ? "443" : "80")}`;
  } catch {
    return String(value || "").replace(/^https?:\/\//i, "").replace(/\/.*$/, "") || "host:443";
  }
}

function inlineCode(value) {
  return String(value || "").replace(/`/g, "'");
}

function findingStatus(finding) {
  if (finding.confidence === "low") return "Needs validation";
  if (finding.confidence === "high") return "Confirmed";
  const confirmedCategories = new Set([
    "HTTP security header",
    "Transport security",
    "Session security",
    "CORS",
    "HTTP method exposure",
    "Exposed path",
    "Information disclosure",
    "Dependency vulnerability",
    "Secret exposure",
    "Client-side exposure",
    "Client-side token storage"
  ]);
  if (confirmedCategories.has(finding.category)) return "Confirmed";
  if (finding.category === "API security") return "Likely";
  if (finding.category === "Authorization review hotspot") return "Needs validation";
  if (finding.category === "Token/session security") return finding.confidence === "high" ? "Confirmed" : "Needs validation";
  if (finding.category === "CI/CD security") return finding.confidence === "high" ? "Confirmed" : "Needs validation";
  if (finding.category === "SAST" || finding.category === "DAST") return "Needs validation";
  return "Likely";
}

function findingRisk(finding) {
  const bySeverity = {
    critical: "A capable attacker may be able to compromise sensitive data, credentials, accounts, or core application integrity.",
    high: "A capable attacker may be able to gain unauthorized access, escalate privileges, extract sensitive data, or materially weaken protections.",
    medium: "This weakness can increase attack success or expose useful information when chained with other issues.",
    low: "This is a hardening gap or limited information disclosure that can support reconnaissance or defense bypass chains.",
    info: "This is informational context that helps assess exposure, stack, or residual testing risk."
  };
  if (finding.category === "API security") {
    return "Reachable API/schema surfaces can reveal internal object models, auth expectations, and endpoints that need authorization and abuse-case testing.";
  }
  if (finding.category === "Exposed path") {
    return "A reachable sensitive path can disclose configuration, diagnostics, admin surfaces, or deployment artifacts.";
  }
  if (finding.category === "Secret exposure") {
    return "Exposed credentials can allow direct access to third-party services, infrastructure, or user data.";
  }
  if (finding.category === "Transport security") {
    return "Weak transport settings can expose sessions or data to downgrade, interception, or protocol-level attacks.";
  }
  if (finding.category === "Authentication business logic") {
    return "Authentication and identity workflows can fail open if the backend validates that an identity exists but does not bind that identity to the requested user or candidate record.";
  }
  if (finding.category === "Payment workflow") {
    return "Payment workflow configuration drift can break status reconciliation or redirect users through the wrong host when payment return targets are stale or trusted from client-controlled data.";
  }
  if (finding.category === "Authorization review hotspot") {
    return "Object lookup and request-body assignment paths can become IDOR/BOLA or privilege-tampering issues when authorization is not tied to the authenticated user and tenant.";
  }
  if (finding.category === "Token/session security") {
    return "JWT and session mistakes can let attackers trust forged claims, reuse expired tokens, steal browser-readable tokens, or abuse weak cookie settings.";
  }
  if (finding.category === "Client-side token storage") {
    return "Browser-readable session tokens are exposed to any successful XSS or malicious browser extension running in the page context.";
  }
  if (finding.category === "Client-side exposure") {
    return "Values shipped in frontend bundles are public. Secret-like names or unrestricted public keys can expose credentials, quota, billing, or internal service configuration.";
  }
  if (finding.category === "CI/CD security") {
    return "Workflow trust-boundary mistakes can expose privileged GitHub tokens or allow supply-chain compromise through untrusted pull request code or mutable third-party actions.";
  }
  return bySeverity[finding.severity] || bySeverity.info;
}

function findingImpact(finding) {
  if (finding.category === "HTTP security header") {
    return "Browser-side protection is weaker, increasing the impact of XSS, clickjacking, MIME confusion, referrer leakage, or permissions abuse depending on the missing header.";
  }
  if (finding.category === "CORS") {
    return "A malicious site may be able to read or interact with protected responses if credentialed CORS is also allowed or introduced later.";
  }
  if (finding.category === "Session security") {
    return "Session theft or cross-site request scenarios may become easier if cookies are readable, sent cross-site unexpectedly, or allowed over insecure transport.";
  }
  if (finding.category === "Exposed path") {
    return "Attackers can use the exposed endpoint or file for reconnaissance, data exposure, or follow-on attacks.";
  }
  if (finding.category === "API security") {
    return "The exposed API surface gives attackers a map for object authorization, rate-limit, validation, and workflow abuse testing.";
  }
  if (finding.id === "identity-binding-needs-validation") {
    return "If server-side binding is missing, a valid but unrelated identity could authenticate to the wrong candidate record. This remains unconfirmed until controlled server-side validation succeeds.";
  }
  if (finding.id === "hardcoded-identity-mobile-placeholder") {
    return "A fixed mobile attribute can weaken auditability, corrupt contact data, or support account-recovery/OTP mistakes if trusted by the backend.";
  }
  if (finding.id === "payment-return-url-host-mismatch") {
    return "Users or payment status updates may return to a stale host, causing failed reconciliation or confusing payment-state transitions unless server-side validation corrects it.";
  }
  if (finding.category === "Authorization review hotspot") {
    return "If the hotspot is reachable without proper ownership checks, users may access or modify records, files, payments, or account state belonging to another user or tenant.";
  }
  if (finding.category === "Token/session security") {
    return "Impact ranges from account takeover to long-lived unauthorized access depending on whether token verification, expiry, cookie security, and key management are affected.";
  }
  if (finding.category === "Client-side token storage") {
    return "A single XSS issue could become account takeover if access or refresh tokens are readable by JavaScript.";
  }
  if (finding.category === "Client-side exposure") {
    return "Real secrets must be rotated. Public keys should be restricted because attackers can reuse them outside the intended frontend if controls are missing.";
  }
  if (finding.category === "CI/CD security") {
    return "An attacker who influences workflow execution may alter releases, exfiltrate CI secrets, or push unauthorized changes depending on token permissions.";
  }
  if (finding.category === "Dependency vulnerability") {
    return "Impact depends on reachability, but vulnerable components can enable known exploit paths if affected code is loaded or exposed.";
  }
  if (finding.category === "Transport security") {
    return "Sensitive traffic can be exposed to interception, downgrade risk, or weaker transport guarantees depending on the protocol and deployment path.";
  }
  if (finding.category === "SAST") {
    return "Impact depends on data flow and exploitability; source-level validation is required.";
  }
  if (finding.category === "DAST") {
    return "The scanner observed behavior matching a vulnerability pattern; manual validation should confirm exploitability and false-positive risk.";
  }
  return "Impact depends on where this behavior appears in the application and whether it is reachable by untrusted users.";
}

function renderThreatModelSummary(report) {
  if (report.inventory.kind === "url") {
    return [
      `- Assets: public HTTP service at \`${report.inventory.origin || report.target}\`.`,
      "- Trust boundaries: internet client to edge/application server; browser security boundary for cookies, CORS, CSP, redirects, and mixed content.",
      "- Attacker-controlled inputs: request path, headers, query parameters, body parameters, cookies, and browser-origin context.",
      "- Security invariants: HTTPS must protect sensitive traffic; browser-enforced controls should limit script, framing, referrer, and cross-origin abuse; debug and sensitive files must not be public.",
      "- Limits: passive URL checks cannot prove authenticated authorization, business logic, or deep crawler behavior."
    ].join("\n");
  }

  const stacks = report.inventory.stacks?.join(", ") || "unknown stack";
  const frameworks = report.inventory.frameworks?.join(", ") || "none detected";
  return [
    `- Assets: local project source, configuration, dependencies, secrets, route handlers, and API definitions for \`${report.inventory.root || report.target}\`.`,
    `- Runtime context: ${stacks}; frameworks detected: ${frameworks}.`,
    "- Trust boundaries: external users to routes/APIs, stored data to render/parse/evaluate paths, server to filesystem/process/network/database/cloud services, and CI/deployment to production artifacts.",
    "- Attacker-controlled inputs: HTTP parameters, uploaded files, archive members, URLs/callbacks, serialized/parser inputs, auth tokens, tenant/object identifiers, and stored metadata.",
    "- Security invariants: authentication and object authorization must gate protected actions; untrusted input must not control code, query syntax, filesystem paths, network destinations, parser behavior, or secrets."
  ].join("\n");
}

function renderAuthScope(report) {
  const scope = report.inventory.authScope;
  if (!scope) {
    return [
      "- No authenticated/business-logic scope file was supplied.",
      "- Deep role, IDOR/BOLA, workflow abuse, payment, upload, and user-to-user authorization checks remain untested until dedicated test accounts and workflows are provided.",
      "- Use `--scope-file C:\\Users\\soura\\plugins\\security-audit-pro\\templates\\authenticated-audit-scope.md` after filling it with test-scope details."
    ].join("\n");
  }
  const lines = [];
  lines.push(`- Scope file: \`${report.inventory.scopeFile}\``);
  if (scope.primaryUrl) lines.push(`- Primary URL: \`${scope.primaryUrl}\``);
  lines.push(`- Roles listed: ${scope.roles?.length ? scope.roles.join(", ") : "none listed"}`);
  lines.push(`- Workflows listed: ${scope.workflows?.length ? scope.workflows.join(", ") : "none listed"}`);
  if (scope.maxRate) lines.push(`- Max rate/concurrency: ${scope.maxRate}`);
  if (scope.testWindow) lines.push(`- Test window: ${scope.testWindow}`);
  if (scope.outOfScope) lines.push(`- Out of scope: ${scope.outOfScope}`);
  lines.push("- Next manual/auth checks: compare role access, direct object references, state-changing actions, CSRF/session behavior, upload restrictions, and business workflow abuse with dedicated test accounts.");
  return lines.join("\n");
}

function renderReviewedSurfaces(report) {
  if (!report.reviewedSurfaces?.length) {
    return "No reviewed surfaces were recorded.\n\n";
  }
  let md = "| Surface | Risk Area | Outcome | Notes |\n|---|---|---|---|\n";
  for (const surface of report.reviewedSurfaces) {
    md += `| ${escapeTable(surface.surface)} | ${escapeTable(surface.riskArea)} | ${escapeTable(surface.outcome)} | ${escapeTable(surface.notes)} |\n`;
  }
  return `${md}\n`;
}

function renderCoverageMatrix(report) {
  if (!report.coverage?.length) {
    return "No coverage records were recorded.\n\n";
  }
  let md = "| Area | Method | Status | Notes |\n|---|---|---|---|\n";
  for (const item of uniqueCoverage(report.coverage)) {
    md += `| ${escapeTable(item.area)} | ${escapeTable(item.method)} | ${escapeTable(item.status)} | ${escapeTable(item.notes)} |\n`;
  }
  return `${md}\n`;
}

function renderHtmlLegacy(report, markdown) {
  const title = `Security Audit Pro - ${report.target}`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root { color-scheme: light dark; --bg: #f8fafc; --fg: #0f172a; --muted: #475569; --panel: #ffffff; --line: #cbd5e1; --accent: #0f766e; }
    @media (prefers-color-scheme: dark) { :root { --bg: #0b1220; --fg: #e5e7eb; --muted: #94a3b8; --panel: #111827; --line: #334155; --accent: #2dd4bf; } }
    body { margin: 0; font: 15px/1.55 system-ui, -apple-system, Segoe UI, sans-serif; background: var(--bg); color: var(--fg); }
    main { max-width: 1120px; margin: 0 auto; padding: 32px 20px 56px; }
    header { border-bottom: 1px solid var(--line); margin-bottom: 24px; padding-bottom: 16px; }
    h1 { margin: 0 0 8px; font-size: 28px; }
    .meta { color: var(--muted); }
    .counts { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin: 20px 0; }
    .count { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
    .count strong { display: block; font-size: 22px; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 18px; }
  </style>
</head>
<body>
<main>
  <header>
    <h1>${escapeHtml(title)}</h1>
    <div class="meta">Generated ${escapeHtml(report.startedAt)} · mode ${escapeHtml(report.mode)}</div>
  </header>
  <section class="counts">
    ${["critical", "high", "medium", "low", "info"].map((severity) => `<div class="count"><span>${severity}</span><strong>${report.findings.filter((finding) => finding.severity === severity).length}</strong></div>`).join("")}
  </section>
  <pre>${escapeHtml(markdown)}</pre>
</main>
</body>
</html>
`;
}

function renderHtml(report, markdown) {
  const title = `AI Security Audit Pro Report - ${reportTargetName(report)}`;
  const counts = severityCounts(report);
  const statuses = validationStatusCounts(report);
  const sections = ["critical", "high", "medium", "low", "info"];
  const total = report.findings.length;
  const riskLabel = overallRiskLabel(counts);
  const riskClass = overallRiskClass(counts);
  const targetName = reportTargetName(report);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      color-scheme: light;
      --paper: #ffffff;
      --ink: #111827;
      --muted: #607089;
      --line: #dce6f1;
      --soft: #f4f8fb;
      --mint: #10a996;
      --mint-soft: #e8fbf7;
      --blue: #4f8df7;
      --lavender: #7c5cff;
      --critical: #e94755;
      --high: #fb7c2d;
      --medium: #f4b91f;
      --low: #5b93ee;
      --info: #20b7b2;
      --shadow: 0 14px 38px rgba(31, 59, 88, 0.10);
    }
    * { box-sizing: border-box; }
    html { background: #edf5f8; }
    body { margin: 0; color: var(--ink); font: 13px/1.55 Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background: linear-gradient(180deg, #f8fcff 0%, #eef7f8 100%); }
    main.report { max-width: 1120px; margin: 0 auto; padding: 28px 18px 48px; }
    h1, h2, h3 { letter-spacing: 0; line-height: 1.16; }
    h1 { margin: 0; font-size: clamp(30px, 4vw, 46px); }
    h2 { margin: 0 0 14px; font-size: 18px; }
    h3 { margin: 0; font-size: 14px; }
    p { margin: 0 0 10px; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Consolas, Liberation Mono, monospace; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #f7fafc; border: 1px solid var(--line); border-radius: 8px; padding: 12px; margin: 8px 0 0; }
    table { width: 100%; border-collapse: separate; border-spacing: 0; background: var(--paper); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
    th, td { border-bottom: 1px solid var(--line); padding: 9px 10px; text-align: left; vertical-align: top; }
    th { background: #f3f8fb; font-size: 11px; text-transform: uppercase; color: #496079; letter-spacing: 0.02em; }
    tr:last-child td { border-bottom: 0; }
    .cover, .page { background: rgba(255, 255, 255, 0.94); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); }
    .cover { padding: 26px; margin-bottom: 18px; overflow: hidden; position: relative; }
    .cover::after { content: ""; position: absolute; inset: auto -40px -70px auto; width: 220px; height: 220px; background: radial-gradient(circle, rgba(16,169,150,0.18), transparent 65%); pointer-events: none; }
    .brand-row { display: flex; justify-content: space-between; gap: 18px; align-items: flex-start; margin-bottom: 24px; position: relative; z-index: 1; }
    .brand { display: flex; gap: 12px; align-items: center; min-width: 220px; }
    .logo { width: 44px; height: 44px; border-radius: 8px; display: grid; place-items: center; color: #ffffff; background: linear-gradient(135deg, #11b7a4, #1778d7); box-shadow: 0 10px 22px rgba(16,169,150,0.22); }
    .logo svg { width: 26px; height: 26px; }
    .brand strong { display: block; font-size: 18px; }
    .brand span { color: var(--muted); }
    .assessment { min-width: 210px; border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; background: #fff; }
    .assessment small { display: block; color: var(--muted); }
    .assessment strong { display: block; margin-top: 4px; font-size: 24px; }
    .risk-critical strong, .risk-high strong { color: var(--critical); }
    .risk-medium strong { color: var(--high); }
    .risk-low strong { color: var(--low); }
    .risk-info strong, .risk-clean strong { color: var(--mint); }
    .cover-grid { display: grid; grid-template-columns: 1.45fr minmax(240px, 0.8fr); gap: 22px; align-items: end; position: relative; z-index: 1; }
    .target { margin-top: 10px; color: var(--muted); font-size: 16px; }
    .target strong { color: var(--mint); }
    .meta-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .meta-card { border: 1px solid var(--line); background: #fbfdff; border-radius: 8px; padding: 10px 12px; }
    .meta-card span { display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; }
    .meta-card strong { display: block; margin-top: 2px; }
    .page { padding: 20px; margin: 18px 0; }
    .section { margin: 18px 0; }
    .section-title { display: flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 14px; }
    .section-title span { color: var(--muted); font-size: 12px; }
    .grid { display: grid; gap: 14px; }
    .grid.two { grid-template-columns: minmax(0, 1fr) minmax(280px, 0.8fr); }
    .grid.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .severity-grid { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; }
    .stat { border: 1px solid var(--line); border-radius: 8px; padding: 12px; background: linear-gradient(180deg, #fff, #f9fcfd); min-height: 112px; }
    .stat .label { display: flex; align-items: center; justify-content: space-between; gap: 8px; color: #31445a; font-weight: 700; }
    .dot { width: 10px; height: 10px; border-radius: 99px; display: inline-block; background: var(--info); }
    .stat strong { display: block; margin-top: 10px; font-size: 30px; line-height: 1; }
    .stat small { color: var(--muted); }
    .bar { height: 6px; margin-top: 14px; border-radius: 999px; background: #e7eef6; overflow: hidden; }
    .bar i { display: block; height: 100%; width: var(--pct); border-radius: inherit; background: var(--color); }
    .critical { --color: var(--critical); }
    .high { --color: var(--high); }
    .medium { --color: var(--medium); }
    .low { --color: var(--low); }
    .info { --color: var(--info); }
    .panel { border: 1px solid var(--line); border-radius: 8px; background: #fff; padding: 16px; }
    .conclusion { background: linear-gradient(135deg, #f2fffc, #ffffff 58%, #f7fbff); }
    .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
    .chip, .badge { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--line); border-radius: 999px; padding: 5px 9px; background: #fff; font-size: 11px; font-weight: 700; }
    .chip.confirmed { color: #087f73; background: #e8fbf7; border-color: #bcebe1; }
    .chip.likely { color: #a35400; background: #fff5dc; border-color: #f5df9f; }
    .chip.validation { color: #5b35c8; background: #f0ebff; border-color: #d7ccff; }
    .badge.critical { color: #b91c1c; background: #fff1f2; border-color: #fecdd3; }
    .badge.high { color: #9a4b0d; background: #fff7ed; border-color: #fed7aa; }
    .badge.medium { color: #8a5b00; background: #fff8db; border-color: #fde68a; }
    .badge.low { color: #1d4ed8; background: #eff6ff; border-color: #bfdbfe; }
    .badge.info { color: #0f766e; background: #effdfa; border-color: #99f6e4; }
    .donut-wrap { display: grid; grid-template-columns: 150px 1fr; gap: 16px; align-items: center; }
    .donut { width: 148px; height: 148px; border-radius: 50%; background: conic-gradient(var(--critical) 0 var(--criticalEnd), var(--high) var(--criticalEnd) var(--highEnd), var(--medium) var(--highEnd) var(--mediumEnd), var(--low) var(--mediumEnd) var(--lowEnd), var(--info) var(--lowEnd) 100%); position: relative; box-shadow: inset 0 0 0 1px rgba(255,255,255,0.85); }
    .donut::after { content: "${escapeHtml(String(total))}\\A Total"; white-space: pre; position: absolute; inset: 28px; border-radius: 50%; background: #fff; display: grid; place-items: center; text-align: center; font-weight: 800; font-size: 28px; color: var(--ink); line-height: 1.05; box-shadow: inset 0 0 0 1px var(--line); }
    .legend { display: grid; gap: 8px; }
    .legend-row { display: grid; grid-template-columns: 12px 1fr auto; gap: 8px; align-items: center; color: #30445d; }
    .findings-table td:first-child { font-weight: 700; }
    .finding { border: 1px solid var(--line); border-left: 5px solid var(--color, var(--line)); border-radius: 8px; padding: 14px; margin: 12px 0; background: #fff; page-break-inside: avoid; }
    .finding-head { display: flex; gap: 10px; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; margin-bottom: 10px; }
    .finding-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
    .field { border-top: 1px solid var(--line); padding-top: 9px; }
    .field strong { display: block; margin-bottom: 3px; color: #33465c; }
    .evidence { word-break: break-word; }
    .safe-list { display: grid; gap: 9px; }
    .safe-step { display: grid; grid-template-columns: 26px 1fr auto; gap: 10px; align-items: start; border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: #fbfefd; }
    .safe-step b { width: 24px; height: 24px; border-radius: 50%; display: grid; place-items: center; background: var(--mint-soft); color: #087f73; }
    .cute-note { display: grid; grid-template-columns: auto 1fr; gap: 14px; align-items: center; border: 1px solid #bcebe1; background: #f1fffb; border-radius: 8px; padding: 14px; color: #0d4f49; }
    .mascot { width: 64px; height: 64px; border-radius: 24px 24px 28px 28px; background: linear-gradient(135deg, #83f0dd, #d8fff7); position: relative; border: 1px solid #a8e8df; }
    .mascot::before, .mascot::after { content: ""; position: absolute; top: 24px; width: 6px; height: 8px; border-radius: 99px; background: #0a5b55; }
    .mascot::before { left: 22px; }
    .mascot::after { right: 22px; }
    .mascot i { position: absolute; left: 22px; bottom: 17px; width: 20px; height: 10px; border-bottom: 2px solid #0a5b55; border-radius: 0 0 99px 99px; }
    details { background: var(--paper); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; margin-top: 18px; }
    summary { cursor: pointer; font-weight: 800; }
    .empty { color: var(--muted); font-style: italic; }
    .muted, .meta { color: var(--muted); }
    .appendix pre { max-height: 520px; overflow: auto; }
    @media (max-width: 920px) {
      .cover-grid, .grid.two, .grid.three, .donut-wrap { grid-template-columns: 1fr; }
      .severity-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .brand-row { flex-direction: column; }
      .assessment { width: 100%; }
    }
    @media print {
      html, body { background: #fff; }
      main.report { max-width: none; padding: 0; }
      .cover, .page { box-shadow: none; border-color: #cfdbe8; break-inside: avoid; margin: 0 0 14px; }
      .page { page-break-inside: avoid; }
      details.appendix { display: none; }
      a { color: inherit; text-decoration: none; }
    }
  </style>
</head>
<body>
<main class="report">
  <section class="cover">
    <div class="brand-row">
      <div class="brand">
        <div class="logo" aria-hidden="true">${shieldSvg()}</div>
        <div><strong>AI Security Audit Pro</strong><span>Professional security report</span></div>
      </div>
      <aside class="assessment ${escapeHtml(riskClass)}">
        <small>Overall Assessment</small>
        <strong>${escapeHtml(riskLabel)}</strong>
      </aside>
    </div>
    <div class="cover-grid">
      <div>
        <h1>Security Audit Report</h1>
        <div class="target">Target: <strong>${escapeHtml(targetName)}</strong></div>
        <div class="chips">
          <span class="chip confirmed">${statuses.Confirmed || 0} Confirmed</span>
          <span class="chip likely">${statuses.Likely || 0} Likely</span>
          <span class="chip validation">${statuses["Needs validation"] || 0} Needs validation</span>
        </div>
      </div>
      <div class="meta-grid">
        <div class="meta-card"><span>Generated</span><strong>${escapeHtml(formatDateTime(report.startedAt))}</strong></div>
        <div class="meta-card"><span>Report ID</span><strong>${escapeHtml(reportId(report))}</strong></div>
        <div class="meta-card"><span>Mode</span><strong>${escapeHtml(report.mode)} / ${escapeHtml(report.profile || "balanced")}</strong></div>
        <div class="meta-card"><span>Authorization</span><strong>${report.authorized ? "provided" : "not provided"}</strong></div>
      </div>
    </div>
  </section>

  <section class="page">
    <div class="section-title"><h2>Executive Snapshot</h2><span>${total} total finding(s)</span></div>
    <div class="severity-grid">${renderSeverityCardsHtml(counts, total)}</div>
  </section>

  <section class="page">
    <div class="grid two">
      <div class="panel conclusion">
        <div class="section-title"><h2>Assessment Conclusion</h2><span>Evidence-based summary</span></div>
        ${htmlParagraphs(renderAssessmentConclusion(report, counts, statuses))}
        <div class="chips">
          <span class="chip confirmed">Confirmed ${statuses.Confirmed || 0}</span>
          <span class="chip likely">Likely ${statuses.Likely || 0}</span>
          <span class="chip validation">Needs validation ${statuses["Needs validation"] || 0}</span>
        </div>
      </div>
      <div class="panel">
        <div class="section-title"><h2>Findings By Severity</h2><span>Distribution</span></div>
        ${renderSeverityDonutHtml(counts, total)}
      </div>
    </div>
  </section>

  <section class="page">
    <div class="section-title"><h2>Findings At A Glance</h2><span>Top reportable items</span></div>
    ${renderFindingsSummaryTableHtml(report)}
  </section>

  <section class="page">
    <div class="section-title"><h2>Confirmed Vulnerabilities / Risks</h2><span>Concrete observations</span></div>
    ${renderConfirmedRisksHtml(report)}
  </section>

  <section class="page">
    <div class="grid two">
      <div class="panel"><h2>Coverage Matrix</h2>${renderCoverageMatrixHtml(report)}</div>
      <div class="panel"><h2>Safe Validation Steps</h2>${renderSafeValidationHtml(report)}</div>
    </div>
  </section>

  <section class="page">
    <div class="grid two">
      <div class="panel"><h2>Reviewed Surfaces</h2>${renderReviewedSurfacesHtml(report)}</div>
      <div class="panel"><h2>Tool Execution</h2>${renderToolsHtml(report)}</div>
    </div>
  </section>

  <section class="page">
    <div class="section-title"><h2>Detailed Findings</h2><span>Grouped by severity</span></div>
    ${sections.map((severity) => renderHtmlSeveritySection(severity, report)).join("")}
  </section>

  <section class="page">
    <div class="grid two">
      <div class="panel"><h2>Scope And Authorization</h2>${htmlMarkdownList(renderScopeAndAuthorization(report))}</div>
      <div class="panel"><h2>Auth And Business Logic Scope</h2>${htmlMarkdownList(renderAuthScope(report))}</div>
    </div>
  </section>

  <section class="page">
    <div class="section-title"><h2>Skipped Checks And Residual Risk</h2><span>Honest coverage limits</span></div>
    ${renderSkippedHtml(report)}
  </section>

  <section class="cute-note">
    <div class="mascot" aria-hidden="true"><i></i></div>
    <div><strong>Defensive report note</strong><br>This report is designed to be clear, non-destructive, and review-ready. Validate uncertain findings with controlled test accounts, source review, logs, or staging proof before treating them as exploitable.</div>
  </section>

  <details class="appendix"><summary>Appendix: Full Markdown Report</summary><pre>${escapeHtml(markdown)}</pre></details>
</main>
</body>
</html>
`;
}

function severityCounts(report) {
  return report.findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {});
}

function validationStatusCounts(report) {
  return report.findings.reduce((acc, finding) => {
    const status = findingStatus(finding);
    acc[status] = (acc[status] || 0) + 1;
    return acc;
  }, {});
}

function overallRiskLabel(counts) {
  if (counts.critical) return "Critical Risk";
  if (counts.high) return "High Risk";
  if (counts.medium) return "Medium Risk";
  if (counts.low) return "Low Risk";
  if (counts.info) return "Informational";
  return "No Findings";
}

function overallRiskClass(counts) {
  if (counts.critical) return "risk-critical";
  if (counts.high) return "risk-high";
  if (counts.medium) return "risk-medium";
  if (counts.low) return "risk-low";
  if (counts.info) return "risk-info";
  return "risk-clean";
}

function reportId(report) {
  const stamp = String(report.startedAt || new Date().toISOString()).slice(0, 10).replace(/-/g, "");
  const target = reportTargetName(report)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 18)
    .replace(/^-|-$/g, "") || "target";
  return `ASAP-${stamp}-${target}`;
}

function formatDateTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value || "");
  return date.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

function severityPercent(count, total) {
  if (!total) return 0;
  return Math.round((count / total) * 100);
}

function renderSeverityCardsHtml(counts, total) {
  const items = [
    ["critical", "Critical"],
    ["high", "High"],
    ["medium", "Medium"],
    ["low", "Low"],
    ["info", "Info"]
  ];
  const cards = items.map(([key, label]) => {
    const value = counts[key] || 0;
    const pct = severityPercent(value, total);
    return `<article class="stat ${key}">
      <div class="label"><span>${escapeHtml(label)}</span><span class="dot"></span></div>
      <strong>${value}</strong>
      <small>${pct}% of total findings</small>
      <div class="bar" style="--pct:${pct}%; --color: var(--${key})"><i></i></div>
    </article>`;
  }).join("");
  return `${cards}<article class="stat">
    <div class="label"><span>Total Findings</span><span class="dot" style="background: var(--mint)"></span></div>
    <strong>${total}</strong>
    <small>Across all severities</small>
    <div class="bar" style="--pct:100%; --color: var(--mint)"><i></i></div>
  </article>`;
}

function renderSeverityDonutHtml(counts, total) {
  const safeTotal = total || 1;
  const c = ((counts.critical || 0) / safeTotal) * 100;
  const h = c + ((counts.high || 0) / safeTotal) * 100;
  const m = h + ((counts.medium || 0) / safeTotal) * 100;
  const l = m + ((counts.low || 0) / safeTotal) * 100;
  const style = `--criticalEnd:${c.toFixed(2)}%; --highEnd:${h.toFixed(2)}%; --mediumEnd:${m.toFixed(2)}%; --lowEnd:${l.toFixed(2)}%`;
  const rows = [
    ["critical", "Critical"],
    ["high", "High"],
    ["medium", "Medium"],
    ["low", "Low"],
    ["info", "Info"]
  ].map(([key, label]) => {
    const value = counts[key] || 0;
    return `<div class="legend-row"><span class="dot" style="background: var(--${key})"></span><span>${escapeHtml(label)}</span><strong>${value} (${severityPercent(value, total)}%)</strong></div>`;
  }).join("");
  return `<div class="donut-wrap"><div class="donut" style="${escapeHtml(style)}"></div><div class="legend">${rows}</div></div>`;
}

function renderFindingsSummaryTableHtml(report) {
  const findings = report.findings
    .filter((finding) => severityRank[finding.severity] >= severityRank.low)
    .slice(0, 12);
  if (!findings.length) return `<p class="empty">No findings recorded by the checks that ran.</p>`;
  return `<table class="findings-table"><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Affected Surface</th></tr></thead><tbody>${
    findings.map((finding) => `<tr>
      <td>${escapeHtml(finding.title)}</td>
      <td><span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(capitalize(finding.severity))}</span></td>
      <td>${escapeHtml(findingStatus(finding))}</td>
      <td>${finding.location ? `<code>${escapeHtml(finding.location)}</code>` : ""}</td>
    </tr>`).join("")
  }</tbody></table>`;
}

function renderSafeValidationHtml(report) {
  const findings = report.findings
    .filter((finding) => severityRank[finding.severity] >= severityRank.medium)
    .slice(0, 5);
  if (!findings.length) return `<p class="empty">No medium-or-higher findings need validation steps.</p>`;
  return `<div class="safe-list">${findings.map((finding, index) => {
    const poc = safePocForFinding(finding, report);
    return `<div class="safe-step"><b>${index + 1}</b><div><strong>${escapeHtml(finding.title)}</strong><br><span class="muted">${escapeHtml(poc?.summary || "Validate safely with source review or staging proof.")}</span></div><span class="badge">Safe</span></div>`;
  }).join("")}</div>`;
}

function shieldSvg() {
  return `<svg viewBox="0 0 24 24" role="img" aria-label="Shield"><path fill="currentColor" d="M12 2 4.5 5.2v5.6c0 4.7 3.1 9 7.5 10.5 4.4-1.5 7.5-5.8 7.5-10.5V5.2L12 2Zm-1.1 13.7-3.3-3.3 1.4-1.4 1.9 1.9 4.4-4.4 1.4 1.4-5.8 5.8Z"/></svg>`;
}

function renderHtmlSeveritySection(severity, report) {
  const findings = report.findings.filter((finding) => finding.severity === severity);
  return `<section class="section"><h2>${escapeHtml(capitalize(severity))} Severity Findings</h2>${
    findings.length
      ? findings.map((finding, index) => renderFindingCardHtml(finding, index + 1, report)).join("")
      : `<p class="empty">No ${escapeHtml(severity)} findings recorded.</p>`
  }</section>`;
}

function renderFindingCardHtml(finding, index, report) {
  const status = findingStatus(finding);
  const poc = safePocForFinding(finding, report);
  return `<article class="finding ${escapeHtml(finding.severity)}">
    <div class="finding-head">
      <h3>${index}. ${escapeHtml(finding.title)}</h3>
      <div class="pills">
        <span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(capitalize(finding.severity))}</span>
        <span class="badge">${escapeHtml(status)}</span>
        <span class="badge">${escapeHtml(finding.confidence)} confidence</span>
      </div>
    </div>
    <div class="finding-grid">
      <div class="field"><strong>Category</strong>${escapeHtml(finding.category)}</div>
      ${finding.location ? `<div class="field"><strong>Affected Surface</strong><code>${escapeHtml(finding.location)}</code></div>` : ""}
      ${finding.owasp ? `<div class="field"><strong>OWASP Mapping</strong>${escapeHtml(finding.owasp)}</div>` : ""}
      ${finding.cwe ? `<div class="field"><strong>CWE</strong>${escapeHtml(finding.cwe)}</div>` : ""}
    </div>
    ${finding.evidence ? `<div class="field evidence"><strong>Evidence</strong><code>${escapeHtml(finding.evidence)}</code></div>` : ""}
    <div class="field"><strong>Risk</strong>${escapeHtml(findingRisk(finding))}</div>
    <div class="field"><strong>Impact</strong>${escapeHtml(findingImpact(finding))}</div>
    <div class="field"><strong>Remediation</strong>${escapeHtml(finding.remediation)}</div>
    ${poc ? `<div class="field"><strong>Safe PoC / Validation</strong><p>${escapeHtml(poc.summary)}</p>${poc.commands?.length ? `<pre>${escapeHtml(poc.commands.join("\n"))}</pre>` : ""}${poc.note ? `<p class="muted">${escapeHtml(poc.note)}</p>` : ""}</div>` : ""}
    ${status === "Needs validation" ? `<div class="field"><strong>Validation Needed</strong>Confirm server-side behavior with an authenticated test account, source review, or controlled staging proof before relying on this as an exploitable vulnerability.</div>` : ""}
  </article>`;
}

function renderConfirmedRisksHtml(report) {
  const items = confirmedRiskItems(report);
  if (!items.length) return `<p class="empty">No confirmed vulnerabilities or concrete risk observations were recorded by the checks that ran.</p>`;
  return items.map((item) => `<article class="finding">
    <div class="finding-head"><h3>${escapeHtml(item.title)}</h3></div>
    <div class="field"><strong>Confirmed</strong>${escapeHtml(item.confirmed)}</div>
    <div class="field"><strong>Risk</strong>${escapeHtml(item.risk)}</div>
    <div class="field"><strong>Impact</strong>${escapeHtml(item.impact)}</div>
    <div class="field"><strong>F12 check</strong><code>${escapeHtml(item.f12)}</code></div>
    ${item.remediation ? `<div class="field"><strong>Fix</strong>${escapeHtml(item.remediation)}</div>` : ""}
  </article>`).join("");
}

function htmlParagraphs(text) {
  return String(text || "")
    .split(/\n{2,}/)
    .filter(Boolean)
    .map((part) => `<p>${escapeHtml(part.trim())}</p>`)
    .join("");
}

function htmlMarkdownList(text) {
  const lines = String(text || "").split(/\r?\n/).filter(Boolean);
  if (!lines.length) return `<p class="empty">None recorded.</p>`;
  if (lines.every((line) => line.trim().startsWith("- "))) {
    return `<ul>${lines.map((line) => `<li>${escapeHtml(line.trim().replace(/^- /, ""))}</li>`).join("")}</ul>`;
  }
  return htmlParagraphs(text);
}

function renderReviewedSurfacesHtml(report) {
  if (!report.reviewedSurfaces?.length) return `<p class="empty">No reviewed surfaces were recorded.</p>`;
  return `<table><thead><tr><th>Surface</th><th>Risk Area</th><th>Outcome</th><th>Notes</th></tr></thead><tbody>${
    report.reviewedSurfaces.map((surface) => `<tr><td>${escapeHtml(surface.surface)}</td><td>${escapeHtml(surface.riskArea)}</td><td>${escapeHtml(surface.outcome)}</td><td>${escapeHtml(surface.notes)}</td></tr>`).join("")
  }</tbody></table>`;
}

function renderCoverageMatrixHtml(report) {
  const items = uniqueCoverage(report.coverage || []);
  if (!items.length) return `<p class="empty">No coverage records were recorded.</p>`;
  return `<table><thead><tr><th>Area</th><th>Method</th><th>Status</th><th>Notes</th></tr></thead><tbody>${
    items.map((item) => `<tr><td>${escapeHtml(item.area)}</td><td>${escapeHtml(item.method)}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.notes)}</td></tr>`).join("")
  }</tbody></table>`;
}

function renderToolsHtml(report) {
  if (!report.tools?.length) return `<p class="empty">No external tools recorded.</p>`;
  return `<table><thead><tr><th>Tool</th><th>Status</th><th>Exit Code</th></tr></thead><tbody>${
    report.tools.map((tool) => `<tr><td>${escapeHtml(tool.name)}</td><td>${escapeHtml(tool.status)}</td><td>${tool.exitCode !== undefined ? escapeHtml(tool.exitCode) : ""}</td></tr>`).join("")
  }</tbody></table>`;
}

function renderSkippedHtml(report) {
  const skipped = unique(report.skipped || []);
  if (!skipped.length) return `<p class="empty">None recorded.</p>`;
  return `<ul>${skipped.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

async function writePdfReport(pdfPath, markdown) {
  await fs.mkdir(path.dirname(pdfPath), { recursive: true });
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "security-audit-pdf-"));
  const markdownPath = path.join(tempDir, "report.md");
  await fs.writeFile(markdownPath, markdown, "utf8");
  const script = `
import re
import sys
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

md_path = Path(sys.argv[1])
pdf_path = Path(sys.argv[2])
text = md_path.read_text(encoding="utf-8-sig", errors="replace")
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="FindingTitle", parent=styles["Heading3"], spaceBefore=8, spaceAfter=4))
styles["Normal"].fontName = "Helvetica"
styles["Normal"].fontSize = 9
styles["Normal"].leading = 12
story = []

def esc(value):
    return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

for raw in text.splitlines():
    line = raw.rstrip()
    if not line:
        story.append(Spacer(1, 0.08 * inch))
        continue
    if line.startswith("# "):
        story.append(Paragraph(esc(line[2:]), styles["Title"]))
    elif line.startswith("## "):
        if story:
            story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph(esc(line[3:]), styles["Heading2"]))
    elif line.startswith("### "):
        story.append(Paragraph(esc(line[4:]), styles["FindingTitle"]))
    elif line.startswith("|") and "---" not in line:
        cells = [esc(cell.strip()) for cell in line.strip("|").split("|")]
        table = Table([[Paragraph(cell, styles["Normal"]) for cell in cells]], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(table)
    elif line.startswith("- "):
        story.append(Paragraph("&bull; " + esc(line[2:]), styles["Normal"]))
    else:
        story.append(Paragraph(esc(line), styles["Normal"]))

doc = SimpleDocTemplate(str(pdf_path), pagesize=LETTER, rightMargin=0.55*inch, leftMargin=0.55*inch, topMargin=0.55*inch, bottomMargin=0.55*inch)
doc.build(story)
`;
  try {
    const result = await runCommand("python", ["-c", script, markdownPath, pdfPath], process.cwd(), 120000);
    if (result.error || result.code !== 0) {
      const detail = result.error || result.stderr || `python exited ${result.code}`;
      throw new Error(`PDF generation failed: ${detail}`);
    }
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}

function formatInventory(inventory) {
  const parts = [];
  if (inventory.kind) parts.push(`kind=${inventory.kind}`);
  if (inventory.scannedFiles !== undefined) parts.push(`scannedFiles=${inventory.scannedFiles}`);
  if (inventory.collectedFiles !== undefined) parts.push(`collectedFiles=${inventory.collectedFiles}`);
  if (inventory.diffBase) parts.push(`diffBase=${inventory.diffBase}`);
  if (inventory.stacks?.length) parts.push(`stacks=${inventory.stacks.join(",")}`);
  if (inventory.frameworks?.length) parts.push(`frameworks=${inventory.frameworks.join(",")}`);
  if (inventory.lockfiles?.length) parts.push(`lockfiles=${inventory.lockfiles.join(",")}`);
  if (inventory.apiArtifacts?.length) parts.push(`apiArtifacts=${inventory.apiArtifacts.length}`);
  if (inventory.endpoints?.length) parts.push(`endpoints=${inventory.endpoints.length}`);
  if (inventory.status) parts.push(`httpStatus=${inventory.status}`);
  if (inventory.tlsProtocol) parts.push(`tls=${inventory.tlsProtocol}`);
  return parts.length ? parts.join("; ") : "not available";
}

function escapeTable(value) {
  return String(value || "").replaceAll("|", "\\|").replace(/\r?\n/g, " ");
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function unique(values) {
  return [...new Set(values)];
}

function uniqueCoverage(items) {
  const seen = new Set();
  const output = [];
  for (const item of items) {
    const key = `${item.area}\0${item.method}\0${item.status}\0${item.notes}`;
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(item);
  }
  return output;
}

function uniquePaths(values) {
  return [...new Set(values.filter(Boolean).map((value) => path.resolve(value)))];
}

function capitalize(value) {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

main().catch((error) => {
  console.error(`security-audit-pro failed: ${error.message}`);
  process.exitCode = 1;
});

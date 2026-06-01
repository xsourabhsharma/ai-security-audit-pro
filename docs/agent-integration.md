# Agent Integration

Security Audit Pro is intentionally agent-neutral. The reliable integration point is the CLI:

```bash
node scripts/security-audit.mjs --target <target>
```

Agents that support plugin or skill manifests can also read the included instruction files.

## Codex

Codex can use:

- `.codex-plugin/plugin.json`
- `skills/security-audit/SKILL.md`
- `AGENTS.md`

Recommended local install after cloning:

```powershell
node scripts/security-audit.mjs --help
```

Then ask Codex to use Security Audit Pro for security audits.

## Claude Code

Claude Code can use:

- `.claude-plugin/plugin.json`
- `skills/security-audit/SKILL.md`
- `CLAUDE.md`

If native plugin installation is not used, keep this repository in the project and let Claude Code read `CLAUDE.md`.

## Gemini CLI

Gemini CLI can use:

- `GEMINI.md`
- The universal CLI command.

Keep this repository in the workspace or reference it by absolute path from Gemini prompts.

## Google Antigravity

Use `GEMINI.md` or `agent-adapters/antigravity.md` as the project instruction source, then run the CLI.

## OpenCode

Use `AGENTS.md` or `agent-adapters/opencode.md`, then run the CLI.

## Hermes

Use `agent-adapters/hermes.md` as the tool instruction source. Register the command as a local shell tool if Hermes supports command tools.

## OpenClaw

Use `agent-adapters/openclaw.md` as the instruction source, then call the CLI through the local shell.

## Universal Prompt

Use this in any agent that can run shell commands:

```text
Use Security Audit Pro from this repository. Run node scripts/security-audit.mjs against the exact target. Keep testing defensive and non-destructive. Redact secrets. Confirm authorization before active testing. Produce Markdown plus HTML when requested.
```

## Notes

Different agents support different plugin formats. This repository includes native metadata for Codex and Claude Code, and portable instructions for every other agent. The CLI is the stable compatibility layer.

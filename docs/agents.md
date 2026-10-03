# Coding agents: manual setup

The **Agents** tab of the VirusTotal panel sets up Omarchy's coding agents for you; see [Coding agents](../README.md#coding-agents). This page is for doing it by hand:

- for the agents the tab marks **Manual setup**;
- when the tab can't edit an agent's settings (comments in the file, a symlinked file, a file it can't read);
- when you'd rather run the commands yourself, or undo them without the panel.

## What every agent needs

- A remote MCP server named `virustotal` with the URL `https://ai.virustotal.com/mcp`. The transport is Streamable HTTP, which most agents call `http`.
- No token and no `Authorization` header. The agent signs in to VirusTotal with your Google account (OAuth) the first time it connects.
- One VirusTotal entry per agent. If the agent already has one, under any name, keep it instead of adding a second.

VirusTotal's own guides: [Claude Code](https://ai.virustotal.com/connect/mcp?client=claude), [Codex](https://ai.virustotal.com/connect/mcp?client=codex), [Antigravity](https://ai.virustotal.com/connect/mcp?client=agy), [GitHub Copilot](https://ai.virustotal.com/connect/mcp?client=copilot), [Cursor](https://ai.virustotal.com/connect/mcp?client=cursor) and [other clients](https://ai.virustotal.com/connect/mcp?client=other).

## Agents with an `mcp add` command

### Claude Code

```bash
claude mcp add --scope user --transport http virustotal https://ai.virustotal.com/mcp
```

Sign in: start `claude`, type `/mcp`, pick **virustotal** and choose **Authenticate**. Your browser opens to sign in with Google.

Omarchy can keep several Claude accounts, and each one has its own MCP settings. `omarchy-agent-account-state homes claude` lists them: account, home folder, and `1` on the active one. The command above covers the primary account, whose home is `~/.claude`. For every other account, run it with that account's home, then sign in in that account too:

```bash
CLAUDE_CONFIG_DIR=<account home> claude mcp add --scope user --transport http virustotal https://ai.virustotal.com/mcp
```

### Codex

```bash
codex mcp add virustotal --url https://ai.virustotal.com/mcp
codex mcp login virustotal
```

The second command opens your browser to sign in with Google. The entry is written to `~/.codex/config.toml`, which Omarchy's Codex accounts share.

### Antigravity

```bash
agy mcp add --type http virustotal https://ai.virustotal.com/mcp
```

Sign in: start `agy`, type `/mcp`, pick **virustotal** and choose **Authenticate**. After you sign in with Google, paste the code from the browser into that dialog, not into the chat. The entry is written to `~/.gemini/config/mcp_config.json`.

### GitHub Copilot

```bash
copilot mcp add --transport http virustotal https://ai.virustotal.com/mcp
```

Sign in: start `copilot`, type `/mcp auth virustotal` and sign in with Google. `/mcp list` shows the connection. The entry is written to `~/.copilot/mcp-config.json`.

### Grok

```bash
grok mcp add --transport http virustotal https://ai.virustotal.com/mcp
```

This recipe comes from xAI's documentation; VirusTotal has not verified it. Grok asks you to sign in with Google the first time it uses VirusTotal, and `/mcps` shows the connection. The entry is written to `~/.grok/config.toml`.

## Agents with a JSON settings file

Merge the `virustotal` entry into the file and keep everything else in it. If the file doesn't exist yet, the snippet is the whole file.

### OpenCode

`~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "virustotal": {
      "type": "remote",
      "url": "https://ai.virustotal.com/mcp"
    }
  }
}
```

Sign in: `opencode mcp auth virustotal` opens your browser to sign in with Google.

If you keep your settings in `opencode.jsonc`, add the same `mcp` entry there. The panel never edits `.jsonc` files.

### Cursor CLI

`~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "virustotal": {
      "url": "https://ai.virustotal.com/mcp"
    }
  }
}
```

Sign in: `cursor-agent mcp login virustotal` opens your browser to sign in with Google.

### Merge with `jq`

For a file without comments, `jq` can add the entry and keep a copy of the old file next to it:

```bash
f=~/.cursor/mcp.json
cp -p "$f" "$f.bak" &&
  jq '.mcpServers.virustotal = {"url": "https://ai.virustotal.com/mcp"}' "$f.bak" > "$f.new" &&
  cat "$f.new" > "$f" && rm "$f.new"
```

The file is only replaced if `jq` succeeds, and it keeps its permissions. For OpenCode, use `f=~/.config/opencode/opencode.json` and the filter `'.mcp.virustotal = {"type": "remote", "url": "https://ai.virustotal.com/mcp"}'`. `jq` rewrites the layout of the file and fails on comments (JSONC); edit those files by hand.

## Agents with guided setup

### Crush

Merge this into `~/.config/crush/crush.json`:

```json
{
  "mcp": {
    "virustotal": {
      "type": "http",
      "url": "https://ai.virustotal.com/mcp"
    }
  }
}
```

Crush's sign-in for remote MCP servers has not been verified with VirusTotal.

### Hermes

Merge this into `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  virustotal:
    url: "https://ai.virustotal.com/mcp"
```

This has not been verified with VirusTotal. The community plugin [hermes-virustotal](https://github.com/king-tero/hermes-virustotal) is an alternative.

### OpenClaw, Oh My Pi, Ori and Muse Code

Add a remote MCP server named `virustotal` with the URL `https://ai.virustotal.com/mcp` (Streamable HTTP) the way the agent's documentation describes, and sign in with your Google account when it asks. Don't add token headers.

For OpenClaw, the community project [VT-sentinel](https://github.com/king-tero/VT-sentinel) is an alternative.

### Pi

Pi has no MCP support by design. [Link the skill](#the-virustotal-skill): in Pi, it looks things up through the plugin's VirusTotal AI connection instead.

## Check the connection

Ask the agent for the VirusTotal domain report of `virustotal.com`. It should call the `get_domain_report` tool and answer with the report. A list of tools alone proves nothing; only the report shows that the sign-in works.

Each check uses one lookup of your quota. MCP lookups count against the Google account the agent signed in with: 60 per minute and 1,000 per day, shared by every agent on that account.

## The `virustotal` skill

The skill is the plugin's `agents/skills/virustotal` folder. **Link** in the Agents tab links it into the skill folders Omarchy uses for its own skills. By hand:

```bash
skill=~/.config/omarchy/plugins/io.github.dsecuma.virustotal/agents/skills/virustotal
for dir in ~/.agents/skills ~/.claude/skills ~/.codex/skills ~/.pi/agent/skills ~/.gemini/config/skills ~/.hermes/skills ~/.hermes/profiles/*/skills; do
  case $dir in *'*'*) continue ;; esac
  mkdir -p "$dir"
  [ -e "$dir/virustotal" ] || [ -L "$dir/virustotal" ] || ln -s "$skill" "$dir/virustotal"
done
```

The loop leaves an existing `virustotal` file, folder or link alone, like **Link** does. Without the skill, agents still get the MCP tools, but not the instructions on how to report VirusTotal's results and when to ask before uploading.

## Remove an entry

Removing an entry does not revoke the access you granted with Google. Do that at [ai.virustotal.com/oauth/connections](https://ai.virustotal.com/oauth/connections) (the **VirusTotal access** button in the Agents tab).

| Agent | Remove |
|---|---|
| Claude Code | `claude mcp remove --scope user virustotal`; for other accounts, with `CLAUDE_CONFIG_DIR=<account home>` in front |
| Codex | `codex mcp remove virustotal` |
| Antigravity | `agy mcp remove virustotal` |
| GitHub Copilot | Delete `virustotal` from `mcpServers` in `~/.copilot/mcp-config.json` |
| Grok | `grok mcp remove virustotal` |
| OpenCode | Delete `virustotal` from `mcp` in `~/.config/opencode/opencode.json` |
| Cursor CLI | Delete `virustotal` from `mcpServers` in `~/.cursor/mcp.json` |
| Crush, Hermes and the rest | Delete the entry you added |

For a JSON file without comments, `jq` can do it, keeping a copy of the old file next to it:

```bash
f=~/.copilot/mcp-config.json
cp -p "$f" "$f.bak" &&
  jq 'del(.mcpServers.virustotal)' "$f.bak" > "$f.new" &&
  cat "$f.new" > "$f" && rm "$f.new"
```

Use `del(.mcp.virustotal)` for OpenCode.

To remove the skill links that point to this plugin, and only those:

```bash
find -H ~/.agents/skills ~/.claude/skills ~/.codex/skills ~/.pi/agent/skills ~/.gemini/config/skills ~/.hermes \
  -maxdepth 4 -type l -name virustotal -lname '*/io.github.dsecuma.virustotal/agents/skills/virustotal*' -print -delete 2>/dev/null
```

The panel only removes what it added: an entry it created that still holds exactly its URL, and links that point to the plugin. It keeps that record in `~/.local/state/omarchy-virustotal/agents.json`, so entries you add by hand are never touched by it.

# Changelog

What changed in each version of the plugin. The version is the one in `manifest.json`.

## 1.1.5 – 2026-10-06

- Honor HTTP Retry-After (seconds or HTTP-date) for both API engines, and keep server polling hints at every stage.
- Serialize and pace automatic uploads independently of parallel lookups. Preserve the recent quota window when rebuilding the limiter.
- Recover uncertain VTAI uploads with GET on the same SHA-256 receipt. Classic uploads fall back to a hash lookup. Ambiguous server/proxy failures no longer trigger another POST; explicit VTAI pre-admission capacity rejection remains retryable.
- Add offline transport/controller regressions and a real curl loopback fixture. Requires curl 7.84 or newer for response-header write-out (available on current Omarchy).

## 1.1.4 – 2026-10-06

- Cancel queued and preparing automatic uploads when permission is withdrawn. Invalidate stale hash callbacks across scanner shutdown, authentication failure, backend changes and permission off/on cycles.
- Keep the plugin scanner running when switching between two connected engines; the unchanged state-file path no longer leaves it waiting for a load signal.
- Add offline tests of the actual QML controller methods with deferred hash callbacks and fake services.

## 1.1.3 – 2026-10-03

- **Notify for every checked file** moved to a new **Notifications** section in Settings. It now shows while the Downloads watcher or the plugin scanner is on: it has always applied to both, but it could only be changed while the watcher was on.
- The bar widget description mentions the plugin scanner and the coding agents.
- Documentation: a Quick start, a settings reference with every `config.json` key, a keyboard table, steps for your own VirusTotal API key and for a key binding that opens the panel, [docs/agents.md](docs/agents.md) with the manual setup of every coding agent, and this changelog. The README now says that the Agents tab is <kbd>4</kbd>, not <kbd>5</kbd>.
- The `virustotal` skill no longer says that the panel shows analysis IDs.
- A test checks that `Model.DEFAULT_VERSION` matches `manifest.json`.

## 1.1.2 – 2026-10-03

- Suspicious-only results get a yellow exclamation mark instead of a red warning sign, in the result card, the alerts and the history. Malicious detections keep the red stop sign.
- The AI insight title is red for a malicious verdict and yellow for a suspicious one.
- The yellow is your theme's own yellow. Themes whose "yellow" is another colour get an amber.
- Hashes that don't fit are shortened in the middle with `…` instead of wrapping.
- More space between the header tabs and the status line.

## 1.1.1 – 2026-10-03

- Two-row header: the status line ("Connected · watching Downloads · checking plugins") gets its own line instead of being cut off next to the tabs.
- The last button of a tab no longer loses its bottom border at fractional monitor scales.
- README checked against the code.

## 1.1.0 – 2026-10-03

- **Agents** tab: adds the VirusTotal AI MCP server to Omarchy's coding agents, with each agent's own `mcp add` command, or a JSON merge with a backup for OpenCode and Cursor CLI. Each agent signs in with Google; the rest get guided steps.
- The `virustotal` skill, linked into the agents' skill folders.
- **Ask &lt;agent&gt;**: hands a finished lookup or a download alert to Omarchy's default agent.

## 1.0.0 – 2026-09-30

- Lookups of URLs, domains, IP addresses, hashes and local files (hashed locally) through VirusTotal AI, uploads after a confirmation dialog, analysis tracking, history, recent downloads, the Downloads watcher and notifications.
- Plugin scanner: looks up the files of new and updated Omarchy plugins, with a classic VirusTotal API key as an alternative engine and opt-in automatic uploads.
- MIT license.

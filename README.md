# VirusTotal for Omarchy

A community plugin for the [Omarchy](https://omarchy.org) shell (Quattro) that checks URLs, domains, IP addresses, file hashes and local files against VirusTotal from the bar. It can also watch your Downloads folder and alert you when a new file is flagged.

It talks to the public [VirusTotal AI API](https://ai.virustotal.com) (VTAI) with `curl`. There is nothing to build and no binary to install.

![VirusTotal panel in the Omarchy bar](preview.png)

## Features

- **Bar icon** with a status dot: red when engines flagged a download as malicious, a softer tone when they only flagged it as suspicious, dimmed while a check is running.
- **Scan tab**: paste a URL, domain, IP, MD5/SHA-1/SHA-256 hash or an absolute file path (`~/…` and `file://` work too).
  - Files are hashed locally; only the SHA-256 is looked up.
  - The result card shows what VirusTotal returned: flagged/total engines, the per-category counts, the most common detection labels, the file type, the most severe AI insight and a link to the full report.
  - An unknown file (32 MB or smaller) can be uploaded for analysis, always after a confirmation dialog. The panel then follows the analysis until it finishes.
- **Recent downloads**: one click checks one of the newest files in your Downloads folder.
- **History tab**: the last 50 checks, kept across restarts.
- The plugin never issues its own verdict: headlines are the raw counts (e.g. `2/91 flagged`) and AI insights are shown as returned.
- **Downloads watcher** (off by default): looks up each new download and notifies you when VirusTotal engines or AI insights flag it. It never uploads anything by itself.
- Keyboard friendly: type straight away; <kbd>Enter</kbd> scans, <kbd>Esc</kbd> closes, <kbd>Tab</kbd> moves to the next bar panel, <kbd>↑</kbd>/<kbd>↓</kbd> leave the text field, then <kbd>h</kbd>/<kbd>l</kbd> or <kbd>1</kbd>–<kbd>3</kbd> switch tabs.
- Follows your Omarchy theme; no hard-coded colours.

## Requirements

- Omarchy with the Quattro shell.
- `curl`, `sha256sum`, `stat` and `date` (curl plus coreutils, present on a standard Omarchy install).
- For the Downloads watcher and the recent downloads list: the `Qt.labs.folderlistmodel` QML module, part of `qt6-declarative`, which Quickshell already depends on. Without it the rest of the plugin keeps working.
- Notifications use `omarchy-notification-send` (bundled with Omarchy), or `notify-send` as a fallback.

## Install

```bash
omarchy plugin add https://github.com/dsecuma/omarchy-virustotal --enable
```

`omarchy plugin add` clones the repository into `~/.config/omarchy/plugins/io.github.dsecuma.virustotal`, validates it and, with `--enable`, asks which bar section to use (right by default). Nothing is compiled or run during installation, and no root access is needed.

Once the plugin is listed on [plugins.omarchy.org](https://plugins.omarchy.org), you can also install it from there.

Update with `omarchy plugin update io.github.dsecuma.virustotal`.

## Connecting to VirusTotal AI

The first time, the panel shows a **Connect** card. Nothing is sent to VirusTotal before you click it.

- **Connect** registers this computer once as an `omarchy` agent (`POST /api/v3/agents/register`). No VirusTotal API key is needed.
- The agent token is written to `${XDG_CONFIG_HOME:-~/.config}/vtai/auth.header` with mode 600, the location the VTAI guide recommends. Other VTAI clients can reuse the same file, and if one already exists the plugin uses it instead of registering again.
- `curl` reads the token straight from that file (`-H @file`). It never appears in QML, in logs or in any process's command line.
- **Settings → Disconnect** revokes the token on the server and deletes the file. Any other tool using that file stops working until you connect again.

If you try a check before connecting, the panel keeps what you typed and runs it right after you connect.

## Privacy and uploads

- A lookup sends only the URL, domain, IP or hash.
- A local file is hashed on your machine and only its SHA-256 is sent.
- A file is uploaded only when you click **Upload for analysis** and accept the dialog. The upload is a *standard, non-private submission* (`X-VTAI-Consent: standard-v1`): the file becomes available to the VirusTotal security community and its partners. Don't upload personal documents, internal code or anything that contains credentials.
- The file is hashed again right before sending; if it changed since the lookup, nothing is uploaded.
- If a connection drops mid-upload, the plugin never resends the file automatically. **Check status** asks VirusTotal whether the upload arrived.
- **No detections** means no vendor flagged the item. It is not a guarantee that it is safe.

## Downloads watcher

Enable it in **Settings → Check new downloads**. It watches the folder from `XDG_DOWNLOAD_DIR` (or `~/Downloads`).

- Files already in the folder when the watcher starts are never checked; only new names are.
- Browser temporary files (`.part`, `.crdownload`, …) and hidden files are ignored. A file is checked once it has not changed for a few seconds, and it is retried for up to 30 minutes while it is still being written.
- At most 20 new files are queued per change, lookups are spaced out, and files above 1 GiB are skipped.
- Each file is looked up once per session, and not again within 24 hours if it already has a report.
- Only flagged files notify, unless you enable **Notify for every checked file**. Clicking a notification opens the panel.
- The watcher runs once per session, whatever the number of monitors. On a replacement bar that doesn't run plugin services, the panel still works but the watcher and notifications are off.

## Files

| Path | Contents |
|---|---|
| `~/.config/vtai/auth.header` | VTAI agent token (shared with other VTAI tools) |
| `~/.config/omarchy-virustotal/config.json` | Watcher settings |
| `~/.local/state/omarchy-virustotal/history.json` | Check history and the last watcher alert |

`XDG_CONFIG_HOME` and `XDG_STATE_HOME` are honoured.

## Remove

1. Optional: open **Settings → Disconnect** to revoke the token first.
2. Remove the plugin:

   ```bash
   omarchy plugin remove io.github.dsecuma.virustotal
   ```

3. Delete its data:

   ```bash
   rm -rf ~/.config/omarchy-virustotal ~/.local/state/omarchy-virustotal
   ```

4. Delete `~/.config/vtai/auth.header` only if no other VTAI tool uses it.

## Troubleshooting

- **"Required tools not found"**: install the listed commands and reopen the panel.
- **"Token rejected"**: the token was revoked or expired. Use **Reconnect** in the panel.
- **The watcher option is disabled**: the `Qt.labs.folderlistmodel` module is missing (install `qt6-declarative`), or the bar doesn't run plugin services.
- **Logs**: warnings are printed with a `[virustotal]` prefix in the Omarchy shell log.

## Development

```bash
node tests/model.test.js     # pure logic in Model.js
node tests/scripts.test.js   # shell snippets in Scripts.js (sh, bash and dash, with a fake curl)
qmllint -I "$OMARCHY_PATH/shell" *.qml
"$OMARCHY_PATH/bin/omarchy-plugin-validate" .
```

| File | Role |
|---|---|
| `manifest.json` | Plugin manifest (`bar-widget` + `service`) |
| `BarWidget.qml` | Bar icon; loads the panel and finds the shared service |
| `Panel.qml` | Scan, History and Settings UI |
| `Service.qml` | Credential, API calls, uploads, polling, history, watcher |
| `DownloadsFolder.qml` | Downloads listing (loaded on demand) |
| `VirusTotalIcon.qml` | The VirusTotal mark drawn with theme colours |
| `Model.js` | Pure helpers (input detection, result mapping, history) |
| `Scripts.js` | POSIX `sh` snippets; untrusted values only travel as arguments |

CI (`.github/workflows/ci.yml`) runs the tests, checks the manifest, rejects hex colours, symlinks and executable files, and runs Omarchy's plugin validator.

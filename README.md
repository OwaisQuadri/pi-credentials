# pi-credentials

A Pi extension that lets agents **use** your credentials without **seeing** them. You decide which credential works where, and you can always see why each one exists.

Status: the helper, `/cred list | add | register | edit | grant | revoke | group | delete | env`, the `cred env create` command, the agent tools `cred_list`, `cred_request`, `cred_type`, `cred_sudo`, `cred_notarize`, `cred_env`, and `cred_ask`, output redaction, the read block for `.env` and Pi auth files, leak warnings with `/cred scan | rotated | scrub`, last use in `/cred list`, and saving a `{{secret:…}}` handle from `pi-ask-user` work. One-time use of a handle without saving it is not built yet.

## Install

Requires macOS, Swift 6.4 or newer, and Pi. The package has no install script, so installing or updating does not build the helper. When the helper is missing at startup, the extension asks you, then runs `scripts/build.zsh`, which builds and signs it. Pi finishes starting when the build is done. It refuses to build when the helper source has uncommitted changes, the package is not its own Git checkout, or Pi has no interface, and then tells you to run the script yourself.

```zsh
pi install git:https://github.com/OwaisQuadri/pi-credentials
```

Then register a key that is already in Keychain, define a project group, and grant it:

```text
/cred register openrouter openrouter-api-key api-key
/cred group work github.com/<org>/*
/cred grant openrouter work
```

## Purpose

- Keep credential values in macOS Keychain, out of the model context, tool results, logs, and saved transcripts.
- Show which credentials an agent may use in the current project, what each one is for, and what it can do.
- Remove you as a blocker. After you grant a credential, agents use it without a prompt.

## Who it serves

| Person or process | Need |
|---|---|
| You, granting access | One clear decision for each credential and scope. A description that reminds you what a key is for. |
| The agent | A catalog of usable credentials, actions that do the job, and refusals that say how to fix them. |
| You, reading a transcript later | No values anywhere. Each use names the credential, action, target, and project. |

## Parts

- **Swift helper.** A signed binary that reads registered Keychain items without a dialog, stores the catalog and grants, and asks for owner confirmation.
- **Pi extension.** TypeScript. It provides the `/cred` command, the agent tools, output redaction, and the read block. It calls the helper and never caches values on disk. At session start, it removes environment variables whose values match a registered `api-key` or `app-password` from the Pi process, so tools that Pi starts do not inherit them.

## Catalog

Only credentials that you register appear. Each entry has:

| Field | Example |
|---|---|
| name | `openrouter` |
| description | `OpenRouter key for model calls and image generation` |
| kind | `api-key`, `password`, `app-password`, or `passcode` |
| Keychain item | The existing item's service name. The broker refers to it; it does not copy the value. |
| allowed hosts | Optional, `api-key` only. Empty means any host. `api.example.com` matches only that host; `*.example.com` matches it and every subdomain. |
| allowed apps | Optional, for typing. Bundle identifiers, such as `com.apple.ScreenContinuity`. Empty means the broker never types the credential. |
| rotation link | Optional. The page where you replace this credential. |
| grants | `global`, or one or more project groups |
| environment variable | Optional. The name in `.env` files. The default is the credential name in upper case, such as `OPENROUTER`. |

Registering a credential moves the item under the helper's ownership:

1. The helper reads the existing item once. macOS shows a dialog, and you click Allow.
2. The helper re-creates the item. Its access list then trusts only the helper, and its partition list holds only the helper's signing team.
3. Other readers, including `security find-generic-password -w`, get a macOS dialog that you can deny.

Items that you created with the `security` command trust `/usr/bin/security` and the `apple-tool:` partition. Any shell command can read those items silently until you register them.

The helper never reads an item before you register it, because macOS cannot suppress the dialog for login-keychain items.

The helper is signed with a Developer ID identity. Its designated requirement is its identifier and team, not a file hash, so a rebuilt helper keeps its access. A build with ad-hoc signing loses access after each rebuild.

Registering copies the item's label, comment, description, and generic attributes. The new item is in the default keychain, even if the original was in another keychain.

The agent reads the catalog with `cred_list`: names, descriptions, kinds, and actions for the current project. Never values.

## Scope

- `global`: every project.
- Project group: a name, such as `work`, matched by Git remote pattern, such as `github.com/<org>/*`. Worktrees and copy-on-write checkouts share the remote, so they match automatically.

A later version may replace remote patterns with deterministic project tags.

## Agent actions

Each kind has fixed actions. The helper delivers the value itself; the model never handles it.

| Kind | Action | Delivery |
|---|---|---|
| `api-key` | `cred_request` | HTTP request with the key in a header. Refused for hosts outside the allowed list, when one is set. |
| `password` | `cred_type` | Types into a named app window, in the background when the app allows it. |
| `password` | `cred_sudo` | Runs one command as root. **Asks you to approve each exact command.** |
| `app-password` | `cred_notarize` | Runs `xcrun notarytool` with the password on standard input. |
| `passcode` | `cred_type` | Same as above. |
| `api-key`, `app-password` | `cred_env`, `/cred env`, `cred env create` | Writes a `.env` file with the credentials granted to this project. |
| — | `cred_ask` | Asks you for a new secret in an input box. See [Input](#input). |

`cred_type` takes a running app's bundle identifier or name. Exactly one running app must match, its bundle identifier must be in the credential's allowed apps, and its signature must chain to Apple for that identifier. A credential with no allowed apps is never typed. Allow only apps that do not save or show typed text, such as iPhone Mirroring or a password dialog; a terminal or text editor would let an agent read the value back. The helper sends each key to that app's process. By default it brings the app to the front first and stops if another app takes focus. With `isActivating: false` it types in the background, which works only in apps that accept background input. The helper needs Accessibility permission: System Settings > Privacy & Security > Accessibility.

`cred_sudo` runs one argument list, not a shell string. The helper resolves a bare program name in `/usr/bin:/bin:/usr/sbin:/sbin` only. An absolute path must name a program that root owns, in directories that only root can change, so nobody can swap it after approval. Touch ID shows the resolved command in full each time, and the helper refuses a command too long to show. The helper gives the password to `sudo -v`, runs the command with `sudo -n` and an empty standard input, then clears the sudo timestamp. When you cancel the tool or the time limit passes, the helper uses the password again to send the command and its child processes a stop signal as root, then a kill signal 3 seconds later, and still clears the timestamp. A process that detaches from the command is not stopped. If the stop fails, the result says that the command may still be running. A cancel that arrives before the command starts stops it from starting. It needs a user present. With `timestamp_timeout=0` in sudoers, the second step fails with `sudo-no-timestamp`. With Touch ID for sudo (`pam_tid`), sudo can show its own Touch ID prompt during the first step, and during a stop after the sudo timestamp expires.

`cred_notarize` refuses `--password` and keychain-profile options, and requires `--apple-id` and `--team-id`. The helper passes the password on standard input, so it never appears in the process list.

`.env` files hold only `api-key` and `app-password` credentials of 8 or more characters. The file must be inside the project and be named `.env` or `.env.<suffix>`, but not `.example`, `.sample`, `.template`, or `.dist`. Inside a Git repository, Git must ignore the file and must not track it. An existing file keeps its other lines; the helper replaces only the variables that it manages. The helper writes the file with mode 600 and refuses a symlink.

To use `cred env create` from your shell, link it once:

```zsh
ln -s <package directory>/scripts/cred.zsh ~/.local/bin/cred
```

`.env` files: agents may create them but not read them. The read tool and command guard block direct reads. Programs that the agent runs can still read the file; see [Limits](#limits).

## Commands

```
/cred add | register | edit | grant | revoke | group | delete | list | scan | rotated | scrub
```

- Fuzzy Tab completion at each position, like `/model`: subcommand, then credential name with its description trimmed to the terminal width, then scope.
- `/cred list` opens a scrollable picker: name, kind, description, grants, last use.
- **Owner confirmation is required for add, register, edit, grant, revoke, group, delete, rotated, and scrub.** macOS asks for Touch ID, or your login password when Touch ID is unavailable. The prompt names the change, such as the old and new hosts, the group patterns, or the Keychain item to take over. Use needs no prompt.
- `/cred edit` changes the value or the metadata: description, kind, hosts, apps, rotation link, and environment variable. It never shows the value. A new value counts as a rotation.

## Input

Two routes bring a new secret in. Neither shows the value to the model.

1. **You start it.** `/cred add <name>` opens an input box.
2. **The agent starts it.** `cred_ask(name, reason)` opens the same input box mid-task.
3. **The agent asks with `pi-ask-user`.** `ask_user_question` with `secure: true` shows the value by default, and Ctrl+T masks it. The model gets only a session handle, such as `{{secret:3f9a01bc}}`. `pi-ask-user` hands the value to this package through Pi's in-process event bus. `cred_ask` with `secret: <handle>` then saves it without asking again. Saving requires Touch ID. Handles end with the Pi session.

## Missing access

When a credential is not granted for the current project, the refusal gives the reason and the fix:

```
'tracker' is not granted for this project. Ask the user to run: /cred grant tracker docs
```

When no project group matches the repository, the fix is `/cred grant tracker global, or add a project group for this repository`.

In an interactive session, the agent offers the grant inline, and you confirm with Touch ID. In an unattended session, the agent records the block and moves to other work.

## Visibility

- The footer shows a marker, such as `🔑 openrouter`, while a credential is in use.
- `~/.pi/agent/cred/usage.jsonl` records each use and each refusal: time, credential, action, target, project groups, session ID, and result. Never the value. Keep it out of Git.

## Leak warnings

The broker scans saved chat history for credentials that leaked before redaction caught them, or that never passed through the broker.

- **What it finds.** Registered `api-key` and `app-password` values of 8 or more characters, including their base64 and URL-encoded forms, and well-known key formats, such as `sk-`, `sk-ant-`, `sk-or-v1-`, `sk-proj-`, `lin_api_`, `ghp_`, and `xoxb-`. The scan skips obvious placeholders, such as `sk-xxxx` or `sk-your-key-here`. It stores a fingerprint of each unregistered key, never the key.
- **When it runs.** In the background at Pi startup, on sessions saved since the last scan. After you add, change, or delete a registered value, the next startup scan reads every session again. It reads only `.jsonl` session files: all of them under Pi's default session folder, and the files directly inside any other session folder that Pi has used. `/cred scan` scans the full history; 10 GB of sessions takes about 3 minutes. The scan state is in `~/.pi/agent/cred/scan.json`, mode 600.
- **How it warns.** Like Pi's package update notice, a warning appears in the conversation each time Pi starts, reloads, or resumes a session, until you resolve it. Warnings from earlier runs are not drawn again, and the model does not see them:

```
⚠ 2 Known and 27 Unknown credentials leaked in chat history.
  Known:
  - linear
  - openrouter

  register credentials with `/cred register` or `/cred add`
  use `/cred scrub` to clean the chat history of credentials
  use `/cred edit <name> value`, `/cred rotated`, or `/cred rotated all` to start with a clean record.
```

- **Known and Unknown.** Known credentials are registered. Unknown ones match a key format but no registered value; the scanner cannot tell whose they are, so it only counts them. Registering a key that is still yours makes its past leaks Known.

- **How you resolve it.** A new value for a registered credential resolves its old leaks by itself: the scan compares each finding with the current value. `/cred edit <name>` with the value field does this in one step. `/cred rotated` opens a picker. `/cred rotated <name>` clears a credential's warnings without a new value. `/cred rotated <prefix>`, such as `sk-ant-`, clears every Unknown key of that format; a fingerprint clears one key; `/cred rotated all` clears everything. Each requires Touch ID. Clearing a registered credential also hides its old value when a later scan finds it as an Unknown key. A warning returns only when the scan finds the key in a session where it was not found before the mark.
- **Optional cleanup.** `/cred scrub` rewrites the matches in saved sessions to `[cred-scrubbed:name]` or `[cred:unknown-<prefix><fingerprint>]`. It requires Touch ID and refuses while a registered `api-key` or `app-password` credential cannot be read from the Keychain. It keeps each file's modification time, and skips the current session and sessions changed in the last 10 minutes. Scrubbing does not resolve a warning, because the key can still work; a new value or `/cred rotated` does.
- The warning and the scan never show the value. They show the credential name, or the key format's prefix only.

## Protection layers

| Layer | Strength |
|---|---|
| Keychain access list on each registered item | Enforced by macOS |
| Catalog and grants inside the helper's Keychain storage, changed only after Touch ID | Enforced by macOS |
| Helper and extension installed where the scope guard blocks agent writes | Enforced by Pi hooks |
| Command guard blocks `security -w`, `security -g`, `dump-keychain`, and `.env` reads | Soft: blocks direct routes only |
| Redaction of every tool result: each registered `api-key` and `app-password` of 8 or more characters becomes `[cred:name]` | Soft: backstop |
| Credentials removed from shell startup environment variables | Required for the boundary to mean anything |

## Limits

- Any process running as you can trigger a Keychain prompt. If you approve it by mistake, it gets the value.
- A program that reads a `.env` file, or receives a variable, can print the value in a transformed form, such as reversed or split, that redaction misses.
- A server that receives a key can log it.
- `cred_sudo` gives root to each approved command. Root can bypass every layer above.
- **Anything signed with the same identifier and team reads registered items without a dialog.** An agent with a shell can sign its own binary that way, or change this repository and rebuild. The startup build refuses uncommitted changes, but an agent that can commit to the installed clone, or put a program named `swift` on your `PATH`, can still get its code built and signed when you approve the build. Make your signing key ask before each use: run `security set-key-partition-list` without `codesign:` for that key, or keep the identity in a separate locked keychain.
- **Project scope is advisory against an agent that can run the helper.** The helper reads Git remotes from the directory it is given, and an agent can give it any directory. The command guard should block direct helper calls from the shell.
- Redaction finds the plain value, standard and URL-safe base64, percent-encoding of every character except `A-Z a-z 0-9 - . _ ~` (upper or lower case escapes, `+` for spaces), and JSON-escaped slashes. Other encoders, partial values, and transformed values get through.
- Redaction skips passwords, passcodes, and values under 8 characters. Otherwise anyone who can call `redact` could guess a short value by watching which guess gets redacted. The broker never prints those values and never writes them to `.env` files. They can still reach output through the app that `cred_type` types into, or a command that `cred_sudo` runs.
- `redact` and `request` list credentials that they could not read under `unavailable`. Output can still contain those values.

## Not included

- Per-use Touch ID.
- A general "run any command with credentials in its environment" action.
- Credential stores other than macOS Keychain.

## Agent tools

| Tool | Purpose |
|---|---|
| `cred_list` | Names, kinds, descriptions, hosts, and whether this project may use each credential |
| `cred_request` | An https request with a registered `api-key`. When the credential is not granted and you are present, Pi offers the grant. |
| `cred_type` | Types a registered `password` or `passcode` into a running app |
| `cred_sudo` | Runs one command as root with a registered `password`, after Touch ID shows the exact command |
| `cred_notarize` | Runs `xcrun notarytool` with a registered `app-password` |
| `cred_env` | Writes a `.env` file with the credentials granted to this project |
| `cred_ask` | Asks you to enter a new secret, which goes straight to Keychain |

When a credential is not granted and you are present, `cred_request`, `cred_type`, `cred_sudo`, and `cred_notarize` offer the grant. While one of them runs, the footer shows `🔑 <name>`.

The `read`, `edit`, and `grep` tools refuse `.env` and `.env.*` files, except `.example`, `.sample`, `.template`, and `.dist`, and Pi's `auth.json` and `mcp-auth.json`. The extension resolves the path as Pi does, also checks the trimmed form, follows symlinks, and ignores case. Before each `grep`, the extension lists the files that ripgrep would search with the same path, glob, and hidden-file settings as Pi, and the same ripgrep binary. The listing reads your ripgrep configuration, as Pi's `grep` does. It refuses the call when any listed file is protected, when the list takes longer than 10 seconds, or when ripgrep cannot list the path. The check skips a folder that ripgrep cannot read; Pi's `grep` cannot search it either. The command guard refuses the same reads in the shell.

Every tool result from a tool that runs, including its structured content and details, passes through `redact` before the model sees it or the session saves it. If redaction fails or takes more than 10 seconds, the extension withholds the output and returns an error. Output from shell commands that you run yourself with `!` is not a tool result, so it is not redacted. Neither are refusals that Pi returns before a tool runs, such as an unknown tool or invalid arguments. Progress that a tool streams while it runs is shown unredacted; only the final result is redacted.

## Helper

Build and sign the helper:

```zsh
./scripts/build.zsh
```

The script signs with your Developer ID identity when one exists. Set `PI_CREDENTIALS_SIGNING_IDENTITY` to choose another identity.

Each command reads one JSON object from standard input and writes one JSON object to standard output. An error is `{"error": {"code", "message"}}` with exit status 1.

| Command | Input | Touch ID |
|---|---|---|
| `list` | `cwd` | No; each credential includes `lastUse` |
| `register` | `name`, `service`, `kind`, `description`, optional `account`, `hosts`, `apps`, `rotation` | Yes |
| `add` | `name`, `value`, `kind`, `description`, optional `service` and metadata | Yes |
| `edit` | `name`, and the metadata or `value` to change | Yes |
| `grant`, `revoke` | `name`, `scope` | Yes |
| `group` | `name`, `patterns`; empty patterns remove the group | Yes |
| `delete` | `name`, optional `isValueDeleted` | Yes |
| `request` | `name`, `cwd`, `session`, `request` | No |
| `redact` | `text` | No |
| `notarize` | `name`, `cwd`, `arguments` | No |
| `sudo` | `name`, `cwd`, `arguments`, optional `timeoutSeconds` (default 600, at most 3600) | Yes, showing the command |
| `type` | `name`, `cwd`, `app`, optional `isActivating` (default true), `isReturnPressed` | No |
| `env` | `cwd`, optional `path` (default `.env`) and `names` | No |
| `scan` | optional `isFull` and `sessionDir` | No |
| `rotated` | `name`: `all`, a credential name, a key format such as `sk-ant-`, or a fingerprint | Yes |
| `scrub` | optional `exclude` (the current session file) | Yes |

`notarize` and `sudo` return the exit status, standard output, and standard error, redacted and truncated to 1 MB each. Every action checks the grant for the project in `cwd` and logs the use or the refusal.

`request` accepts `method`, `url`, `headers`, `body`, `authHeader` (default `Authorization`), `authPrefix` (default `Bearer `), and optional `outputFile`. It requires https, refuses redirects, and uses no cache or cookie store. Without `outputFile`, it redacts the response body and content type before truncating the body to 1 MB.

With `outputFile`, the helper streams the original response bytes to a new file, up to 100 MiB. Relative paths use the project directory; absolute paths are accepted. Parent directories must exist. Existing destinations, symlinks in any path component, and parent traversal (`..`) are refused. On macOS, use `/private/tmp` rather than its `/tmp` symlink. The file has mode `0600` and appears only after a complete successful HTTP response. HTTP errors, interrupted or oversized responses, unavailable credential checks, and responses containing registered credential forms or the active key are refused without publishing a file. The result contains only `status`, redacted `contentType`, `outputFile`, `byteCount`, and redaction metadata, never response bytes. No filename is inferred from server headers.

`cwd` is the project directory. The helper reads its Git remotes to find the project groups.

## License

MIT

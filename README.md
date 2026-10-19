# pi-credentials

A Pi extension that lets agents **use** your credentials without **seeing** them. You decide which credential works where, and you can always see why each one exists.

Status: the helper, `/cred list | add | register | edit | grant | revoke | group | delete`, `cred_list`, `cred_request`, `cred_ask`, and output redaction work. These parts of the design are not built yet: `cred_type`, `cred_sudo`, `cred_notarize`, `.env` creation, leak warnings with `/cred scan | rotated | scrub`, one-time values and `{{secret:…}}` handles, the input mask toggle, last use in `/cred list`, and the command guard rules.

## Install

Requires macOS, Swift 6.4 or newer, and Pi. Installing runs `scripts/build.zsh`, which builds and signs the helper.

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
- **Pi extension.** TypeScript. It provides the `/cred` command, the agent tools, and output redaction. It calls the helper and never caches values on disk.

## Catalog

Only credentials that you register appear. Each entry has:

| Field | Example |
|---|---|
| name | `openrouter` |
| description | `OpenRouter key for model calls and image generation` |
| kind | `api-key`, `password`, `app-password`, or `passcode` |
| Keychain item | The existing item's service name. The broker refers to it; it does not copy the value. |
| allowed hosts | Optional, `api-key` only. Empty means any host. `api.example.com` matches only that host; `*.example.com` matches it and every subdomain. |
| allowed apps | Optional, for typing. Empty means any app. |
| rotation link | Optional. The page where you replace this credential. |
| grants | `global`, or one or more project groups |

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
| `password` | `cred_sudo` | Runs one command through a sudo password helper. **Asks you to approve each exact command.** |
| `app-password` | `cred_notarize` | Runs `xcrun notarytool` with the password on standard input. |
| `passcode` | `cred_type` | Same as above. |
| any granted | `cred env create` | Writes a `.env` file with the credentials granted to this project. |
| — | `cred_ask` | Asks you for a new secret in an input box. See [Input](#input). |

`cred_type` takes a target app. It types into that app's window without focus when the app supports it, and checks focus first when the app needs focus. An allowed-apps list on the credential restricts targets further.

`.env` files: agents may create them but not read them. The read tool and command guard block direct reads. Programs that the agent runs can still read the file; see [Limits](#limits).

## Commands

```
/cred add | register | edit | grant | revoke | group | delete | list | scan | rotated | scrub
```

- Fuzzy Tab completion at each position, like `/model`: subcommand, then credential name with its description trimmed to the terminal width, then scope.
- `/cred list` opens a scrollable picker: name, kind, description, grants, last use.
- **Owner confirmation is required for add, register, edit, grant, revoke, group, and delete.** macOS asks for Touch ID, or your login password when Touch ID is unavailable. The prompt names the change, such as the old and new hosts, the group patterns, or the Keychain item to take over. Use needs no prompt.
- `/cred edit` changes metadata only: description, kind, hosts, apps, and rotation link. It never shows the value.

## Input

Two routes bring a new secret in. Neither shows the value to the model.

1. **You start it.** `/cred add <name>` opens an input box.
2. **The agent starts it.** `cred_ask(name, reason)` opens the same input box mid-task. If `pi-ask-user` is installed, its secure field does the same inside a richer prompt and hands the value to this package through Pi's in-process event bus.

The input shows text by default, with a mask toggle. You can use the value once or save it. A one-time value returns to the model as a session handle, such as `{{secret:3f9a}}`, that only broker actions accept. Saving requires Touch ID.

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

- **What it finds.** Registered values, including their base64 and URL-encoded forms, and well-known key formats, such as `sk-`, `sk-or-`, `lin_api_`, and `ghp_`. A match on a key format that is not registered offers to register the key, so it gets a name and a rotation link.
- **When it runs.** At Pi startup, on sessions saved since the last scan. `/cred scan` scans the full history.
- **How it warns.** Like Pi's notice for a Model Context Protocol server that needs a login, a warning stays visible until you resolve it:

```
⚠ 2 credentials leaked in chat history. Rotate them:
  openrouter  3 sessions, last 2026-10-12  → <rotation link>
  unknown sk-…  1 session, 2026-10-03      → /cred add to name it
```

- **How you resolve it.** `/cred rotated <name>` marks the credential as replaced. The old value can stay in transcripts, because it no longer works.
- **Optional cleanup.** `/cred scrub` rewrites the matches in saved transcripts to `[cred:name]`. It requires Touch ID, because it changes your history.
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
- **Anything signed with the same identifier and team reads registered items without a dialog.** An agent with a shell can sign its own binary that way, or change this repository and rebuild. Make your signing key ask before each use: run `security set-key-partition-list` without `codesign:` for that key, or keep the identity in a separate locked keychain.
- **Project scope is advisory against an agent that can run the helper.** The helper reads Git remotes from the directory it is given, and an agent can give it any directory. The command guard should block direct helper calls from the shell.
- Redaction finds the plain value, standard and URL-safe base64, percent-encoding of every character except `A-Z a-z 0-9 - . _ ~` (upper or lower case escapes, `+` for spaces), and JSON-escaped slashes. Other encoders, partial values, and transformed values get through.
- Redaction skips passwords, passcodes, and values under 8 characters. Otherwise anyone who can call `redact` could guess a short value by watching which guess gets redacted. The broker never prints those values, so they reach output only through a program that you approved.
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
| `cred_ask` | Asks you to enter a new secret, which goes straight to Keychain |

While `cred_request` runs, the footer shows `🔑 <name>`.

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
| `list` | `cwd` | No |
| `register` | `name`, `service`, `kind`, `description`, optional `account`, `hosts`, `apps`, `rotation` | Yes |
| `add` | `name`, `value`, `kind`, `description`, optional `service` and metadata | Yes |
| `edit` | `name` and the metadata to change | Yes |
| `grant`, `revoke` | `name`, `scope` | Yes |
| `group` | `name`, `patterns`; empty patterns remove the group | Yes |
| `delete` | `name`, optional `isValueDeleted` | Yes |
| `request` | `name`, `cwd`, `session`, `request` | No |
| `redact` | `text` | No |

`request` accepts `method`, `url`, `headers`, `body`, `authHeader` (default `Authorization`), and `authPrefix` (default `Bearer `). It requires https, refuses redirects, uses no cache or cookie store, and redacts the response body and content type before it truncates the body to 1 MB.

`cwd` is the project directory. The helper reads its Git remotes to find the project groups.

## License

MIT

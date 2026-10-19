# pi-credentials

Status: design. Nothing is built yet.

A Pi extension that lets agents **use** your credentials without **seeing** them. You decide which credential works where, and you can always see why each one exists.

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

- **Swift helper.** A signed binary that alone reads Keychain items silently, stores the catalog and grants, and runs Touch ID.
- **Pi extension.** TypeScript. It provides the `/cred` command, the agent tools, and output redaction. It calls the helper and never caches values on disk.

## Catalog

Only credentials that you register appear. Each entry has:

| Field | Example |
|---|---|
| name | `openrouter` |
| description | `OpenRouter key for model calls and image generation` |
| kind | `api-key`, `password`, `app-password`, or `passcode` |
| Keychain item | The existing item's service name. The broker refers to it; it does not copy the value. |
| allowed hosts | Optional, `api-key` only. Empty means any host. |
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
/cred add | edit | grant | revoke | delete | list | scan | rotated | scrub
```

- Fuzzy Tab completion at each position, like `/model`: subcommand, then credential name with its description trimmed to the terminal width, then scope.
- `/cred list` opens a scrollable picker: name, kind, description, grants, last use.
- **Touch ID is required for add, edit, grant, revoke, and delete.** Use needs no prompt.
- `/cred edit` changes metadata only: description, kind, hosts, apps. It never shows the value.

## Input

Two routes bring a new secret in. Neither shows the value to the model.

1. **You start it.** `/cred add <name>` opens an input box.
2. **The agent starts it.** `cred_ask(name, reason)` opens the same input box mid-task. If `pi-ask-user` is installed, its secure field does the same inside a richer prompt and hands the value to this package through Pi's in-process event bus.

The input shows text by default, with a mask toggle. You can use the value once or save it. A one-time value returns to the model as a session handle, such as `{{secret:3f9a}}`, that only broker actions accept. Saving requires Touch ID.

## Missing access

When a credential is not granted for the current project, the refusal gives the reason and the fix:

```
✗ 'tracker' is not granted for project group 'docs'.
  Grant it with: /cred grant tracker docs
```

In an interactive session, the agent offers the grant inline, and you confirm with Touch ID. In an unattended session, the agent records the block and moves to other work.

## Visibility

- The footer shows a marker, such as `🔑 openrouter`, while a credential is in use.
- `~/.pi/agent/cred/usage.jsonl` records each use: time, credential, action, target, project group, session ID, and result. Never the value. Keep it out of Git.

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
| Redaction of every tool result: each registered value, plus its base64 and URL-encoded forms, becomes `[cred:name]` | Soft: backstop |
| Credentials removed from shell startup environment variables | Required for the boundary to mean anything |

## Limits

- Any process running as you can trigger a Keychain prompt. If you approve it by mistake, it gets the value.
- A program that reads a `.env` file, or receives a variable, can print the value in a transformed form, such as reversed or split, that redaction misses.
- A server that receives a key can log it.
- `cred_sudo` gives root to each approved command. Root can bypass every layer above.

## Not included

- Per-use Touch ID.
- A general "run any command with credentials in its environment" action.
- Credential stores other than macOS Keychain.

## License

MIT

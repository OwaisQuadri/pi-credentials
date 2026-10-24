# pi-credentials

A Pi extension that lets agents **use** your credentials without **seeing** them. You decide which credential works where, and you can always see why each one exists.

Status: stable projects with `/project create | list | rename | inspect | membership`, the helper, `/cred list | add | register | edit | grant | revoke | group | delete | env`, the `cred env create` command, the agent tools `cred_list`, `cred_request`, `cred_type`, `cred_sudo`, `cred_notarize`, `cred_env`, and `cred_ask`, output redaction, the read block for `.env` and Pi auth files, leak warnings with `/cred scan | rotated | scrub`, last use in `/cred list`, and saving a `{{secret:…}}` handle from `pi-ask-user` work. One-time use of a handle without saving it is not built yet.

## Install

Requires macOS, Swift 6.4 or newer, and Pi. The package has no install script. After `pi install` or `pi update`, the helper is missing or out of date when Pi starts. The extension then runs `scripts/build.zsh` through [pi-compiled](https://github.com/OwaisQuadri/pi-compiled), which builds and signs it, and shows a progress bar above the editor. It does not ask first. Other extensions start while it builds; messages, tool calls, tool output, and `/cred` wait until the build finishes. It refuses to build unless the checkout is the fetched upstream commit, so install from a branch, not a pinned tag or commit. It also refuses when the helper source has uncommitted or ignored changes, when `.swiftpm` exists, or when the package is not its own Git checkout, and then tells you to run the script yourself. Each build starts from an empty build directory, so no leftover build files are linked in. To use a helper built elsewhere, set `PI_CREDENTIALS_HELPER` to its absolute path; the extension refuses a relative path or a file that is not executable.

```zsh
pi install git:https://github.com/OwaisQuadri/pi-credentials
```

Register a key that is already in Keychain. Create a project, approve this repository's membership, and grant the key:

```text
/cred register openrouter openrouter-api-key api-key
/project create Work tools
/project membership add <project-id>
/cred grant openrouter project:<project-id>
```

Use the identifier returned by `/project create` in place of `<project-id>`.

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
- **Pi extension.** TypeScript. It provides the `/cred` command, the agent tools, output redaction, and the read block. It calls the helper and never caches values on disk. At session start, it removes environment variables whose values match a registered `api-key` or `app-password` from the Pi process, so tools that Pi starts do not inherit them. When the helper is already built, this happens before the next extension starts. During a build, other extensions' startup code can run before the variables are removed; tool calls still wait for it.

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
| grants | `global`, `project:<identifier>`, or legacy remote group names |
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

- `global`: every repository, including directories outside Git.
- Project: a stable UUID with a readable name. A credential grant refers to `project:<identifier>`, not the name.
- Legacy remote group: a name, such as `work`, matched by Git remote patterns, such as `github.com/<org>/*`.

The helper stores project names and explicit repository membership in its Keychain catalog, outside repository control. Adding membership requires owner authentication because it gives access to the project's granted credentials. A repository can belong to several projects. Renaming a project leaves its identifier, membership, and grants unchanged. Names need not be unique; commands use the full identifier.

Repository identity is the canonical absolute Git common-directory path. Linked worktrees and symlinked paths share membership. A separate clone or copy at another path does not inherit project membership, even with identical remotes. Moving the common directory requires a new membership approval. Membership follows the path, not a cryptographic identity of its contents; replacing a repository at an approved path reuses that membership.

Removing membership stops only access derived from that project. It does not remove the project's credential grants or independent global, legacy-group, or other project access. `/cred revoke <credential> project:<identifier>` removes the credential's project grant instead.

Existing remote groups and their grants keep their behavior. They can independently authorize a clone with a matching remote. No command migrates patterns into projects or assigns membership automatically. Ticket labels, project names, repository files, and remote patterns never create project membership.

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
| — | `cred_ask` | Asks you for a new secret in an input box, or saves a `secret` handle from `ask_user_question`. See [Input](#input). |

`cred_type` takes a running app's bundle identifier or name. Exactly one running app must match, its bundle identifier must be in the credential's allowed apps, and its signature must chain to Apple for that identifier. A credential with no allowed apps is never typed. Allow only apps that do not save or show typed text, such as iPhone Mirroring or a password dialog; a terminal or text editor would let an agent read the value back. The helper sends each key to that app's process. By default it brings the app to the front first and stops if another app takes focus. With `isActivating: false` it types in the background, which works only in apps that accept background input. The helper needs Accessibility permission: System Settings > Privacy & Security > Accessibility.

Without `sshTarget`, `cred_sudo` runs one local argument list, not a shell string. The helper resolves a bare program name in `/usr/bin:/bin:/usr/sbin:/sbin` only. An absolute path must name a program that root owns, in directories that only root can change, so nobody can swap it after approval. Touch ID shows the resolved command in full each time, and the helper refuses a command too long to show. The helper gives the password to `sudo -v`, runs the command with `sudo -n` and an empty standard input, then clears the sudo timestamp. When you cancel the tool or the time limit passes, the helper uses the password again to send the command and its child processes a stop signal as root, then a kill signal 3 seconds later, and still clears the timestamp. A process that detaches from the command is not stopped. If the stop fails, the result says that the command may still be running. A cancel that arrives before the command starts stops it from starting. It needs a user present. With `timestamp_timeout=0` in sudoers, the second step fails with `sudo-no-timestamp`. With Touch ID for sudo (`pam_tid`), sudo can show its own Touch ID prompt during the first step, and during a stop after the sudo timestamp expires.

Supply optional `sshTarget` to run remotely, for example `cred_sudo({ name: "<password-name>", sshTarget: "<user>@<host>", command: ["/usr/bin/id"] })`. Replace the placeholders before use. A supplied target, even an empty one, selects the distinct `ssh-sudo` helper operation. Invalid targets refuse; older helpers require a rebuild and never fall back to local sudo. Targets support ASCII SSH aliases or hostnames with an optional username, up to 255 bytes. Ports belong in trusted SSH configuration; URLs, IPv6 literals, flags, whitespace and shell syntax are refused. Remote program paths must be absolute. Arguments are quoted as literal data across both remote shell boundaries.

Remote sudo requires an already enrolled known host and a usable public key that needs no interaction. Fixed SSH options refuse unknown or changed host keys, password and keyboard-interactive authentication, prompts, agent forwarding and connection sharing. Owner authentication (Touch ID or login-password confirmation) shows the credential, exact supplied destination, remote cwd `/`, and complete escaped argv. Approval text over 400 characters refuses rather than truncates. Local `cwd` selects project grants and the SSH process directory, never the remote directory. SSH aliases, configuration (including proxies and trust sources), login startup environment, single-quote-compatible login command parsing, `/bin/zsh`, `/usr/bin/sudo` and the approved remote program are trusted. This does not verify remote ownership or independently resolve the recipient shown for approval.

One persistent remote Z shell, started with `-f`, invalidates the sudo timestamp, sends the password only to `sudo -S -v`, then runs `sudo -n -- <argv>` with `/dev/null` stdin. Commands receive no leftover password input even when cached or NOPASSWD validation consumes none. Empty passwords and passwords containing NUL, CR or LF refuse. Invalidation and validation failures prevent execution; incompatible or zero-duration timestamp policy fails without weakening sudoers. The shell retains the same parent identity for validation and execution and attempts cleanup while preserving command status.

The remote timeout defaults to 600 seconds and clamps finite values to 1...3600. It includes SSH connection setup, validation and execution after launch, not owner approval or local termination/drain allowances. Timeout, cancellation, lost or malformed responses, and ambiguous SSH exits report that remote completion was not confirmed and privileged work may still be running. There is no automatic retry. Nonzero status is failure, not proof the command never began. Exit zero observes completion, not health, descendant termination or successful cleanup. Network loss, forced termination, detached descendants and delegated service jobs can leave work or timestamps alive. Cleanup and final auditing are best effort.

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
- `/cred grant <credential> project:<identifier>` grants a credential to an explicit project through the same owner confirmation as other grants. Tab completion shows project names beside their scopes.

### Projects

```text
/project create <readable name>
/project list
/project rename <identifier> <readable name>
/project inspect <identifier>
/project membership add <identifier> [repository directory]
/project membership remove <identifier> [repository directory or recorded identity]
```

Names and paths can contain spaces; they use the rest of the command without shell quoting. Membership defaults to the current directory. The helper resolves Git common-directory identity before approval. Removal also accepts the exact recorded identity from `/project inspect`, even when that directory no longer exists.

`list` shows identifiers and marks projects that include this repository. `inspect` shows the name, approved repository identities, and credential grants. Tab completes subcommands, membership operations, identifiers with names, and recorded identities for removal. Creation, rename, and membership changes require owner authentication. The membership prompt names the project, repository identity, and affected credentials. Creating a project gives it no repositories or grants.

The extension caches metadata only for completion. Each credential operation asks the Swift helper to check the current catalog and repository membership.

## Input

Three routes bring a new secret in. None shows the value to the model.

1. **You start it.** `/cred add <name>` opens an input box.
2. **The agent starts it.** `cred_ask(name, reason)` opens the same input box mid-task.
3. **The agent asks with `pi-ask-user`.** `ask_user_question` with `secure: true` shows the value by default, and Ctrl+T masks it. The model gets only a session handle, such as `{{secret:3f9a01bc}}`. `pi-ask-user` hands the value to this package through Pi's in-process event bus. `cred_ask` with `secret: <handle>` then saves it without asking again. Saving requires Touch ID and uses up the handle. Handles last until Pi exits.

## Missing access

When a credential is not granted for the current project, the refusal gives the reason and the fix:

```
'tracker' is not granted for this project. Ask the user to run: /cred grant tracker docs
```

For an approved project, the fix uses `/cred grant tracker project:<identifier>`. Existing matching remote groups still produce a group grant suggestion. When neither applies, the fix offers a global grant or a remote group. To use explicit membership instead, create a project and approve the repository first.

In an interactive session, the agent offers the grant inline, and you confirm with Touch ID. In an unattended session, the agent records the block and moves to other work.

## Visibility

- The footer shows a marker, such as `🔑 openrouter`, while a credential is in use.
- `~/.pi/agent/cred/usage.jsonl` records each use and each refusal: time, credential, action, target, legacy project groups, stable project identifiers, session ID, and result. Never the value. Keep it out of Git.

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
- **Pi sign-in is not a leak.** Keys that Pi saved from `/login` in `auth.json` or from `/mcp` in `mcp-auth.json` are not counted and do not cause the warning. Redaction and `/cred scrub` still replace them.

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
| Redaction of your messages, tool call arguments, and tool results with the `/cred scrub` policy: each registered `api-key` and `app-password` of 8 or more characters becomes `[cred:name]`, and an unregistered key format becomes `[cred:unknown-<prefix><fingerprint>]` | Soft: backstop |
| Credentials removed from shell startup environment variables | Required for the boundary to mean anything |

## In-process redaction service v1

Trusted extensions can discover a narrow runtime capability on `pi-credentials:redaction-service:v1`. This is not an agent tool or a generic helper dispatcher. Discovery carries **no source text**. The provider calls `provide` synchronously during `emit`, retains no callback, and ignores malformed, cancelled, or unloaded discovery requests. The request has exactly three fields:

```ts
const providers: CredentialRedactionServiceV1[] = [];
const discovery = new AbortController();
const discoveryTimer = setTimeout(() => discovery.abort(), 1_000);
try {
  pi.events.emit("pi-credentials:redaction-service:v1", {
    version: 1,
    signal: discovery.signal,
    provide(service: CredentialRedactionServiceV1) {
      providers.push(service);
    },
  });
} finally {
  clearTimeout(discoveryTimer);
  discovery.abort();
}
```

Consumers must reject missing or duplicate providers, check `version === 1`, and impose a discovery deadline of at most 1,000 ms. The callback is synchronous; do not await `emit` or accept later callbacks. A timer cannot preempt blocking JavaScript, so consumers must also reject discovery that returns after their deadline. Keep source pieces off the shared event bus; invoke the selected capability directly with a caller-owned `AbortSignal`.

The exported TypeScript contracts live in `extension/redaction-service.ts`:

```ts
interface CredentialRedactionServiceV1 {
  readonly version: 1;
  redact(
    request: { version: 1; requestID: string; pieces: readonly string[] },
    options: { signal: AbortSignal }
  ): Promise<
    | { status: "checked"; requestID: string; policy: "pi-credentials/redact-v1"; pieces: string[] }
    | { status: "blocked"; requestID: string; code:
        | "not-ready" | "unavailable" | "timeout" | "cancelled"
        | "invalid-input" | "invalid-output" | "failed" }
  >;
}
```

`requestID` is a non-content correlation identifier: 1–128 ASCII letters, digits, `.`, `_`, `:`, or `-`, starting with a letter or digit. Invalid identifiers return `requestID: ""` and `invalid-input`; other results echo the valid identifier. Consumers must verify the matching identifier, exact policy, returned piece count and shape before using a checked result. `checked` explicitly acknowledges unchanged text too; an absent result is never success.

| Bound | Limit |
|---|---|
| Input pieces | 1,000, including empty pieces |
| Each input piece | 1,048,576 UTF-8 bytes |
| Total input | 4,194,304 UTF-8 bytes |
| Total output | 8,388,608 UTF-8 bytes |
| Service deadline | 10,000 ms, including startup readiness and redaction |

Inputs and outputs must be arrays of strings with well-formed Unicode and the same piece count. Oversized inputs are refused, never clipped. Piece boundaries are preserved, not joined to detect secrets split across pieces. Requests snapshot caller input before waiting. Failed or missing startup returns `not-ready`; the initial resolved foreground-hook promise is not proof of startup. Pending startup must finish successfully within the service deadline. Any unavailable credential blocks the entire result, even if the text appears unchanged. Blocked results contain only status, correlation identifier, and a fixed code; service failures never include input, partial output, helper diagnostics, or arbitrary exception text, and the service does not log them.

Cancellation, deadline expiry, startup reinitialization, and `session_shutdown` revoke pending work; late completions cannot become checked results. Retained capabilities from a shutdown session remain blocked. Discover again after the next session starts or the extension reloads. Caller cancellation aborts the runtime redactor as well, but does not itself stop credential startup shared with foreground hooks.

This service reuses the existing private redactor and `pi-credentials/redact-v1` policy: registered `api-key` and `app-password` values of at least eight characters, their supported encoded forms, and recognized unknown key formats. It does not add credential grants, expose values, rewrite archives or memories, or admit protected-file bodies. Passwords, passcodes, short values, unrecognized formats, arbitrary transformations, and visual or split secrets remain outside that policy. Protected-source omission and provenance checks are still required. A policy identifier is not cryptographic proof, and the shared bus does not authenticate providers or isolate malicious installed extension code. Use trusted installation assumptions.

The service alone does not protect native frozen input, queue evidence, or model dispatch. Consumers own pre-admission integration, source authority, missing/duplicate-provider refusal, and their persistence boundary. Do not use fabricated tool events, archive scrub flags, or direct helper imports as a substitute.

## Limits

- Any process running as you can trigger a Keychain prompt. If you approve it by mistake, it gets the value.
- A program that reads a `.env` file, or receives a variable, can print the value in a transformed form, such as reversed or split, that redaction misses.
- A server that receives a key can log it.
- `cred_sudo` gives root to each approved command. Root can bypass every layer above.
- **Anything signed with the same identifier and team reads registered items without a dialog.** An agent with a shell can sign its own binary that way, or change this repository and rebuild. The startup build runs without asking. It refuses uncommitted changes and any commit other than the fetched upstream one, but an agent that can commit to the installed clone and also move its upstream-tracking ref, or put a program named `swift` on your `PATH`, can still get its code built and signed. The build checks come from pi-compiled's latest `main`, so anyone who can push to that repository can also change what gets built. Make your signing key ask before each use: run `security set-key-partition-list` without `codesign:` for that key, or keep the identity in a separate locked keychain.
- **Project scope is advisory against an agent that can run the helper.** The helper resolves membership and legacy remote groups from the directory it receives. An agent can give it another directory. Explicit membership does not fix this cwd spoofing limitation. The command guard should block direct helper calls from the shell.
- Redaction finds the plain value, standard and URL-safe base64, percent-encoding of every character except `A-Z a-z 0-9 - . _ ~` (upper or lower case escapes, `+` for spaces), and JSON-escaped slashes. Other encoders, partial values, and transformed values get through.
- Redaction checks text only. A credential shown inside an image, in your message or in a tool result, reaches the model.
- Global redaction skips passwords, passcodes, and values under 8 characters. Otherwise anyone who can call `redact` could guess a short value by watching which guess gets redacted. The broker never prints those values and never writes them to `.env` files. Remote sudo additionally redacts known plain and encoded forms of its active password, including short values, only for that action. Arbitrary transformations can still evade redaction. Values can still reach output through the app that `cred_type` types into, or a command that `cred_sudo` runs.
- `redact` and `request` list credentials that they could not read under `unavailable`. The extension then withholds the tool result, holds back your message, or blocks the tool call. Output from a direct helper call outside Pi can still contain those values.

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
| `cred_sudo` | Runs one command as root with a registered `password`, locally or with optional `sshTarget`, after owner authentication shows the exact command and destination |
| `cred_notarize` | Runs `xcrun notarytool` with a registered `app-password` |
| `cred_env` | Writes a `.env` file with the credentials granted to this project |
| `cred_ask` | Asks you to enter a new secret, or saves a `secret` handle from `ask_user_question`; the value goes straight to Keychain |

When a credential is not granted and you are present, `cred_request`, `cred_type`, `cred_sudo`, and `cred_notarize` offer the grant. While one of them runs, the footer shows `🔑 <name>`.

The `read`, `edit`, and `grep` tools refuse `.env` and `.env.*` files, except `.example`, `.sample`, `.template`, and `.dist`, and Pi's `auth.json` and `mcp-auth.json`. The extension resolves the path as Pi does, also checks the trimmed form, follows symlinks, and ignores case. Before each `grep`, the extension lists the files that ripgrep would search with the same path, glob, and hidden-file settings as Pi, and the same ripgrep binary. The listing reads your ripgrep configuration, as Pi's `grep` does. It refuses the call when any listed file is protected, when the list takes longer than 10 seconds, or when ripgrep cannot list the path. The check skips a folder that ripgrep cannot read; Pi's `grep` cannot search it either. The command guard refuses the same reads in the shell.

Every tool result from a tool that runs, including its structured content and details, passes through `redact` before the model sees it or the session saves it. If redaction fails or takes more than 10 seconds, the extension withholds the output and returns an error. Your messages and the arguments of each tool call pass through `redact` too. If that fails, or a registered credential cannot be read from the Keychain, the extension withholds the tool result, does not send the message, or blocks the call. `redact` and `/cred scrub` use one policy: the same registered values and the same key formats. Output from shell commands that you run yourself with `!` is not a tool result, so it is not redacted. Neither are refusals that Pi returns before a tool runs, such as an unknown tool or invalid arguments. Progress that a tool streams while it runs is shown unredacted; only the final result is redacted.

## Helper

Build and sign the helper:

```zsh
./scripts/build.zsh
```

The script signs with your Developer ID identity when one exists. Set `PI_CREDENTIALS_SIGNING_IDENTITY` to choose another identity.

Each command reads one JSON object from standard input and writes one JSON object to standard output. An error is `{"error": {"code", "message"}}` with exit status 1.

| Command | Input | Touch ID |
|---|---|---|
| `list` | `cwd` | No; returns credentials with `lastUse`, legacy groups, projects, current `projectIDs`, and optional repository identity |
| `register` | `name`, `service`, `kind`, `description`, optional `account`, `hosts`, `apps`, `rotation` | Yes |
| `add` | `name`, `value`, `kind`, `description`, optional `service` and metadata | Yes |
| `edit` | `name`, and the metadata or `value` to change | Yes |
| `grant`, `revoke` | `name`, `scope` (`global`, legacy group, or `project:<identifier>`) | Yes |
| `project-create` | `name` | Yes |
| `project-rename` | `project` (identifier), `name` | Yes |
| `project-membership` | `project`, `operation` (`add` or `remove`), `cwd`, optional `path` | Yes |
| `group` | `name`, `patterns`; empty patterns remove the group | Yes |
| `delete` | `name`, optional `isValueDeleted` | Yes |
| `request` | `name`, `cwd`, `session`, `request` | No |
| `redact` | `text` | No |
| `notarize` | `name`, `cwd`, `arguments` | No |
| `sudo` | `name`, `cwd`, `arguments`, optional `timeoutSeconds` (default 600, at most 3600) | Yes, showing the command |
| `ssh-sudo` | `name`, `cwd`, `sshTarget`, `arguments`, optional finite `timeoutSeconds` (default 600, clamped to 1...3600) | Yes, showing credential, literal destination, remote cwd and complete argv |
| `type` | `name`, `cwd`, `app`, optional `isActivating` (default true), `isReturnPressed` | No |
| `env` | `cwd`, optional `path` (default `.env`) and `names` | No |
| `scan` | optional `isFull` and `sessionDir` | No |
| `rotated` | `name`: `all`, a credential name, a key format such as `sk-ant-`, or a fingerprint | Yes |
| `scrub` | optional `exclude` (the current session file) | Yes |

`notarize`, `sudo`, and `ssh-sudo` return the exit status, standard output, and standard error, redacted before truncation to 1 MB each. Every action checks the grant for the project in `cwd` and logs the use or the refusal.

`request` accepts `method`, `url`, `headers`, `body`, `authHeader` (default `Authorization`), `authPrefix` (default `Bearer `), and optional `outputFile`. It requires https, refuses redirects, and uses no cache or cookie store. Without `outputFile`, it redacts the response body and content type before truncating the body to 1 MB.

With `outputFile`, the helper streams the original response bytes to a new file, up to 100 MiB. Relative paths use the project directory; absolute paths are accepted. Parent directories must exist. Existing destinations, symlinks in any path component, and parent traversal (`..`) are refused. On macOS, use `/private/tmp` rather than its `/tmp` symlink. The file has mode `0600` and appears only after a complete successful HTTP response. HTTP errors, interrupted or oversized responses, unavailable credential checks, and responses containing registered credential forms or the active key are refused without publishing a file. The result contains only `status`, redacted `contentType`, `outputFile`, `byteCount`, and redaction metadata, never response bytes. No filename is inferred from server headers.

`cwd` is the repository directory. The helper resolves its canonical Git common directory for explicit membership and reads its remotes for legacy groups. `list.projects` maps identifiers to records with `name` and `repositories`. `list.projectIDs` contains the projects that include the current repository. `list.repository` is absent outside Git. The three project mutation commands return the affected identifier in `project`.

## License

MIT

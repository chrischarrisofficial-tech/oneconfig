# Security policy

OneConfig logs into network devices and changes their configuration, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Report it privately through GitHub: on this repository's **Security** tab, choose **Report a vulnerability**. Please don't open a public issue, pull request or discussion for a security problem.

Include what you can of:

- what an attacker can do, and what they need first (access to the same computer, the same network, a device OneConfig talks to, a file someone opens)
- the steps or a proof of concept
- the OneConfig version or commit, your operating system, and the device OS involved, if any

You'll get a reply once the report has been read, and credit in the fix's release notes if you'd like it.

Only test against devices and networks you own or are allowed to test. Don't run proofs of concept against production equipment.

## Supported versions

Fixes go into the latest release and the `main` branch only.

## What's in scope

- **The local server and page:** anything that lets another website, another program or another account on the same computer use OneConfig, read what it holds, or run script in its page.
- **Secrets:** device logins, keys and API keys leaking into files, logs, the browser, the Advisor prompt or a backup.
- **Generated and pushed configs:** a value that turns into extra commands on a device, or a push that skips its plan, its rollback or its checks.
- **Device input:** output from a device, a discovered neighbor or an opened network file that crashes or stalls OneConfig, or does something worse.
- **Accounts, the audit trail and encrypted backups:** getting around a role, changing the audit log without it showing, or reading a backup without its key.
- **The Mac app**, as built from `packaging/OneConfig.spec`.

## What's out of scope

- Anything that needs the attacker to already control your user account on the computer running OneConfig. That account holds the keychain and the launch key, so it can do whatever OneConfig can.
- Weaknesses in the network devices themselves (report those to their vendor), and STIG findings OneConfig reports about a device.
- Problems in third-party packages that OneConfig doesn't make reachable. Do tell us if one is reachable.

## How OneConfig protects itself

This describes the intended design, so a report can say which part it breaks.

- The server listens on 127.0.0.1 only, rejects other `Host` and `Origin` headers, and needs a random key made at each launch. The key is handed over in the URL fragment and dropped from the address bar.
- The page runs under a Content Security Policy that allows only its own script file.
- With accounts set up, every request needs a signed-in session, and the server checks the role (viewer, operator, admin).
- Device logins, keys and API keys live in the OS keychain, never in OneConfig's files. Backups are encrypted with a key from the keychain.
- State in `~/.oneconfig` is readable by the user's account only. The audit trail is a hash chain signed with a keychain key.
- Pushes run under each device's own rollback timer where it has one, after a plan that checks for lockouts. SSH host keys are trusted on first contact and checked from then on.

# Harbinger

Harbinger is a Go command-line tool that checks local TCP listeners against processes managed by [Ace](https://github.com/Abiral-Karmacharya/Ace). It scans a configured port range, identifies listening processes with `lsof`, and runs [Jester](https://github.com/Abiral-Karmacharya/Jester) to evaluate Lua policies. Ace handles managed projects; Harbinger can terminate remaining listeners with `SIGTERM` or `SIGKILL`.

Each invocation performs one scan and exits. There is no background service or built-in scheduler.

## Requirements

- Linux with a readable `/proc` filesystem and `lsof`.
- Go 1.27.0 or newer, as declared in [go.mod](go.mod).
- Jester and a Lua interpreter supporting `goto` (Lua 5.2 or newer syntax; checked with Lua 5.5.1).
- Lua modules `dkjson`, `socket.http`, and `ltn12`. Jester also needs `logging.rolling_file` when its logging is enabled. See [Jester's installation guide](https://github.com/Abiral-Karmacharya/Jester#installation).
- Ace's Node API and Marshal process helper running on the same machine, or an API implementing the same contract.
- Permission to inspect the target processes, write the configured files, and signal processes selected by the policy.

The Go dependency is `github.com/BurntSushi/toml`; Go resolves it from the module files.

## Installation and build

```sh
git clone --branch github https://github.com/Abiral-Karmacharya/Harbinger.git harbinger
git clone --branch github https://github.com/Abiral-Karmacharya/Jester.git jester
cd harbinger
go mod download
go build -o port .
cp harbinger.toml.example harbinger.toml
```

Edit `harbinger.toml` before running. For these sibling checkouts, change the three Jester paths to:

```toml
# Inside the existing [paths] table:
script = "../jester/script.lua"
bootstrap = "../jester/bootstrap.lua"
policy = "../jester/policy.lua"
```

Relative paths resolve from the process's working directory, **not** from the TOML file's directory. Absolute paths are useful when launching from another application.

Set `node.url` to Ace's `/api/lua` endpoint. The example uses port `3178`; Ace's source defaults to `3179` unless `PORT` is set. Create the parent directories for all enabled log files and exchange files, and make them writable by the account running Harbinger. The program does not create those directories.

Review Jester's policy before the first run: its supplied default action is `destroy`. For an initial run that skips enforcement, point `paths.policy` at a separate Lua file containing only:

```lua
Default { action = "permit" }
```

This bypasses policy enforcement; it is not a dry-run report of what a restrictive policy would do.

## Usage

From the Harbinger directory, after configuring the paths, API, and policy:

```sh
./port -h
./port
./port -config /path/to/harbinger.toml
```

`-config` is the only application flag. It defaults to `harbinger.toml` in the working directory. A missing or invalid configuration causes startup to fail. There are no port, policy-action, or logging flags; those settings belong in the TOML file or Lua policy.

## Configuration

Use [harbinger.toml.example](harbinger.toml.example) as the complete template.

| Table | Settings |
| --- | --- |
| `scan` | Target IP, TCP connection timeout in milliseconds, inclusive port range, worker count. |
| `paths` | JSON exchange files, Jester script, bootstrap, policy, and `/proc` location. |
| `commands` | Lua and `lsof` executable names or paths. |
| `node` | API URL used for both GET and POST requests. |
| `logging` | Global switch for Harbinger and Jester. |
| `logging.scan`, `.config`, `.node`, `.danger`, `.kill` | Individual Harbinger log switches and paths. |
| `logging.jester` | Jester's log switch, path, maximum file size in bytes, and backup count. |

The scan range must be within `1–65535`; the worker count must be positive and no greater than the number of ports. The timeout must be positive. Keep `scan.ip` local: process lookup and signaling always operate on the local machine.

Set `enabled = false` in the existing `[logging]` table to disable file logging in both programs. Individual log tables can also be disabled. This does **not** disable enforcement. Harbinger writes JSON logs without built-in rotation; Jester uses a rolling log. Startup errors can still appear on stderr.

## Architecture

1. Go workers attempt TCP connections and use `lsof` to map reachable ports to listening PIDs. A concurrent GET to Ace retrieves its port-to-supervisor-PID map.
2. Harbinger writes both results to `paths.port_data`, then launches Jester with the decoded TOML settings in the `JESTER_CONFIG` environment variable.
3. Jester resolves policies and compares each non-permitted listener's immediate parent PID with Ace's reported PID. It posts mismatches to Ace, which attempts to stop matching managed projects.
4. Jester writes actions for ports Ace reports as uncontrolled to `paths.lua_data`. Harbinger reads that file, looks up the current listener again, and sends `SIGTERM` for `kill` or `SIGKILL` for `destroy`.

Jester consumes the input exchange file; Harbinger consumes the output file. Policy syntax and API payloads are documented in [Jester](https://github.com/Abiral-Karmacharya/Jester).

## Limitations and security

- This checks TCP listeners only. It is not a firewall, a remote process manager, or a complete process inventory.
- Parent-PID comparison assumes one supervisor/child relationship. Directly launched processes, deeper process trees, multiple listening PIDs, or ports reported only by Ace can produce incorrect results or Lua errors.
- Scanning and enforcement are separate steps. A process can exit or a port can change owners between them. Missing API data can skip comparison, and a successful exit does not guarantee that every action succeeded. The Go HTTP request has no explicit timeout.
- **There is no dry-run mode.** Jester's `log` action still reaches Ace's POST handler, which stops matching managed projects without checking the action value. Harbinger does not implement `log` for uncontrolled ports and records it as an unknown action when logging is enabled.
- Lua policies and configured executables run with the caller's privileges. Use trusted files and the least privileges needed; do not run as root merely to work around log-directory permissions.
- Use a trusted local API and private, separate exchange-file paths for each run. Files are not locked or written atomically; overlapping runs, stale output, or tampered files can affect enforcement. The example's fixed `/tmp` filenames are not suitable for shared, untrusted use.
- Ace's current stop handler invokes an installation-specific Harbinger binary path without `-config`. Running Harbinger manually works independently of that hook; the hook needs separate integration work for another installation.

## Development checks

```sh
go build -o port .
go test ./...
go vet ./...
```

Build, help output, and vet were checked locally. The repository currently contains no Go test files; `go test` checks compilation but does not exercise enforcement.

## Why I Built This

<!-- Add your personal motivation and background here. -->

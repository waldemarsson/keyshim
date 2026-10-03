# Fullmakt

A local HTTP proxy that adds secrets to outgoing HTTPS requests, so coding
agents in sandboxes, devcontainers and VMs can use APIs without ever holding
the credentials.

*Fullmakt* is Swedish for power of attorney: the agent acts with your
authority without holding it.

```text
 sandbox / VM                           host
┌────────────────────────┐ HTTPS_PROXY ┌────────────────────────┐     ┌────────────────┐
│ agent                  │ ──────────► │ fullmakt               │ ──► │ api.github.com │
│ GH_TOKEN=proxy-managed │             │ + Authorization:       │     └────────────────┘
└────────────────────────┘             │   Bearer <real token>  │
                                       │ secrets: local file,   │
                                       │ Azure Key Vault        │
                                       └────────────────────────┘
```

## Security model

Guarantees, when fullmakt runs outside the sandbox (on the host or in a
separate VM or container):

- **The agent cannot read secret values.** They exist only in fullmakt's
  memory and the vault.
- **Secrets are only sent to the hosts, methods and paths in the rules**, and
  only over TLS that fullmakt verifies.
- **Secrets are only injected into headers**, never into bodies or URLs.
- **Only known clients can use the proxy.** Each sandbox authenticates with
  its own name and token (`HTTPS_PROXY=http://<name>:<token>@host:port`);
  everything else gets 407. Listening on loopback alone is not enough: other
  processes, users, VMs and containers on the host can reach it too.

Not guaranteed:

- **The agent can still use the secrets** for any request the rules allow.
  Keep tokens narrowly scoped and rules tight.
- **No egress firewall.** Clients that ignore `HTTPS_PROXY` reach the internet
  directly. Their requests simply carry no secrets.
- **Run fullmakt as your user, not root.** Anyone with your user's access to
  the host can read the CA key, the local secrets file and the process memory.
- **Derived credentials are not redacted.** If an API exchanges the injected
  token for another token in the response body, the client receives that one.
- **Redaction is a backstop, not a guarantee.** Injected values are replaced
  with `[REDACTED]` when they appear verbatim in response headers or bodies.
  An endpoint that stores a header and returns it in pieces or transformed
  gets past that. Only write rules for APIs that do not reflect
  authentication headers.
- **Protocol upgrades (WebSockets) and `TRACE` cannot receive secrets.** They
  are rejected with 403. `Range` headers are removed from injected requests,
  so stored values cannot be fetched in pieces.
- **Trust the CA only inside sandboxes.** Never add it to the host's trust
  store: whoever holds the CA key could then intercept the host's HTTPS.

Request handling details:

- A CONNECT to a host named by a rule is intercepted with a leaf certificate
  from fullmakt's CA. All other hosts are tunneled untouched.
- Inside an intercepted connection, the `Host` header must match the CONNECT
  target (421 otherwise). This stops a shared CDN or load balancer from
  routing a secret to another tenant.
- Path rules refuse dot segments, encoded `/`, `\` and `.`, `//` and double
  encoding, so a server's path normalization cannot widen a rule.
- Wildcards cannot cover a public suffix where anyone can register names
  (`*.s3.amazonaws.com`, `*.github.io`, `*.azurewebsites.net`, `*.co.uk`;
  checked against the Public Suffix List). A wildcard only matches hosts in
  the same registrable domain as the rule, so `*.amazonaws.com` does not
  match `bucket.s3.amazonaws.com`.
- `config.yaml` and `key.json` are refused when group or others can write
  them, since they decide where secrets go. `FULLMAKT_PASSPHRASE` is removed
  from the environment after it is read, so child processes such as `az` do
  not inherit it. The environment the process started with stays readable to
  other processes running as the same user (`/proc/<pid>/environ`, `ps eww`);
  prefer the terminal prompt where possible.
- Header values that would contain control characters are rejected, which
  prevents header injection from a malformed secret.
- On injected requests, fullmakt negotiates gzip itself and decodes it, so
  the body can be redacted. Responses with any other encoding fail with 502.
- The audit log records host, method, path (without query), rule, secret
  names and status. Never values.
- Proxy clients cannot reach loopback, link-local or unspecified addresses
  (403). Without this, a client could use the proxy to reach services on
  fullmakt's host, including the UI and cloud metadata endpoints. The check
  runs on the resolved IP, so DNS names that point at loopback are caught
  too. Set `allowLoopbackTargets: true` to turn it off.

## Data at rest

| File | Content | Protection |
|---|---|---|
| `config.yaml` | providers, secret names, rules | none needed: no values |
| `key.json` | key ID, KDF parameters, check value | none needed: reveals nothing about the key |
| local secrets file (`secrets.enc`) | names, values, added times | AES-256-GCM with the master key |
| `ca/ca.key` | CA private key | AES-256-GCM with the master key |
| `ca/ca.crt` | CA certificate | public |

Each file has its own key derived from the master key (HKDF). The key ID
and purpose are authenticated, so encrypted files cannot be swapped for each
other, and changes to them are detected. A plaintext CA key from an earlier
version is encrypted automatically on first start. Plaintext secrets files
are refused; load them with `fullmakt secrets import <file>`.

The master key comes from `encryption.key` in the configuration:

- **`keychain`** (default): a random key in the OS keychain (macOS
  Keychain, Windows Credential Manager, Linux Secret Service). Fullmakt
  restarts without prompting while you are logged in. Any process running as
  your user can read it; agents in a VM or container cannot.
- **`passphrase`**: derived with Argon2id from a passphrase of at least 12
  characters, read from `FULLMAKT_PASSPHRASE` or asked for in the terminal on
  every start. Use it where no keychain exists, such as headless Linux.

Local values are write-only. The UI and CLI list names and added times, and
values can be added or deleted, never shown or changed. To replace a value,
delete it and add it again.

### Backup and restore

- **Back up anywhere:** `config.yaml`, `key.json`, `secrets.enc`, `ca/`.
  Without the master key they are useless.
- **Keep in a password manager:** `fullmakt key export` prints a recovery
  code (keychain mode). With a passphrase, the passphrase is the recovery.
- **Restore:** copy the files to the new machine and run `fullmakt key import`
  (keychain mode).

## Web UI

`fullmakt run` also serves a management UI on `127.0.0.1:8900` and prints a
single-use login URL:

- **Activity:** live log of connections and requests, with rule and secret
  names.
- **Secrets:** map names to provider values, check that they resolve, and
  set local values.
- **Rules:** host, methods, paths and headers, with templates for Bearer,
  Basic and raw values.
- **Providers:** local files and Key Vaults.
- **Setup:** CA download, proxy clients (token shown once) and client
  environment variables.

Changes are validated, written to the config file and applied without a
restart. Requests already in progress finish with the previous rules.
Comments in the config file are not preserved when the UI saves it.

UI security:

- **Session required, without cookies.** A VM may be able to reach the
  host's loopback, so every API call needs a session token, sent as a bearer
  header. The page keeps it in `localStorage`, which is scoped to the exact
  origin including the port. Cookies are avoided on purpose: browsers send
  them to every port on `127.0.0.1`, including ports Lima forwards from the
  VM, where the agent could collect them.
- **Single-use login.** The login URL carries a random 256-bit token in the
  fragment, so it never reaches the server in a request line or log. It
  works once; after each login fullmakt prints a new URL. Sessions expire
  after 12 hours, and Sign out ends one immediately.
- **Strict request checks.** Requests are rejected unless the `Host` header
  names the UI listener, which blocks DNS rebinding. Changes also need a
  same-origin `Origin` header and a custom request header. The page sets a
  strict Content-Security-Policy and renders all data as text.
- **Secret values are write-only.** The UI and API never return them.

Set `ui.disabled: true` to run without the UI.

## Build

Requires Go 1.27+.

```bash
go build -o fullmakt ./cmd/fullmakt
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o fullmakt-darwin-arm64 ./cmd/fullmakt
go test -race ./...
```

## Use

```bash
mkdir -p ~/.config/fullmakt && chmod 700 ~/.config/fullmakt
cp config.example.yaml ~/.config/fullmakt/config.yaml
fullmakt client add agentbox  # proxy credentials for the sandbox, shown once
fullmakt secrets add github   # asks for the value without echo; or pipe it in
fullmakt check -resolve       # validate config and fetch every secret (values are never printed)
fullmakt ca > fullmakt-ca.pem # public CA certificate for the client
fullmakt run
```

For Azure Key Vault, sign in with `az login` (or use managed or workload
identity). The identity needs the *Key Vault Secrets User* role on the vault.

### Client setup

Create a client for each sandbox (or use Setup in the UI):

```bash
fullmakt client add agentbox   # prints the token once
```

In the sandbox, set the proxy with the client's credentials and trust the CA:

```bash
export HTTPS_PROXY=http://agentbox:<token>@<fullmakt-host>:8899
export HTTP_PROXY=http://agentbox:<token>@<fullmakt-host>:8899
export NO_PROXY=localhost,127.0.0.1

# Ubuntu system store inside the sandbox; covers curl, git, gh, Go and most CLIs.
sudo cp fullmakt-ca.pem /usr/local/share/ca-certificates/fullmakt.crt
sudo update-ca-certificates

# Runtimes with their own trust stores.
export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/fullmakt.crt
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt   # Python requests
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
```

#### Placeholder credentials

Set every credential in the client to the same placeholder, `proxy-managed`:

```bash
export GH_TOKEN=proxy-managed
export OPENAI_API_KEY=proxy-managed
```

The placeholder only keeps tools from refusing to start. Rules choose the
secret by host, method and path, and overwrite the header whatever the
client sent. Requests that no rule matches carry the placeholder upstream
and fail authentication, so nothing secret leaks.

### Lima

Run fullmakt on the Mac and point the VM at `host.lima.internal`. Lima's
user-mode network is expected to forward that address to the Mac's
loopback; this is not yet verified.

Lima also forwards ports that the VM listens on to the Mac's `127.0.0.1`.
Exclude fullmakt's ports, so the agent cannot occupy them while fullmakt is
stopped and serve a fake UI:

```yaml
portForwards:
  - guestPort: 8899
    ignore: true
  - guestPort: 8900
    ignore: true
```

## Configuration

See [`config.example.yaml`](config.example.yaml).

| Template | Result |
|---|---|
| `{{ secret "name" }}` | the secret value |
| `{{ basic "user" (secret "name") }}` | `Basic base64(user:value)` |

The first matching rule wins. Hosts take an optional `:port` (default 443),
and `*.example.com` matches subdomains only.

Set `clients: [agentbox, ci]` on a rule to inject its secrets only for those
proxy clients; other clients' requests to the host pass through untouched
and are tunneled unless another rule applies to them. Without `clients`, a
rule applies to every client. A client can be a whole sandbox or a single
tool that you give its own proxy credentials.

Set `disabled: true` on a rule to pause it, or use Pause in the UI. A
paused rule is still validated but never matches. Its requests pass through
with the client's placeholder, and its host is tunneled unless another rule
covers it.

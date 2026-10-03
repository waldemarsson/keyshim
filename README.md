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
- **Echoes are redacted.** Injected values are replaced with `[REDACTED]` in
  response headers and bodies, so an endpoint that echoes request headers
  cannot reveal them.

Not guaranteed:

- **The agent can still use the secrets** for any request the rules allow.
  Keep tokens narrowly scoped and rules tight.
- **No egress firewall.** Clients that ignore `HTTPS_PROXY` reach the internet
  directly. Their requests simply carry no secrets.
- **Run fullmakt as your user, not root.** Anyone with your user's access to
  the host can read the CA key, the local secrets file and the process memory.
- **Derived credentials are not redacted.** If an API exchanges the injected
  token for another token in the response body, the client receives that one.
- **Protocol upgrades (WebSockets) cannot receive secrets.** They are
  rejected with 403 because their frames cannot be redacted.

Request handling details:

- A CONNECT to a host named by a rule is intercepted with a leaf certificate
  from fullmakt's CA. All other hosts are tunneled untouched.
- Inside an intercepted connection, the `Host` header must match the CONNECT
  target (421 otherwise). This stops a shared CDN or load balancer from
  routing a secret to another tenant.
- Path rules refuse dot segments, encoded `/`, `\` and `.`, `//` and double
  encoding, so a server's path normalization cannot widen a rule.
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

## Web UI

`fullmakt run` also serves a management UI on `127.0.0.1:8900` and prints a
one-time login URL:

- **Activity:** live log of connections and requests, with rule and secret
  names.
- **Secrets:** map names to provider values, check that they resolve, and
  set local values.
- **Rules:** host, methods, paths and headers, with templates for Bearer,
  Basic and raw values.
- **Providers:** local files and Key Vaults.
- **Setup:** CA download and client environment variables.

Changes are validated, written to the config file and applied without a
restart. Requests already in progress finish with the previous rules.
Comments in the config file are not preserved when the UI saves it.

UI security:

- **Session required.** A VM may be able to reach the host's loopback, so
  every API call needs a session. The session comes from a random 256-bit
  token printed at startup and is stored in an `HttpOnly`, `SameSite=Strict`
  cookie. The token changes on every start.
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
fullmakt check -resolve   # validate config and fetch every secret (values are never printed)
fullmakt ca > fullmakt-ca.pem   # public CA certificate for the client
fullmakt run
```

For Azure Key Vault, sign in with `az login` (or use managed or workload
identity). The identity needs the *Key Vault Secrets User* role on the vault.

### Client setup

Clients need the proxy address and must trust the CA:

```bash
export HTTPS_PROXY=http://<fullmakt-host>:8899 HTTP_PROXY=http://<fullmakt-host>:8899
export NO_PROXY=localhost,127.0.0.1

# Ubuntu system store; covers curl, git, gh, Go and most CLIs.
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

## Configuration

See [`config.example.yaml`](config.example.yaml).

| Template | Result |
|---|---|
| `{{ secret "name" }}` | the secret value |
| `{{ basic "user" (secret "name") }}` | `Basic base64(user:value)` |

The first matching rule wins. Hosts take an optional `:port` (default 443),
and `*.example.com` matches subdomains only.

Set `disabled: true` on a rule to pause it, or use Pause in the UI. A
paused rule is still validated but never matches. Its requests pass through
with the client's placeholder, and its host is tunneled unless another rule
covers it.

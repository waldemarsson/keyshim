# Spike: Go with secret-provider SDKs

Date: 2026-10-02. Go 1.27.1, `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'`.

One binary contains everything below. The default run is offline and does not
read cloud environment variables. `call` uses the default credential chains
and real API calls; it was not run.

| Component | Module | Offline run |
|---|---|---|
| Azure | azidentity v1.14.1, azsecrets v1.5.0 | ok |
| AWS | aws-sdk-go-v2/service/secretsmanager v1.50.1 | ok |
| GCP | cloud.google.com/go/secretmanager v1.22.0 + cloud.google.com/go/auth | ok, including the `authorized_user` credential parse that failed under .NET AOT |
| YAML | go.yaml.in/yaml/v3 v3.0.5 | ok |
| UI | `embed.FS` + `net/http` | ok (served and fetched) |

| Target | Size |
|---|---|
| linux/amd64 | 22.0 MB |
| darwin/arm64 (cross-compiled from Linux, Mach-O arm64 header verified) | 21.2 MB |

## Comparison with `../aot-sdks`

- GCP works with the official SDK; no custom REST client or credential code needed.
- macOS binaries build from any host with no native toolchain.
- One binary with all three SDKs is about the size of a single .NET AOT SDK
  binary (11–18 MB each).

## Not covered

- Real round trips to the vaults.
- Running the darwin binary on macOS.

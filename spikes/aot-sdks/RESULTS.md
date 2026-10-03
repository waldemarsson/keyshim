# Spike: Native AOT with secret-provider SDKs

Date: 2026-10-02. .NET SDK 10.0.401, `linux-x64`, linked with gcc
(`CppCompilerAndLinker=gcc`; clang not installed). Run with `LINKER=gcc ./run.sh`.

Each project publishes with `PublishAot=true` and `TrimmerSingleWarn=false`, so
ILC reports every warning in the code it can reach. Calls that would touch the
network sit behind a `call` argument that was not used; the default run
checks that client construction works.

| Project | Package | IL warnings | Native run | Size |
|---|---|---|---|---|
| Baseline | none | 0 | ok | 1.1 MB |
| Azure | Azure.Identity 1.21.0, Azure.Security.KeyVault.Secrets 4.11.1 | 0 | ok | 13 MB |
| Aws | AWSSDK.SecretsManager 4.0.100.15 | 0 | ok | 11 MB |
| Gcp | Google.Cloud.SecretManager.V1 2.8.0 | 22 | **fails** | 18 MB |
| Yaml | YamlDotNet 18.1.0 (reflection deserializer) | 35 | **fails** | 4.2 MB |
| Web | ASP.NET Core slim builder + STJ source gen | 0 | ok (start/stop) | 9.0 MB |

## Findings

- **Azure and AWS work with AOT.** No warnings, including in
  `DefaultAzureCredential` and the `GetSecret`/`GetSecretValue` code paths. The
  real network round trip was not run.
- **GCP does not work.** Warnings come from Newtonsoft.Json, Google.Api.Gax and
  Google.Apis.Json. Parsing an `authorized_user` credential offline fails at
  runtime:
  `JsonSerializationException: Unable to find a constructor ... JsonCredentialParameters`.
  Every ADC flow goes through this parser.
- **YamlDotNet's reflection path does not work**, as expected
  (`Failed to create an instance of type 'Config'`).
- **ASP.NET Core minimal API with source-generated JSON works.**

## Decisions

- Keep `PublishAot` and treat IL warnings as errors.
- GCP provider: call the Secret Manager REST API
  (`GET .../secrets/*/versions/*:access`) with `HttpClient` and STJ source
  gen, plus our own ADC handling. The alternative is a non-AOT build.
- Config: JSON with STJ source gen, or the YamlDotNet static generator
  (not tested).
- Not covered: `osx-arm64` (cross-OS AOT is unsupported, so this needs a macOS
  build host).

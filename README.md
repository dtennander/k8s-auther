# k8s-auther

A CLI tool for authenticating to an OpenID Connect (OIDC) provider and generating Kubernetes ExecCredential tokens.

Allows integration of OIDC authentication flows into Kubernetes client tools by acting as an exec plugin.

## Features

- Authenticate with any OIDC-compliant provider using Authorization Code flow.
- Supports token caching and refresh for improved user experience.
- Outputs credentials in Kubernetes ExecCredential JSON format, suitable for `kubectl` exec plugin.
- Stores tokens securely in `~/.config/k8s-auther/tokens.json`.

## Installation

**Requirements:**

- Rust toolchain (edition 2024)

To build from source:

```sh
cargo install --path .
```

This will install it in your PATH.

## Usage

Authenticate to your OIDC provider and output the id-token in ExecCredential format:

```sh
k8s-auther --issuer-url <OIDC_ISSUER_URL> --client-id <CLIENT_ID> [--scopes <SCOPES>]
```

- `--issuer-url`: The OIDC provider's issuer URL (required)
- `--client-id`: The OIDC client ID to use (required)
- `--scopes`: Space-separated OIDC scopes (optional, default: "openid")

On first use, your browser will open for OIDC authentication. The tool will listen locally on `http://localhost:8080/callback` for the redirect. Tokens are cached for future use and refreshed automatically if possible.

## Integration with kubectl

You can use `k8s-auther` as an exec credential plugin in your `kubeconfig`:

```yaml
users:
  - name: oidc-user
    user:
      exec:
        command: k8s-auther
        args:
          - --issuer-url https://accounts.example.com
          - --client-id my-k8s-client
          - --scopes openid
```

## Configuration and Token Storage

- Tokens are stored at `~/.config/k8s-auther/tokens.json`.
- Tokens are automatically refreshed or re-authenticated as required.

## Contributing

Contributions are welcome!
Please open an issue or submit a pull request on GitHub ❤️!

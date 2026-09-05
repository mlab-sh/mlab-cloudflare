# Install

## From source

A recent Rust toolchain is all it needs.

```bash
git clone https://github.com/mlab-sh/mlab-cloudflare.git
cd mlab-cloudflare
cargo build --release
```

The binary lands at `target/release/mlab-cloudflare`. Put it on your `PATH`:

```bash
install -m 755 target/release/mlab-cloudflare /usr/local/bin/
```

Or run it in place while developing, which is what the pages in this wiki
assume when they show `cargo run`:

```bash
cargo run -- whoami
```

Note the `--`: everything after it goes to the program rather than to cargo.

## Packages

The `Cargo.toml` carries `cargo-deb` and `cargo-generate-rpm` metadata, so
`.deb` and `.rpm` packages build from it, but there is no release pipeline yet
and nothing is published. Until there is, build from source.

## First run

```bash
mlab-cloudflare login
mlab-cloudflare whoami
```

Get a token first at **dash.cloudflare.com → My Profile → API Tokens**, using
the **Read all resources** template. Read [Tokens](Tokens) before you make it —
there is a choice in there that decides whether the token survives your leaving
the account.

## In CI

Nothing to install beyond the binary. The tool reads `CLOUDFLARE_API_TOKEN`,
`CLOUDFLARE_ACCOUNT_ID` and `CF_*` straight from the environment, so no config
file is needed:

```yaml
- run: mlab-cloudflare whoami -o json
  env:
    CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
    CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}
```

Progress rendering switches itself off when `CI` is set or when stderr is not a
terminal.

## Uninstall

```bash
rm /usr/local/bin/mlab-cloudflare
rm -rf ~/.mlab/cloudflare.conf
```

Then revoke the token in the dashboard. Deleting the config file does not.

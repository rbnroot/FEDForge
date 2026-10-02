# FEDForge

**FEDForge** is a bring-your-own OIDC identity provider for red teams testing workload identity federation. It publishes discovery metadata and a JSON Web Key Set (JWKS), signs JWTs with a local RSA key, and exchanges those JWTs for credentials in Microsoft Entra ID, Google Cloud, and AWS.

FEDForge helps you test:

- Which issuer, subject, audience, and claims a workload identity trust accepts
- Whether a token signed by your published key can be exchanged for cloud credentials
- Which cloud token exchange steps succeed or fail

Use FEDForge only in environments where you are authorized to test federation configurations.

---

## Requirements and Installation

### Requirements

1. Python 3
2. A public HTTPS URL for the issuer when a cloud provider needs to fetch its discovery document and JWKS
3. A workload identity trust configured in the target environment

### Install from the repository

```bash
git clone https://github.com/rbnroot/FEDForge.git
cd FEDForge
python3 -m venv fedforce_venv
source fedforce_venv/bin/activate
python -m pip install -r requirements.txt
python fedforge.py --help
```

Run the commands below from the repository root. Replace example URLs, account IDs, and resource names with values from your test environment.

---

## server start

### What it does

`server start` hosts the OIDC discovery document and the public signing key. The server exposes `/.well-known/openid-configuration`, `/jwks`, and `/health`.

The Flask server listens over HTTP. Put a reverse proxy or tunnel in front of it for a public HTTPS issuer. The `--issuer` value must be that public URL and must exactly match the issuer configured in the target trust.

If the selected key directory has no key pair, FEDForge generates one. Use the same directory when creating tokens.

### Syntax

```bash
python fedforge.py server start [--issuer <url>] [options]
```

### Additional Arguments

- `--issuer <url>`  
  Public issuer URL. If omitted, FEDForge uses `http://<host>:<port>`.
- `--host <host>`  
  Address to bind. Default: `0.0.0.0`.
- `--port <port>`  
  Port to listen on. Default: `8080`.
- `--key-dir <path>`  
  Directory containing `private.pem` and `public.pem`. Default: `./keys`.
- `--debug`  
  Enable Flask debug mode.

### Example Usage

```bash
python fedforge.py server start --issuer https://issuer.example.test --port 8080
```

---

## keys generate / keys show

### What they do

`keys generate` creates an RSA private key and public key. `keys show` prints the public key as a JWKS, including the key ID used in signed tokens.

**Generating keys again replaces the current key pair.** Tokens signed with the old private key will no longer match the published JWKS.

### Syntax

```bash
python fedforge.py keys generate [--key-dir <path>]
python fedforge.py keys show [--key-dir <path>]
```

The default key directory is `./keys`. `keys show` generates a key pair if none exists.

---

## token create

### What it does

`token create` signs an RS256 JWT with FEDForge's private key. Set the issuer, subject, and audience to values accepted by the target workload identity trust. The server and token command must use the same key directory.

### Syntax

```bash
python fedforge.py token create --issuer <url> [options]
```

### Additional Arguments

- `--issuer <url>`  
  Required. Must match the public issuer URL served by FEDForge.
- `--subject <subject>`  
  JWT `sub` claim. Default: `system:serviceaccount:default:fedforge`.
- `--audience <audience>`  
  JWT `aud` claim. Default: `api://AzureADTokenExchange`. Set this explicitly for Google Cloud or AWS when their trust expects a different audience.
- `--lifetime <seconds>`  
  Token lifetime. Default: `3600`.
- `--claims '<json>'`  
  Additional JWT claims as a JSON object.
- `--key-dir <path>`  
  Directory containing the signing key. Default: `./keys`.
- `--output <path>` or `-o <path>`  
  Save the raw JWT to a file. FEDForge also prints it to the terminal.

### Example Usage

```bash
python fedforge.py token create \
  --issuer https://issuer.example.test \
  --subject system:serviceaccount:default:fedforge \
  --audience api://AzureADTokenExchange \
  --output fedforge-token.jwt
```

---

## token decode

### What it does

`token decode` prints the claims and expiration status of a **raw JWT**. Pass the token directly or prefix a file path with `@`. The file must contain only the JWT, not a JSON object returned by an exchange command.

With `--verify`, it also checks the JWT signature against FEDForge's local `public.pem`. This is useful for checking a FEDForge-signed token before exchange. It does not verify tokens issued by Entra ID or Google Cloud, and it does not validate audience or expiration. An expired FEDForge token can still pass the signature check.

### Syntax

```bash
python fedforge.py token decode <jwt-or-@file> [options]
```

### Additional Arguments

- `--verify`  
  Check the signature with the local public key. Without this flag, claims are displayed without signature verification.
- `--key-dir <path>`  
  Directory containing `public.pem` for `--verify`. Default: `./keys`.

### Example Usage

```bash
python fedforge.py token decode @fedforge-token.jwt
python fedforge.py token decode @fedforge-token.jwt --verify
```

---

## entra exchange

### What it does

`entra exchange` submits a FEDForge-signed JWT to Microsoft Entra ID as a client assertion and requests an access token for an application. The application's federated credential must accept the JWT's issuer, subject, and audience.

### Syntax

```bash
python fedforge.py entra exchange --token <jwt-or-@file> --tenant-id <tenant-id> --client-id <client-id> [options]
```

### Additional Arguments

- `--token <jwt-or-@file>`  
  Required. Raw federated JWT or a file containing it.
- `--tenant-id <tenant-id>`  
  Required. Microsoft Entra tenant ID.
- `--client-id <client-id>`  
  Required. Application client ID.
- `--scope <scope>`  
  Requested scope. Default: `https://graph.microsoft.com/.default`.
- `--output <path>` or `-o <path>`  
  Save the response. Default: `entra-access-token.jwt`.

### Example Usage

```bash
python fedforge.py token create \
  --issuer https://issuer.example.test \
  --subject system:serviceaccount:default:fedforge \
  --audience api://AzureADTokenExchange \
  --output fedforge-token.jwt

python fedforge.py entra exchange \
  --token @fedforge-token.jwt \
  --tenant-id YOUR_TENANT_ID \
  --client-id YOUR_APP_CLIENT_ID
```

The output file contains a **JSON object** with the access token and metadata, even though its default extension is `.jwt`. `token decode` cannot read that file directly.

---

## gcp exchange

### What it does

`gcp exchange` exchanges a federated JWT for a Google Cloud STS token, then uses that token to request a service account access token. The workload identity pool provider must accept the issuer and token claims, and the service account must allow the impersonation.

### Syntax

```bash
python fedforge.py gcp exchange --token <jwt-or-@file> --project-number <number> --pool-id <id> --provider-id <id> --service-account <email> [options]
```

### Additional Arguments

- `--token <jwt-or-@file>`  
  Required. Raw federated JWT or a file containing it.
- `--project-number <number>`  
  Required. Google Cloud project **number**, not project ID.
- `--pool-id <id>` and `--provider-id <id>`  
  Required. Workload identity pool and provider IDs.
- `--service-account <email>`  
  Required. Service account to impersonate.
- `--scope <scope>`  
  Requested scope. Default: `https://www.googleapis.com/auth/cloud-platform`.
- `--output <path>` or `-o <path>`  
  Save the response as JSON. Default: `gcp-access-token.jwt`.

### Example Usage

Create a token with an audience accepted by your Google Cloud provider, then exchange it:

```bash
python fedforge.py token create \
  --issuer https://issuer.example.test \
  --audience YOUR_GCP_ALLOWED_AUDIENCE \
  --output gcp-fedforge-token.jwt

python fedforge.py gcp exchange \
  --token @gcp-fedforge-token.jwt \
  --project-number YOUR_PROJECT_NUMBER \
  --pool-id YOUR_POOL_ID \
  --provider-id YOUR_PROVIDER_ID \
  --service-account name@project-id.iam.gserviceaccount.com
```

---

## gcp exchange-sts / gcp exchange-sa

### What they do

These commands run the two Google Cloud exchange steps separately. `exchange-sts` returns a federated STS token. `exchange-sa` uses that token to request a service account access token.

### Syntax

```bash
python fedforge.py gcp exchange-sts --token <jwt-or-@file> --project-number <number> --pool-id <id> --provider-id <id> [options]
python fedforge.py gcp exchange-sa --sts-token <token-or-@file> --service-account <email> [options]
```

`exchange-sts` defaults to `gcp-sts-token.json`. `exchange-sa` accepts that JSON file with `@` and defaults to `gcp-access-token.jwt`. Both output files contain JSON, regardless of extension. `exchange-sa` also accepts `--scope` and `--output`.

---

## aws exchange

### What it does

`aws exchange` calls STS `AssumeRoleWithWebIdentity` with a FEDForge-signed JWT and returns temporary role credentials. The IAM OIDC provider and role trust policy must accept the token's issuer, audience, and subject.

### Syntax

```bash
python fedforge.py aws exchange --token <jwt-or-@file> --role-arn <arn> [options]
```

### Additional Arguments

- `--token <jwt-or-@file>`  
  Required. Raw federated JWT or a file containing it.
- `--role-arn <arn>`  
  Required. IAM role to assume.
- `--session-name <name>`  
  Role session name. Default: `fedforge-session`.
- `--output <path>` or `-o <path>`  
  Save the credentials as JSON. Default: `aws-credentials.json`.

### Example Usage

```bash
python fedforge.py token create \
  --issuer https://issuer.example.test \
  --audience YOUR_AWS_PROVIDER_AUDIENCE \
  --output aws-fedforge-token.jwt

python fedforge.py aws exchange \
  --token @aws-fedforge-token.jwt \
  --role-arn arn:aws:iam::123456789012:role/YOUR_ROLE
```

The saved JSON includes `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`, and `AssumedRoleArn`. FEDForge also prints the credentials to the terminal.

---

## Notes

- FEDForge serves discovery metadata and keys, but does not implement an authorization flow or a working OAuth token endpoint. Create JWTs through the CLI.

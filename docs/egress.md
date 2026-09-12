# Sandbox egress

The egress backend wraps a Firecracker sandbox in a transparent HTTP/HTTPS
proxy. Programs receive placeholder environment variables; the proxy resolves
credentials outside the VM and substitutes them on authorized requests.

On macOS, TLS and credential resolution run in the native Exo process. The
existing Lima bridge carries streams and DNS configuration, without receiving
credentials or the TLS signing key.

## Try it

Build with `cargo build -p exo --features firecracker,egress-proxy` and save this
as `egress.json`:

```json
{
  "networking": {
    "type": "limited",
    "allowed_hosts": ["api.notion.com"]
  },
  "credentials": [
    {
      "name": "notion",
      "environment_variable": "NOTION_API_KEY",
      "networking": {
        "type": "limited",
        "allowed_hosts": ["api.notion.com"]
      },
      "injection_location": { "header": true, "body": false }
    }
  ]
}
```

```bash
exo secret set notion --env NOTION_API_KEY
exo --egress-policy egress.json sandbox play \
  --provider firecracker --networking enabled --idle-seconds 300
```

Inside the sandbox:

```bash
curl https://api.notion.com/v1/users/me \
  -H "Authorization: Bearer $NOTION_API_KEY" \
  -H "Notion-Version: 2022-06-28"
```

The client supplies `Bearer ` or other surrounding syntax. The proxy replaces
only the placeholder. `Authorization`, `x-api-key`, and other ordinary headers
work; routing and framing headers cannot contain placeholders.

The CLI interprets binding names as names or IDs in the local encrypted secret
store. Missing, ambiguous, or non-key secrets fail the request. The same flag
works with `exo repl` and a managed Firecracker sandbox. Tell the agent which
variables it can use; the runtime currently injects the environment without
adding a credential inventory to its prompt.

## Policy and credentials

`SandboxNetworkPolicy` controls where the sandbox can connect. Each binding's
`CredentialNetworkPolicy` separately controls where substitution is permitted.
Both must allow the destination. An unrestricted credential inherits the
sandbox's permitted destinations.

Binding names are scoped references, not storage IDs. Two threads can both
request `notion` and resolve different secrets. Implement `EgressCredentialResolver`:

```rust
async fn bindings(&self, identity: &EgressIdentity)
    -> anyhow::Result<Vec<EgressCredentialBinding>>;

async fn resolve(
    &self,
    identity: &EgressIdentity,
    binding_name: &str,
    destination: &EgressDestination,
) -> anyhow::Result<String>;
```

Bindings are selected when the proxy starts. Each use is resolved again, so
rotation and revocation take effect without replacing the sandbox. Identity
includes the sandbox ID and agent/thread scope; destination includes the host,
port, method, and normalized path/query. A vault adapter can pin a binding to a
vault/secret reference per thread and enforce its stored destination restrictions.
The local CLI resolver assumes a single user owns the secret store; hosted
resolvers must supply their own authorization. Resolver failures are sanitized
before returning them to the guest.

```rust
let backend = EgressSandboxBackend::new(backend, networking, resolver);
let sandbox = backend.acquire(request).await?;
let output = sandbox.exec(&command).await?;
```

The wrapper injects placeholders into `exec`, `start_process`, and terminals,
overriding caller-supplied values. It also configures TLS trust for curl, Git,
Python requests, Node, and clients that use `SSL_CERT_FILE`. Images need
`/bin/sh`, `cat`, and `/etc/ssl/certs/ca-certificates.crt`. Separate trust stores
need their own integration. Callers must avoid passing other real credentials
or credential files into the sandbox.

`EgressTransport` provides source-bound listeners. Firecracker redirects guest
TCP 80/443 and TCP/UDP 53, checks the guest source against its veth, and rejects
other traffic, including IPv6 and QUIC. CIDR exceptions cannot bypass the proxy.
DNS answers exact allowed names with a synthetic IPv4 address. The proxy resolves
and pins public upstream IPv4 addresses, validates TLS, requires matching SNI
and HTTP Host, and does not follow redirects. Requests are bounded to 8 MiB;
responses stream, including SSE. Allowed upstreams can still return sensitive
values in their responses.

Listener addresses live in `SandboxRequest.egress_proxy`, outside the spec hash.
`backend.shutdown()` closes egress while retaining the VM. A fresh wrapper can
reacquire it with new listeners, trust, and placeholders; existing client
processes must restart to receive those values. `stop` and `terminate` preserve
the provider's lifecycle behavior. Source-IP binding assumes local traffic
before NAT; a hosted relay needs an authenticated sandbox identity.

## Current scope

The proxy supports limited networking with exact hosts and HTTPS header
substitution. Unrestricted passthrough and body substitution are represented in
the types but rejected until implemented. Standard ports 80/443 are supported;
local gateways on other ports need additional transport support. Model
credential bindings are not inferred automatically.

Apple Containers, smolvm, AWS, snapshots/forks, external attachments, and
one-shot sandboxes are unsupported. HTTP/2, WebSockets, arbitrary TCP, Git Basic
auth encoding, and signed requests are also outside this initial implementation.

## Tests

With the [Firecracker artifacts](../support/firecracker/README.md) installed:

```bash
cargo test -p exoharness --features firecracker,egress-proxy --lib
bash support/firecracker/egress-smoke.sh
bash support/firecracker/managed-egress-smoke.sh
```

The first smoke test checks two VMs against a controlled TLS upstream, including
host/SNI and DNS denial, direct egress, credential rotation/removal, isolation,
and shutdown. The managed test covers automatic trust, process environments,
and reacquiring the same VM with fresh bindings. On macOS it crosses the real
Lima bridge with an isolated test executable. Set
`EXO_FIRECRACKER_LIMA_INSTANCE` to use a different Lima instance.

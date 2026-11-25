# topolvm-attester (Phison) - AI Agent Notes

topolvm-attester is a Phison addition to this TopoLVM fork. It is documented in
[docs/topolvm-attester.md](../../docs/topolvm-attester.md) (design, deployment) and
[docs/topolvm-attester-api.md](../../docs/topolvm-attester-api.md) (the protocol MW implements).

Where it lives:

- `cmd/topolvm-attester`, `cmd/topolvm-attester-agent`: entry points, dispatched by `cmd/hypertopolvm` and
  shipped in the TopoLVM image (symlinks in the Dockerfile).
- `internal/attester/...`: all of its code.
- `docs/topolvm-attester-mw.md`: what the middleware team implements against; keep it in step with the API.
- `charts/topolvm/templates/attester/` and the `attester:` block of `values.yaml`: deployment. Run
  `make generate-helm-docs` (or the pinned helm-docs) after changing values, or `make check-uncommitted` fails.

Rules:

- Do not change TopoLVM's own code, Go version or dependency versions for attester's sake. Keep the attester
  self-contained so upstream TopoLVM releases merge cleanly.
- No `+kubebuilder:rbac` markers in attester code: `make manifests` scans `./internal/...` and `./cmd/...` and would
  merge them into topolvm-controller's ClusterRole. RBAC lives in the chart templates.
- No keys of our own, anywhere. Every credential is a Kubernetes ServiceAccount token (`internal/attester/kubeauth`):
  - MW -> attester: MW's Pod-bound ServiceAccount token (default token, or a projected one for audience
    `topolvm-attester`), checked with TokenReview; only Pod-bound tokens are accepted.
  - attester -> agent: a TokenRequest token of `topolvm-attester` (audience `topolvm-attester-agent`), checked by the
    agent with TokenReview.
  - agent -> attester: every `agent.Report` is attested by a `topolvm-attester-agent` token bound to the agent Pod,
    audience `sha256:<report>`, echoing the attester's nonce. The attester checks it is the agent Pod it called on the
    caller's node. That hop is plain HTTP and must stay untrusted.
  - attester -> MW: `{"result": "<JSON string>", "attestation": "<token>"}`, the attestation being a TokenRequest
    token of `topolvm-attester` bound to the attester Pod with audience `sha256:<hex SHA-256 of result>`. The result
    echoes MW's nonce and names the calling `pod`, which MW must compare with itself (stops relaying).
- MW hardcodes `system:serviceaccount:topolvm-system:topolvm-attester` and
  `https://topolvm-attester.topolvm-system.svc`. The chart keeps those names fixed (not derived from the release name);
  changing them or the namespace breaks released MW builds.
- The Roles allowing `serviceaccounts/token` are limited with `resourceNames` to each component's own ServiceAccount.
  Keep them that narrow: it is what makes attestations unforgeable without rights in the namespace.
- Agent Pods are found by `app.kubernetes.io/component=attester-agent`, the chart's component label convention.
- Docs are in Traditional Chinese like the other Phison docs.

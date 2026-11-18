# wit/unstable

The pre-sync vendored tree: the legacy `wit/v0` surface plus transport and
webhook drafts (`sockets.wit`, `ws-client.wit`, webhook ingress in
`channel.wit`) from host branches that have not merged, with the
`memory-audit` logging case released hosts require.

Plugins bind here until their own migration PR moves them to `wit/v0`, which
tracks released hosts byte-identically (pin in `wit/UPSTREAM_REF`; enforced by
the WIT drift CI job). A plugin that imports the unstable transport interfaces
cannot load on released hosts and must stay `registry = false` until the host
ships those interfaces.

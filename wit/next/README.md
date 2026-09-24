# wit/next

The plugin contract of the unmerged zeroclaw host branch that adds
host-mediated sockets (`sockets.wit`), WebSocket (`websocket.wit`), and TLS
profiles. It is a byte copy of that branch's `wit/v0`; `NEXT_REF` pins the
commit.

`wit/v0` stays byte-identical to released hosts, and `wit/unstable` keeps the
older transport drafts the existing channel plugins bind to. A plugin binds
here only while it is being ported to the new transport contract, and stays
`registry = false` until the host ships it. When the host branch merges, these
files become `wit/v0` and this directory goes away.

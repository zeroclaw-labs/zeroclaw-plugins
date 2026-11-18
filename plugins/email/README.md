# Email

Text-only IMAP and SMTP channel over ZeroClaw’s socket resource. The host applies its email sender matching to addresses and display-name forms.

## Install and configure

Build the source-only package from its directory and bind the channel on ZeroClaw v0.9.0.

```sh
cargo build --locked --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/email.wasm .
zeroclaw plugin install "$PWD"
zeroclaw plugin bind email --channel-alias mail --egress none
zeroclaw plugin info email
```

Copy the config entry key printed by `plugin info` into the shell variable `key`. The commands for secrets prompt without echo. Grant the IMAP host and, when sending mail, the SMTP host.

```sh
zeroclaw config set "plugins.entries.$key.egress_hosts" 'imap.example.com,smtp.example.com'
zeroclaw config set "plugins.entries.$key.config.imap_host" 'imap.example.com'
zeroclaw config set "plugins.entries.$key.config.username" 'bot@example.com'
zeroclaw config set "plugins.entries.$key.config.password"
zeroclaw config set "plugins.entries.$key.config.smtp_host" 'smtp.example.com'
zeroclaw config set "plugins.entries.$key.config.from_address" 'bot@example.com'
```

Enable `plugins.enabled`, route `plugin.mail` to an enabled agent, and authorize senders in the alias’s peer group.

Omit both `smtp_host` and `from_address` for an inbound-only mailbox. A blank pair has the same effect. Inbound-only mailboxes also support `observer_mode = true`. A send request returns an inbound-only error before opening an SMTP connection. Configure both fields to enable sending. SMTP credentials default to the IMAP credentials and can be set separately using `smtp_username` and the `smtp_password` secret.

## Supported behavior

- IMAP uses host-managed implicit TLS, LOGIN password authentication, SELECT,
  UID SEARCH, and one-at-a-time UID FETCH commands.
- Active mode drains UNSEEN mail at startup with RFC822, then polls from
  UIDNEXT using BODY.PEEK[].
- Observer mode records UIDNEXT at SELECT time, ignores older mail, and only
  uses BODY.PEEK[], so it does not change message flags.
- Arbitrary TCP chunks are reassembled into IMAP lines and bounded literals.
  Message literals are capped at 4 MiB.
- Plain-text MIME bodies are emitted with sender, subject, Message-ID, and
  parsed Date. HTML-only bodies are reduced to text. MIME attachments are not
  surfaced.
- SMTP uses AUTH PLAIN or AUTH LOGIN and advances one command per complete
  server reply. It does not assume PIPELINING.
- Outbound messages are RFC 5322 text/plain MIME with encoded UTF-8 subjects,
  base64 bodies, dot stuffing, Date, Message-ID, and validated reply headers.
- SMTP connections and queued messages are bounded. A disconnect after DATA
  is not retried because delivery may already have succeeded.

The WIT send call validates and queues an SMTP transaction. SMTP replies arrive
through later nonblocking poll_message calls, so a later rejection is emitted
to the host log and cannot be returned to the original send caller.

## Explicit limits

- OAuth2/XOAUTH2 is rejected during configure.
- STARTTLS is not implemented. smtp_tls = true means host-managed implicit TLS;
  smtp_tls = false means plaintext. Servers that require STARTTLS, commonly on
  port 587, are unsupported.
- IMAP IDLE is not implemented. poll_interval_secs controls UID polling;
  idle_timeout_secs is accepted for native config compatibility but unused.
- Outbound attachments are rejected and inbound attachments are ignored.
  max_attachment_bytes therefore has no effect in this text-only slice.
- html_body is accepted for native config compatibility, but outbound mail is
  always text/plain.
- Address envelopes are conservative ASCII addr-spec values. Display names,
  address groups, internationalized envelopes, SMTPUTF8, DSN, and multiple
  recipients are unsupported.
- Delivery confirmation beyond the SMTP final 250 response is unsupported.

No live IMAP or SMTP credentials are stored in this repository, and the
automated suite uses protocol transcripts rather than a live provider.

## Validation

Run from the zeroclaw-plugins repository root:

~~~bash
cargo fmt --manifest-path plugins/email/Cargo.toml -- --check
cargo test --manifest-path plugins/email/Cargo.toml
cargo clippy --manifest-path plugins/email/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/email/Cargo.toml --target wasm32-wasip2 --release
cargo clippy --manifest-path plugins/email/Cargo.toml --target wasm32-wasip2 -- -D warnings
~~~

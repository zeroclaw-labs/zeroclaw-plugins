# kiosk-qr — render a Solana Pay charge as a scannable QR (host-side)

A tiny **host-side** helper for ProofKiosk. It is deliberately **not** part of any
wasm plugin: `kiosk-charge` stays a ~208 KB, zero-network component that returns a
`solana:` URL string, and this skill turns that string into a QR image the operator's
channel can send. Keeping image rendering out of wasm is why the plugin is small.

## When to use it

After `kiosk_charge` returns a `solana:` URL, use this to give the customer something
to scan or tap:

- **QR image** — for a customer standing at the kiosk looking at a *separate* screen
  (the Pi's display, or a photo sent into the chat). A QR only makes sense across two
  screens; a customer on the same phone should use the tap-link instead.
- **Tap-link fallback** — the `solana:` URI itself is tappable: mobile wallets
  (Phantom, Solflare, …) register the `solana:` scheme and open the payment pre-filled
  with one tap, for same-device chat flows. No wrapper service needed.

## Usage

```bash
./render-qr.sh 'solana:4Nd1…?amount=1.5&spl-token=EPjF…&reference=3g8oT…' out.png
# -> writes out.png (QR of the solana: URL)
# -> prints the tappable solana: link fallback to stdout
```

`render-qr.sh` uses `qrencode` if present (no network, no wasm). The tap-link needs no
dependency at all.

## Delivery

- Channels that support images (Telegram `sendPhoto`, Discord, WhatsApp, Matrix) send
  `out.png` as a photo with the amount in the caption.
- Text-only channels (IRC, email) send the tap-link and the raw `solana:` URL.

The image and link are presentation only — the payment is still the customer's own
wallet signing the transfer to the operator's address. Nothing here holds a key or
changes the on-chain amount; `kiosk-watch` verifies the result regardless of how the
charge was shown.

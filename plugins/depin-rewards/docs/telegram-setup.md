# Telegram setup (for depin-rewards alerts)

A 2-minute manual flow to get a `telegram_bot_token` + `telegram_chat_id` into your plugin config. No SDK, no code — just @BotFather + one HTTP call.

## 1. Create a bot → get the token

1. Open Telegram, message **[@BotFather](https://t.me/BotFather)**.
2. Send `/newbot`.
3. Pick a **name** (e.g. `Palinurus Alerts`) and a **username** ending in `bot` (e.g. `palinurus_alerts_bot`).
4. BotFather replies with an HTTP API token like `7123456789:AAH…token`. That's your `telegram_bot_token`.

## 2. Get your `chat_id`

The bot can only message a chat it's been invited to / that has started it.

- **DM alerts (simplest):** create a DM with your new bot, send it any message (e.g. `hi`), then open this URL in a browser (replace `<token>`):
  ```
  https://api.telegram.org/bot<TOKEN>/getUpdates
  ```
  In the JSON response, find `"chat": { "id": 123456789 }` — that number is your `telegram_chat_id`.
- **Channel alerts:** add the bot to a channel as an **administrator** (it needs the *post messages* permission), then use the channel id as `telegram_chat_id` — it's the negative number starting with `-100…` (e.g. `-1001234567890`).

## 3. Paste into config

```toml
[plugins.entries.depin_rewards]
relay_api_key      = "…"
hotspots           = "[\"11dZ…\"]"
telegram_bot_token = "7123456789:AAH…token"   # from step 1
telegram_chat_id   = "123456789"               # from step 2 (or -100… for a channel)
```

## 4. Sanity check (optional)

Send a test message directly:

```bash
curl -s "https://api.telegram.org/bot<TOKEN>/sendMessage" \
  -d chat_id=<CHAT_ID> \
  -d text="palinurus test"
```

You should receive "palinurus test" in the chat. The plugin's `watch` action uses this exact endpoint.

---

## Notes

- The bot token is a credential — keep it in the jailed plugin config (`config_read`); the plugin's `Debug` impl redacts it (it never appears in logs or output).
- `chat_id` is sourced from config, never from a message — a prompt-injection cannot redirect alerts to an attacker's chat (see README → Custody).
- Rate limits: Telegram allows ~30 msgs/sec to a single chat; the plugin's cadence (one alert per offline-flip + a daily summary) is nowhere near that.

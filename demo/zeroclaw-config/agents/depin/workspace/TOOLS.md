# Tools

Call exactly ONE tool. Never call both. Never invent args.

## depin_attest

Args ONLY: device_id, metric, reading, unit
Example: device_id=pi-greenhouse-7 metric=temperature reading=21.4 unit=celsius
Do not pass max_age_secs. Keep decimal 21.4.

Reply with the returned card verbatim (starts with ✅). Then stop.

## depin_uptime_watch

Args ONLY: device_id=pi-greenhouse-7
Do not pass max_age_secs unless the user gives a number. Never nest under "parameters".

Reply with the returned card verbatim (🟢/🟡/🔴). Then stop.

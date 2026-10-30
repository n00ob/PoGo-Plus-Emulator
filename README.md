# PoGo-Plus-Emulator

A Pokemon GO Plus emulator for the [Seeed Studio XIAO ESP32-C3](https://www.seeedstudio.com/Seeed-XIAO-ESP32C3-p-5431.html), built with Arduino IDE. Auto-catches Pokemon and Pokestops with no button, no LED, no vibration. Uses your dumped device keys to authenticate as a real GO Plus.

## Features

- **Auto-catch** — answers every LED pattern from the app with a button press automatically
- **Phone lock** — after first pairing, only your phone can connect. Other phones are rejected before any pairing handshake
- **Invisible while connected** — once paired, the device advertises a bare anonymous packet with no GO Plus name or service data, so other phones' GO apps can't find it
- **Reconnect** — your phone reconnects automatically using the stored bond; no re-pairing needed after disconnect or power cycle
- **Admin dashboard** — connects to your phone's hotspot and serves a local web page to forget the paired phone without needing USB or Serial
- **Power optimised** — BT modem sleep, 80MHz CPU, WiFi power save, automatic light sleep if your core build supports it

## Hardware

| Part | Notes |
|------|-------|
| Seeed Studio XIAO ESP32-C3 | Any revision |
| 850mAh Li-ion battery (e.g. XTAR 16340) | Protected cell recommended |
| Inline power switch (optional) | On the BAT+ wire for hard off |

## Requirements

- [Arduino IDE](https://www.arduino.cc/en/software) 2.x
- [arduino-esp32](https://github.com/espressif/arduino-esp32) core **2.0.x** (3.x changes the Bluetooth headers — not supported yet)
- Board: **XIAO_ESP32C3**
- Partition scheme: **Huge APP (3MB No OTA / 1MB SPIFFS)**
- USB CDC On Boot: **Enabled** (only needed for the Serial log; disable for battery use)

## Setup

### 1. Dump your GO Plus keys

You need three values from a real Pokemon GO Plus:
- **MAC address** — the Bluetooth MAC of your original device
- **Device key** — 16 bytes
- **Blob** — 256 bytes

Tools like [gogplusplus](https://github.com/PokeAPI/goPlusPlus) can dump these. Keep them private.

### 2. Fill in secrets.h

Open `secrets.h` and paste your values:

```c
#define PGP_MAC_HEX         "98:B6:E9:xx:xx:xx"
#define PGP_DEVICE_KEY_HEX  "0123456789abcdef0123456789abcdef"
#define PGP_BLOB_HEX        "0000...0000"   // 512 hex chars
#define PGP_HOTSPOT_SSID     "Your hotspot name"
#define PGP_HOTSPOT_PASSWORD "Your hotspot password"
#define PGP_DEVICE_LABEL     ""  // optional friendly name shown in the dashboard
```

**Never commit `secrets.h` to a public repo.** Add it to `.gitignore`.

### 3. Flash

1. Open `PGPlusC3.ino` in Arduino IDE
2. Select **XIAO_ESP32C3** as the board
3. Set Partition Scheme to **Huge APP (3MB No OTA / 1MB SPIFFS)**
4. Upload
5. Open the Serial Monitor at **115200 baud** and check the boot log

### 4. Pair

In the Pokemon GO app: **Settings → Pokemon GO Plus → search for device**. Pair once — the device locks itself to your phone and rejects all others from that point on.

## Serial commands

| Command | Action |
|---------|--------|
| `RESET` | Forget the paired phone and open pairing to any phone |
| `STATUS` | Print current state (BLE, pairing, WiFi, cert) |

## Admin dashboard

When your phone's personal hotspot is active, the device joins it automatically (checked every 30 seconds) and hosts a local web page at `http://pogo-hub.local/`. From there you can forget the paired phone on any unit without needing USB access.

## Options

At the top of `PGPlusC3.ino`:

| Option | Default | Description |
|--------|---------|-------------|
| `PGP_ENFORCE_LOCK` | `1` | Set to `0` to log rejected phones without actually kicking them (diagnostic mode) |
| `PGP_STEALTH_WHEN_LOCKED` | `0` | Set to `1` to strip the GO Plus name from advertisements while paired — other phones' GO apps can't find it |
| `PGP_USE_RECONNECT_PATH` | `0` | Experimental shorter reconnect handshake |
| `WIFI_CHECK_MS` | `30000` | How often to look for the hotspot (ms) |

## How the phone lock works

Phones use rotating private Bluetooth addresses, so MAC-based whitelisting breaks reconnect. Instead:

1. On first successful pairing, the bond is stored in flash
2. Every subsequent connection is checked against the bond record using Bluedroid's IRK-based identity resolution (the same method the Bluetooth spec defines for private address matching)
3. An unrecognised phone is disconnected before any pairing handshake — no encryption, no certificate exchange, nothing

## Licence

BSD 3-Clause. See [LICENSE](LICENSE).

## Credits

Designed and built by [n00ob](https://github.com/n00ob). The project concept, hardware choices, feature decisions, and all real-hardware testing and debugging were driven by them. Implementation was developed with coding assistance from [Claude](https://claude.ai) (Anthropic).

Crypto and certificate handshake ported from [pgpemu](https://github.com/yohanes/pgpemu) by Yohanes Nugroho, © 2018, BSD 3-Clause licence.
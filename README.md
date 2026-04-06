# Home Presence Monitor

Small Flask app for a Raspberry Pi or another Linux machine on your home network. The backend checks local network presence with `speedport devices` by default, then optionally falls back to `arp -a` and `nmap -sn`. The browser does not scan the network itself; it only fetches backend results over HTTP.

## File tree

```text
.
|-- README.md
|-- app.py
|-- config.py
|-- detector.py
|-- requirements.txt
|-- static
|   |-- app.js
|   `-- style.css
`-- templates
    `-- index.html
```

## How it works

- `app.py`: Flask routes for the HTML page, `GET /api/status`, and `GET /api/devices/debug`.
- `config.py`: One editable place for target MAC/IP/hostname values, subnet, polling interval, bind host, and fallback settings.
- `detector.py`: Runs Linux commands, parses output defensively, matches the target, and tracks the last successful positive detection time.
- `templates/index.html`: Minimal status page.
- `static/app.js`: Fetches backend JSON, refreshes every few seconds, and updates the debug panel.
- `static/style.css`: Simple local-only styling.

## Configuration

Edit `config.py` and replace the example values in `USER_CONFIG`.

Example:

```python
USER_CONFIG = {
    "TARGETS": [
        {
            "name": "Alex",
            "macs": ["aa:bb:cc:dd:ee:ff"],
            "ips": ["192.168.1.50"],
            "hostnames": ["my-phone"],
        }
    ],
    "SUBNET_CIDR": "192.168.1.0/24",
    "POLL_INTERVAL_SECONDS": 20,
    "COMMAND_TIMEOUT_SECONDS": 8,
    "ENABLE_REVERSE_DNS": True,
    "ENABLE_ARP_FALLBACK": True,
    "ENABLE_NMAP_FALLBACK": False,
    "SPEEDPORT_COMMAND": "",
    "BIND_HOST": "127.0.0.1",
    "BIND_PORT": 5000,
}
```

Notes:

- `TARGETS`: Each person can be matched by any combination of MACs, IPs, and hostnames.
- `ENABLE_ARP_FALLBACK`: Keeps `arp -a` as a passive local fallback after the Speedport check.
- `ENABLE_NMAP_FALLBACK`: Off by default because it is the slowest and most active fallback, scanning the configured local subnet.
- `SPEEDPORT_COMMAND`: Optional explicit path to the `speedport` executable. Leave it empty to prefer a repo-local `.venv` executable if present, then fall back to `speedport`.
- `BIND_HOST`: Defaults to `127.0.0.1` for local-only use. Change to `0.0.0.0` only if you want to access it from other devices on your LAN.

## Setup on Raspberry Pi / Linux

1. Install system packages:

   ```bash
   sudo apt update
   sudo apt install -y python3 python3-venv python3-pip net-tools
   ```

2. Install `nmap` only if you want the optional active scan fallback:

   ```bash
   sudo apt install -y nmap
   ```

3. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. Install Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Make sure the `speedport` CLI works on the Pi. It is the default primary check:

   ```bash
   speedport devices
   ```

6. Edit `config.py` with your real MAC, IP, hostname, and subnet.

## Run the server

```bash
source .venv/bin/activate
python3 app.py
```

Then open:

- `http://127.0.0.1:5000` on the Raspberry Pi itself
- or, if you set `BIND_HOST = "0.0.0.0"`, `http://<pi-lan-ip>:5000` from another device on the same LAN

## API endpoints

### `GET /api/status`

Returns current presence status and diagnostics.

Example response:

```json
{
  "present": true,
  "status_text": "Probably at Home",
  "last_checked": "2026-04-05T12:34:56+02:00",
  "method": "speedport devices",
  "matched_by": "mac_address",
  "target_identifier": "aa:bb:cc:dd:ee:ff",
  "confidence": "high",
  "last_positive_detection": "2026-04-05T12:34:56+02:00",
  "sources_attempted": ["speedport devices", "arp -a"],
  "details": [],
  "errors": []
}
```

### `GET /api/devices/debug`

Returns the currently observed nearby devices and command errors, useful for figuring out what the Pi can actually see on the network.

## How to test it

1. Put the real target identifiers into `config.py`.
2. Start the server on the Raspberry Pi.
3. Make sure the target device is on the local Wi-Fi or LAN.
4. Visit the web page and press `Refresh now`.
5. If the device does not appear immediately, confirm it shows up in `speedport devices` and trigger a normal network action from that device.
6. If the passive local fallback is not enough, enable `ENABLE_NMAP_FALLBACK` and test again.
7. Use `GET /api/devices/debug` or the page's debug panel to inspect what identifiers are actually visible.

Useful manual checks on the Raspberry Pi:

```bash
speedport devices
arp -a
nmap -sn 192.168.1.0/24
```

## Limitations

- `speedport devices` depends on what the router reports as connected. In some home networks that is the strongest signal, but it is still not perfect proof of physical presence.
- `arp -a` is a passive local fallback. It only shows devices that the Pi has seen recently.
- A negative result does not prove the person is away. It only means the target device was not confidently visible during the latest check.
- Phones and laptops may sleep, disconnect briefly, or delay replies to save power.
- Some devices use MAC randomization, especially on Wi-Fi, which can break MAC-based matching.
- Hostname matching is weaker than MAC or a known stable IP.
- `nmap -sn` is the last fallback. It is more reliable than passive cache inspection, but it is still only checking the configured local subnet and may miss firewalled or unusual devices.

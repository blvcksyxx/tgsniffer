# blvcksyxx tg_sniffer [v1]

a lightweight, multi-threaded console utility designed to isolate and monitor real-time peer-to-peer (P2P) network streams. utilizing raw socket sniffing, the tool automatically drops cdn noise, structures connection traffic into a minimal grid interface, and resolves remote endpoint metadata instantly.

---

## features

* **auto-interface gateway lock:** dynamically binds directly to your primary active internet adapter, bypassing loopback and virtual network adapters.
* **live metadata processing:** fetches deep geoip attributes (country, city, region) and asn service provider (isp) parameters in background threads without UI lockup.
* **smart protocol filtration:** * automatically filters internal lan structures (`192.168.x.x`, `10.x.x.x`, `0.x.x.x`, `255.xxx.xxx.xxx`), local loopbacks, and multi-cast routing noise (`224.x.x.x`, `239.x.x.x`).
* drops heavy corporate infrastructure traffic (google llc, cloudflare, cloud providers).
* checks destination points against official server blocks, gracefully visually striking them out (`[s]ip[/]`) to isolate direct client channels.
* **integrated audio alerts:** fires low-frequency tactical system audio cues (`winsound`) the exact moment an endpoint connection crosses the steady threshold.
* **on-the-fly search constraints:** clean screen-clearing controls to query location or provider patterns instantly.

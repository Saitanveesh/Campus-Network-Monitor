# Campus Network Observatory

A passive, evidence-driven network monitoring system built around one rule: **if the sensor cannot currently prove it, the live board must not show it as fact.**

## Stage 1 foundation

The current branch implements a fresh architecture instead of continuing the old multi-terminal VM prototype.

### What is different

- one Python process owns supervisor, capture, live state, API and web UI;
- automatic interface discovery and election;
- network fingerprinting and automatic session rotation;
- live state exists only in memory and is destroyed on session invalidation;
- historical sessions are stored separately in `data/history.db`;
- dashboard/topology call only `/api/live/*` endpoints;
- destination-only IP addresses cannot become local endpoints;
- sensor, gateway/infrastructure, verified local endpoints and off-subnet peers are different classes;
- binary PCAP parsing replaces free-form `tcpdump` text parsing;
- capture health can report active, idle, stalled, parser failure or capture failure;
- current topology is an observed communication relationship graph, not a claimed physical campus topology;
- no active scanning is used.

## Architecture

```text
Linux network state
      |
      v
Interface discovery/election
      |
      v
Session supervisor
      |
      +---- network fingerprint changes ----> clear live state / archive old session
      |
      v
Managed tcpdump binary-PCAP capture
      |
      v
Strict Ethernet / IPv4 / ARP parser
      |
      v
Thread-safe CURRENT SESSION state (memory only)
      |                         |
      |                         +----> isolated history archive
      v
Integrated HTTP API + Web UI
      |
      +---- /api/live/*
      +---- /api/history/*
      |
      +---- Dashboard
      +---- Observed Live Communication Topology
```

## Repository layout

```text
app/
  __main__.py       # python -m app entrypoint
  main.py           # preflight + one-command launcher
  service.py        # supervisor/session lifecycle
  network.py        # automatic interface discovery/election
  capture.py        # managed tcpdump capture worker/watchdog
  pcap.py           # binary PCAP + Ethernet/IPv4/ARP parser
  state.py          # fail-closed current-session truth state
  history.py        # closed-session archive only
  server.py         # localhost API + static web server
  config.py
web/
  index.html        # live board
  topology.html     # packet-movement communication graph
tests/
  test_state.py
  test_pcap.py
data/               # runtime only; gitignored
```

## Kali setup

The Python code uses only the standard library. `tcpdump` is the only external runtime dependency.

```bash
sudo apt install tcpdump libcap2-bin
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which tcpdump)")"
getcap "$(readlink -f "$(which tcpdump)")"
```

Expected capability output should include `cap_net_raw`.

## Run

```bash
git clone https://github.com/Saitanveesh/Campus-Network-Monitor.git
cd Campus-Network-Monitor
git checkout stage1-foundation
python3 -m unittest discover -s tests -v
python3 -m app
```

Then open:

- Dashboard: `http://127.0.0.1:8080/`
- Live topology: `http://127.0.0.1:8080/topology.html`
- Live status API: `http://127.0.0.1:8080/api/live/status`

There is no second API process and no separate HTTP server.

## Endpoint truth rules

A local endpoint is created only when the sensor observes defensible source-side evidence:

- `IPV4_SOURCE_FRAME`: valid local source IP paired with the observed Ethernet source MAC;
- `ARP_SENDER`: valid ARP sender IP/MAC whose ARP sender MAC matches the Ethernet source MAC.

The following do **not** create a local endpoint:

- an IP appearing only as a destination;
- public Internet peers;
- private addresses outside the sensor subnet;
- multicast/broadcast/special addresses;
- malformed packets.

## Live vs history boundary

`LiveState` never reads the history database. On network loss or fingerprint change:

1. capture stops;
2. current live entities are snapshotted for history;
3. in-memory endpoints/flows/ARP/packet feed/traffic samples are cleared;
4. the live API fails closed until a valid capture session exists;
5. a reconnect creates a new UUID session.

The live dashboard and topology never call `/api/history/*`.

## Stage 1 closure gate

Stage 1 is not complete until these real tests pass:

- boot with no network -> `NETWORK_DOWN`, empty board;
- connect after startup -> automatic interface selection and new session;
- disconnect while monitoring -> board/topology clear;
- reconnect same network -> fresh session without process restart;
- Wi-Fi <-> Ethernet change -> automatic re-election/session rotation;
- IPv4/subnet/gateway change -> new fingerprint/session;
- two usable interfaces -> stable deterministic selection;
- quiet link -> `LINK_UP_IDLE`, not fake offline data;
- tcpdump/capture failure -> fail-closed state;
- malformed input -> rejected, never displayed as a device;
- restart with old `data/history.db` -> no historical entity appears on the live board.

## Scope boundary

Stage 1 currently captures **Ethernet IPv4 + ARP**. IPv6, DNS/DHCP-specific intelligence, security correlation, host risk scoring and longer behavioural baselines belong after the sensing/reliability gate is closed.

# Campus Network Observatory

A passive, evidence-driven campus network monitoring system designed for trustworthy live observability rather than synthetic or inferred network state.

## Stage 1 goal

Build a robust monitoring core that can:

- automatically discover and select the active capture interface;
- detect network, interface, address, route, and session changes;
- isolate every live monitoring session from historical data;
- capture packet metadata passively without active scanning;
- create endpoint records only from defensible source-side evidence;
- distinguish sensor, infrastructure, local endpoints, private off-subnet peers, public peers, broadcast, multicast, and special addresses;
- expose current-session traffic, flows, ARP evidence, capture health, and topology;
- fail closed when the capture or network state cannot be validated;
- clear live state immediately when a session becomes invalid;
- retain historical records separately from the live board.

## Non-negotiable correctness rules

1. No evidence -> no live entity.
2. Historical data must never enter the live dashboard or live topology.
3. Every reconnect or network change creates a new session.
4. A destination-only IP must never be promoted to a local endpoint.
5. Sensor and gateway/infrastructure are classified separately from ordinary endpoints.
6. External peers are never counted as local connected devices.
7. Malformed, special, multicast, broadcast, loopback, and invalid addresses are never shown as ordinary devices.
8. Every live entity carries provenance/evidence.
9. If capture health is uncertain, the UI must clear and report the reason instead of showing stale values.
10. No active network scanning is required for Stage 1.
11. No automatic claim that an endpoint is malicious or compromised from a weak indicator.
12. The observed topology is a communication relationship graph, not a claimed physical switch-by-switch topology.

## Target architecture

```text
Operating system network state
        |
        v
Sensor Supervisor
  - interface discovery/election
  - link/address/route validation
  - network fingerprinting
  - session lifecycle
  - capture watchdog
        |
        v
Session-aware Collector
  - structured packet capture
  - strict parsing/validation
  - endpoint evidence
  - flow/ARP evidence
  - live TTLs
        |
        +----------------------+
        |                      |
        v                      v
Live state store          History store
(current session only)    (closed sessions only)
        |
        v
Live API
        |
   +----+----+
   |         |
Dashboard  Observed Live Flow Map
```

## Planned repository layout

```text
campus-network-observatory/
  app/
    supervisor.py
    collector.py
    api.py
    launcher.py
  web/
    index.html
    topology.html
  tests/
  docs/
  config/
  runtime/
  data/
  requirements.txt
  README.md
```

Runtime databases, packet-event snapshots, PID files, and logs must not be committed.

## Stage 1 closure gate

Stage 1 will not be considered complete until the system passes at least these physical tests:

- boot with no network;
- connect a network after startup;
- disconnect while monitoring;
- reconnect to the same network;
- switch between Wi-Fi and Ethernet;
- change IP/subnet/gateway;
- run with two usable interfaces simultaneously;
- kill the collector during capture;
- kill the API while the browser remains open;
- restart with historical databases present;
- remain on an idle but valid link;
- reject malformed/unusable packet input;
- verify that old-session endpoints and flows never reappear on the live board.

## Current development policy

This repository is the source of truth for all further development. Experimental code should be committed on branches and integrated only after its reliability checks pass.

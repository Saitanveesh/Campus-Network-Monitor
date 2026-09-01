# Stage-1 Physical Validation Plan

Stage 1 is accepted only if the live board remains truthful under state changes and failures. Perform these tests on an authorized network.

## Pass/fail rule

For every test, the system must either show validated current evidence or explicitly show an unavailable/error state. It must never keep stale live values after the underlying session becomes invalid.

| ID | Test | Expected result |
|---|---|---|
| T01 | Start with no network | `NETWORK_DOWN`; zero live endpoints/flows/packets |
| T02 | Connect valid Ethernet/Wi-Fi | interface selected automatically; new session UUID; capture starts |
| T03 | Quiet valid link | `LINK_UP_IDLE`; zero/low current rates; old data not replayed |
| T04 | Generate ordinary traffic | `CAPTURE_ACTIVE`; current flows/packet feed update |
| T05 | Pull cable / disconnect Wi-Fi | capture stops; live board and topology clear; old session archived |
| T06 | Reconnect same network | new session UUID without application restart |
| T07 | Switch Wi-Fi to Ethernet | automatic re-election; old live state cleared; new session |
| T08 | Switch Ethernet to Wi-Fi | same guarantees as T07 |
| T09 | Address/subnet/gateway changes | fingerprint changes; session rotates |
| T10 | Two usable interfaces | deterministic stable choice; no rapid interface flapping |
| T11 | tcpdump exits unexpectedly | live API fails closed with `CAPTURE_ERROR`; worker attempts controlled recovery |
| T12 | Capture lacks permission | startup/capture error is explicit; no false live data |
| T13 | Malformed frame/parser rejection | rejected counter increases; no fabricated endpoint |
| T14 | Destination-only local IP | must not appear in verified local endpoint inventory |
| T15 | Public/private off-subnet peer | may appear in flow/topology as peer; must not count as local endpoint |
| T16 | Restart with `data/history.db` present | live board starts empty until new current evidence exists |
| T17 | Browser left open through disconnect | UI clears on next refresh and shows fail-closed reason |
| T18 | Session switch while topology open | old nodes disappear before new-session nodes appear |

## Evidence to record

For each test capture:

- test ID and time;
- interface selected;
- sensor IP/subnet/gateway;
- old and new session UUID where applicable;
- screenshot or API status before/during/after the transition;
- pass/fail result and any defect found.

Do not inject synthetic hosts or alerts into the production live session to demonstrate features. Use isolated unit tests or dedicated lab traffic for controlled validation.

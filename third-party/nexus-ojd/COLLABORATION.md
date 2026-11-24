# Community collaboration brief

Context for another engineer picking this up. Written to be read before
touching code, and kept honest about what is proven and what is not.

## The problem

Sunshine on macOS cannot create virtual gamepads without Apple's
`com.apple.developer.hid.virtual.device` entitlement. That entitlement is
restricted: Apple grants it per team, and it is **not** obtainable through a free
Personal Team, a paid membership, or by disabling SIP alone.

`libvirtualhid` solves this by shipping a separately signed, notarized broker
that already holds the entitlement and sells a machine license for it. That works
but costs money.

## What this directory is

An alternative backend: instead of creating HID devices itself, Sunshine talks to
**OpenJoystickDriver** (OJD), a notarized third-party app that holds the same
entitlement. OJD exposes a documented local-socket API that lets an external
program drive a virtual gamepad. No SIP change, no AMFI change, no purchased
license.

Proven on this machine (macOS 27.2, arm64, SIP enabled, boot-args empty):

| Claim | Evidence |
|---|---|
| OJD is notarized and Apple-signed | `spctl -a` → `accepted / Notarized Developer ID` |
| OJD holds the restricted entitlement | `codesign -d --entitlements` shows `com.apple.developer.hid.virtual.device` |
| The entitlement is bound to OJD's team | Re-signing OJD with a different cert → `Killed: 9` |
| A third party can drive OJD | `feed_client` completes Challenge/Hello/FeedSession |
| The pad is real to macOS | `IOHIDManager` enumerates `Xbox Adaptive Controller 045e:0b0c` |
| Input actually propagates | Button press/change/release read back from HID elements |
| 4 pads at once | 4/4 sessions started, macOS enumerated 4 gamepads |
| Rumble reaches the client | 4/4 pads produced a `RumbleCommand` with intensities |
| No security changes needed | `csrutil status` = enabled, `boot-args` unset |

## Architecture

```
Moonlight client
      |  MSE / Moonlight input packets
      v
Sunshine  (platf::gamepad_update)
      |  nexus::ojd::sunshine::register/update
      v
nexus-ojd bridge  (this component)
      |  JSON lines over AF_UNIX
      v
OpenJoystickDriver endpoint
      |  IOHIDUserDevice (Apple-entitled)
      v
macOS HID  ->  games
```

The bridge is the only new part. It batches Sunshine's input rate (which can
exceed 100 Hz per pad) down to a bounded publish rate, sends `KeepAlive` when a
pad goes idle so OJD's 2-second feed timeout never fires, and releases the pad
cleanly on teardown.

## Design constraints that shaped this

1. **OJD frames are absolute, not incremental.** An omitted control is neutral,
   not "unchanged". `PadSession` therefore sends every control on every frame
   (`full_frame()`); a delta drops held buttons and snaps a held stick axis to
   center when the other axis moves. `diff_frame()` re-sends held buttons but
   only changed axes, so don't use it for the feed.
2. **Face buttons are positional.** Sunshine/Moonlight's `A` becomes OJD's
   `South`. On an Xbox pad they coincide; a DualSense label would not. Mapping by
   position is deliberate.
3. **Axis conventions already match.** Both use int16 sticks with positive Y
   down, so only scaling differs. There is no Y flip.
4. **`apiVersion` is alpha.** OJD is at `openjoystickdriver/v1alpha3` and the
   docs state an alpha "can change without a compatibility promise". All protocol
   strings live in `protocol.hpp`; an upstream bump should be one file.
5. **SIGPIPE is a real hazard.** OJD closes the socket when it refuses a line or
   times out. Every `send` uses `MSG_NOSIGNAL`; without it the host process dies.

## Layout

```
include/nexus/ojd/
  sha256.hpp         SHA-256 + HMAC-SHA256 (own impl, RFC-tested)
  protocol.hpp       frame/hello/keepalive rendering, OJD vocabulary
  reply.hpp          strict single-line reply parser
  feed_client.hpp    socket transport, handshake, feed lifecycle
  pad_session.hpp    per-pad pacing, KeepAlive, PadPool
  sunshine_bridge.hpp  small surface actually called from Sunshine
src/                  implementations + sunshine_adapter.cpp
tests/                unit tests, fake endpoint, live OJD checks
```

Everything except `sunshine_adapter.cpp` is free of Sunshine headers, so the
protocol core builds and tests without Sunshine or OJD.

## Rumble

OJD forwards each rumble a game requests to the feed client, on the same socket
as `FeedSession`, as a `RumbleCommand` line:

```json
{"apiVersion":"openjoystickdriver/v1alpha3","durationMilliseconds":250,
 "intensities":{"highFrequency":65535,"leftHaptic":0,"leftTrigger":0,
 "lowFrequency":65535,"rightHaptic":0,"rightTrigger":0},
 "kind":"RumbleCommand","type":"SetRumble"}
```

`PadSession` runs a reader thread for these and calls `SessionConfig::on_rumble`
with the slot. `sunshine_adapter.cpp` raises
`platf::gamepad_feedback_msg_t::make_rumble` onto Sunshine's feedback queue,
which is the same path a physical controller uses, so rumble returns to the
Moonlight client with no extra protocol work.

Intensities are 0..65535 on both sides, so there is no rescaling. `StopRumble`,
and a `SetRumble` with both main motors at zero, are forwarded as a zero rumble
so the motors stop.

**Getting a game to produce rumble at all** depends on the game, not on this
bridge: macOS delivers rumble to the virtual pad only when the application writes
a HID output report. Two practical notes from testing:

- A HID output report must include the report-ID byte in the buffer. For the
  `SDLCompatible` persona that means a **13-byte** buffer for report ID 9, not 12.
  Passing 12 bytes returns `kIOReturnBadArgument`.
- The `Generic` persona's format is input-only (`output_elements=0`), so rumble
  cannot work there. Use `SDLCompatible`.

## Test status

`tests/ojd_client_test.cpp` — 30 checks, all passing:

- SHA-256 and HMAC-SHA256 against RFC 6234 / RFC 4231 vectors
- Message rendering, JSON escaping, locale-independent number formatting
- Reply parsing: valid, malformed, truncated, unknown-field tolerance
- Rumble parsing: `SetRumble`, `StopRumble`, clamping of out-of-range values
- Button/axis mapping including positional face buttons
- Full handshake against a fake endpoint (success, no-grant, feed-refused)
- KeepAlive behaviour under idle

`tests/live_ojd_test.cpp`, `tests/live_input_test.mm` and
`tests/live_multipad_test.mm` — integration against a real OJD install, all PASS.

Not covered: reconnection after an OJD restart.

## What still needs doing

1. **Reconnect.** If OJD restarts, `PadSession` reports `io_failed` and stops.
   A retry with backoff would be better than requiring a stream restart.
2. **Config plumbing.** Socket path and token need to come from Sunshine's
   config rather than the compile-time defaults.
3. **Arrival metadata.** OJD picks the persona itself. Sunshine's
   `SS_CONTROLLER_ARRIVAL` type/capabilities are ignored, so motion and battery
   are unavailable for these pads.

## Practical notes for a 5-player session

OJD serves **4 virtual gamepads per endpoint client**, so the bridge tops out at
4 remote controllers. With 5 players that means one player uses a controller
attached to the host Mac, which Sunshine already reads as a physical device
(path `player_id == 1` in the Nexus flow). Plan seating accordingly: 4 virtual
pads plus 1 local.

## Upstreamability

Two things to raise with the Sunshine maintainers before proposing this
upstream:

- It adds a runtime dependency on a third-party app, in a noncommercial
  (PolyForm) license. LizardByte already sells the licensed alternative, so
  upstreaming this is a product decision, not just a technical one.
- OJD is pre-release alpha. Upstream may reasonably wait for a stable API.

A fork, or a local patch, avoids both questions. Recommendation: keep it a fork
until OJD 1.0 and until the maintainers have a view on the dependency.

## Reproducing the verification

```sh
# 1. Install OJD, grant Input Monitoring + Accessibility
open /Applications/OpenJoystickDriver.app
ojd permission request

# 2. Enable the endpoint and mint a Control token
ojd access enable --force
ojd access grant --token sunshine --scope read --scope control --force

# 3. Point the tests at it
SOCK=$(ojd --json access status | jq -r .socketPath)
cmake -S . -B build && cmake --build build
./build/ojd_client_test
./build/live_ojd_test "$SOCK" "$TOKEN"
./build/live_input_test "$SOCK" "$TOKEN"
```

Expect `All OJD client tests passed` and `RESULT: PASS` from both live checks.

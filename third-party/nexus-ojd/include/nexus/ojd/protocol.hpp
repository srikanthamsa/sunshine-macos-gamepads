// OpenJoystickDriver endpoint protocol messages.
//
// Pure data: no sockets, no Sunshine, no JSON library. Messages are rendered to
// the documented single-line JSON form, which keeps this testable and lets the
// transport stay trivial.
//
// Reference: OJD docs/sdk/endpoint.md, apiVersion openjoystickdriver/v1alpha3.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "nexus/ojd/sha256.hpp"

namespace nexus::ojd {

struct Reply;

/// The only endpoint version this client speaks. OJD accepts exactly the values
/// it lists in details.supportedAPIVersions; an alpha may bump this.
inline constexpr std::string_view kApiVersion{"openjoystickdriver/v1alpha3"};

/// Virtual gamepad personas OJD can present. They name no operating system.
enum class Persona {
  /// A plain HID gamepad.
  generic,
  /// An Xbox Adaptive Controller identity: what SDL and Steam read reliably.
  sdl_compatible,
};

[[nodiscard]] std::string_view to_string(Persona persona) noexcept;

/// Buttons and axes, named exactly as OJD's vocabulary schema requires.
/// Face buttons are positional: South=A, East=B, West=X, North=Y on Xbox.
enum class Button {
  south,
  east,
  west,
  north,
  left_shoulder,
  right_shoulder,
  back,
  start,
  left_stick_click,
  right_stick_click,
  dpad_up,
  dpad_down,
  dpad_left,
  dpad_right,
  guide,
  capture,
  microphone,
  touchpad_click,
};

[[nodiscard]] std::string_view to_string(Button button) noexcept;

enum class Axis {
  left_stick_x,
  left_stick_y,
  right_stick_x,
  right_stick_y,
  left_trigger,
  right_trigger,
};

[[nodiscard]] std::string_view to_string(Axis axis) noexcept;

/// One analog sample. Sticks run -1..1 with positive Y down; triggers 0..1.
/// OJD clamps out-of-range values, so this type does not.
struct AxisValue {
  Axis axis;
  double value;
};

/// One input frame. Omitted controls are neutral, so only changed controls need
/// to be present.
struct Frame {
  std::vector<Button> buttons;
  /// D-pad directions. OJD treats these as a separate field and ignores
  /// "DpadUp" and friends inside `buttons`, so they must be listed here.
  std::vector<Button> dpad;
  std::vector<AxisValue> axes;
  /// Minimum time to show this frame. Empty means "until the next frame".
  std::int32_t hold_milliseconds = -1;
};

namespace detail {

/// Render a double without locale dependence and without trailing zeros, so the
/// wire form is stable regardless of the host's locale.
[[nodiscard]] std::string render_number(double value);

/// Append a JSON string literal, escaping per RFC 8259.
void append_json_string(std::string &out, std::string_view text);

}  // namespace detail

/// Build the token proof OJD expects: HMAC-SHA256, keyed with SHA-256(token),
/// over four newline-terminated lines.
[[nodiscard]] std::string build_token_proof(std::string_view token, std::string_view nonce);

/// {"apiVersion":...,"kind":"Hello","scopes":["Control"],"tokenName":...,"proof":...}
[[nodiscard]] std::string build_hello_token(
    std::string_view token_name, std::string_view token, std::string_view nonce);

/// {"apiVersion":...,"kind":"Hello","scopes":["Control"]} for a signature grant.
[[nodiscard]] std::string build_hello_signature_grant();

/// {"apiVersion":...,"kind":"FeedRequest","as":"SDLCompatible"}
[[nodiscard]] std::string build_feed_request(Persona persona);

/// {"apiVersion":...,"kind":"Frame",...}
[[nodiscard]] std::string build_frame(const Frame &frame);

/// {"apiVersion":...,"kind":"KeepAlive"}
[[nodiscard]] std::string build_keepalive();

/// {"apiVersion":...,"kind":"Drain"}
[[nodiscard]] std::string build_drain();

/// A rumble request OJD received from a game and forwarded to the feed client.
/// Intensities are 0..65535, matching OJD's wire range.
struct RumbleCommand {
  /// True for SetRumble, false for StopRumble.
  bool set = false;
  std::uint16_t low_frequency = 0;
  std::uint16_t high_frequency = 0;
  std::uint16_t left_trigger = 0;
  std::uint16_t right_trigger = 0;
  /// How long the motors run, when OJD reports it.
  std::int32_t duration_milliseconds = -1;
};

/// Parse a `RumbleCommand` line. Returns nullopt for any other reply kind or a
/// malformed payload, so a caller can ignore unrelated lines.
[[nodiscard]] std::optional<RumbleCommand> parse_rumble_command(const Reply &reply);

}  // namespace nexus::ojd

// Sunshine adapter: the only translation unit that includes Sunshine headers.
//
// It implements the gamepad entry points Sunshine's macOS backend needs when
// libvirtualhid cannot create pads (no Apple-approved HID entitlement), by
// forwarding to an OpenJoystickDriver endpoint instead.
//
// The four functions here mirror the ones in src/platform/virtualhid_input.cpp
// under the `#ifndef _WIN32` block. See INTEGRATION.md for the patch.
#include "nexus/ojd/sunshine_adapter.hpp"

#include <array>
#include <mutex>

#include "nexus/ojd/sunshine_bridge.hpp"

// Sunshine. Included after the bridge so this file fails loudly if the bridge
// header ever grows a Sunshine dependency.
#include "src/platform/common.h"

namespace nexus::ojd::sunshine {

// Pin the duplicated Moonlight constants to Sunshine's real ones. If upstream
// renumbers a button, the build fails here instead of silently misrouting input.
namespace {
static_assert(moonlight::dpad_up == platf::DPAD_UP);
static_assert(moonlight::dpad_down == platf::DPAD_DOWN);
static_assert(moonlight::dpad_left == platf::DPAD_LEFT);
static_assert(moonlight::dpad_right == platf::DPAD_RIGHT);
static_assert(moonlight::start == platf::START);
static_assert(moonlight::back == platf::BACK);
static_assert(moonlight::left_stick == platf::LEFT_STICK);
static_assert(moonlight::right_stick == platf::RIGHT_STICK);
static_assert(moonlight::left_button == platf::LEFT_BUTTON);
static_assert(moonlight::right_button == platf::RIGHT_BUTTON);
static_assert(moonlight::home == platf::HOME);
static_assert(moonlight::a == platf::A);
static_assert(moonlight::b == platf::B);
static_assert(moonlight::x == platf::X);
static_assert(moonlight::y == platf::Y);
static_assert(moonlight::paddle1 == platf::PADDLE1);
static_assert(moonlight::paddle2 == platf::PADDLE2);
static_assert(moonlight::paddle3 == platf::PADDLE3);
static_assert(moonlight::paddle4 == platf::PADDLE4);
static_assert(moonlight::touchpad_button == platf::TOUCHPAD_BUTTON);
static_assert(moonlight::misc_button == platf::MISC_BUTTON);
}  // namespace

namespace {
/// Where one pad's rumble goes: the owning session's feedback queue and the
/// pad's index within that client, which is what Moonlight's messages carry.
struct FeedbackRoute {
  bool allocated = false;
  std::uint8_t client_relative_index = 0;
  FeedbackSink sink;
  bool trigger_rumble = false;  ///< Last command moved the trigger motors.
};

std::mutex route_mutex;
std::array<FeedbackRoute, kMaxVirtualPads> routes;
std::once_flag rumble_handler_once;

/// Runs on a pad's rumble thread. A stop (or the expiry PadSession synthesizes)
/// arrives as set == false and zeroes every motor.
void forward_rumble(int slot, const RumbleCommand &command) {
  if (slot < 0 || slot >= kMaxVirtualPads) {
    return;
  }
  std::lock_guard lock(route_mutex);
  auto &route = routes[slot];
  if (!route.allocated || !route.sink) {
    return;
  }

  const auto value = [&command](std::uint16_t v) -> std::uint16_t { return command.set ? v : 0; };
  route.sink(platf::gamepad_feedback_msg_t::make_rumble(
      route.client_relative_index, value(command.low_frequency), value(command.high_frequency)));

  const bool triggers = value(command.left_trigger) || value(command.right_trigger);
  if (triggers || route.trigger_rumble) {
    route.sink(platf::gamepad_feedback_msg_t::make_rumble_triggers(
        route.client_relative_index, value(command.left_trigger), value(command.right_trigger)));
  }
  route.trigger_rumble = triggers;
}
}  // namespace

/// Sunshine entry point: allocate a virtual pad in `id.globalIndex`.
int alloc_gamepad(int slot, std::uint8_t client_relative_index, FeedbackSink feedback) {
  // OJD creates the pad on the first frame, so allocation only records intent.
  // A failure surfaces on the first update, which is where OJD reports
  // permission and license problems.
  if (global_bridge().availability() != Availability::ready) {
    return -1;
  }
  if (slot < 0 || slot >= kMaxVirtualPads) {
    return -1;
  }

  // Installing the handler rebuilds the bridge's pad pool, so do it once, before
  // the first update creates any pads. Pads without a sink drop their rumble.
  std::call_once(rumble_handler_once, []() { global_bridge().set_rumble_handler(forward_rumble); });

  std::lock_guard lock(route_mutex);
  routes[slot] = FeedbackRoute{true, client_relative_index, std::move(feedback), false};
  return 0;
}

/// Sunshine entry point: route an existing pad's feedback to a resumed session.
bool rebind_gamepad(int slot, std::uint8_t client_relative_index, FeedbackSink feedback) {
  if (slot < 0 || slot >= kMaxVirtualPads) {
    return false;
  }
  std::lock_guard lock(route_mutex);
  auto &route = routes[slot];
  if (!route.allocated) {
    return false;
  }
  route.client_relative_index = client_relative_index;
  route.sink = std::move(feedback);
  route.trigger_rumble = false;
  return true;
}

/// Sunshine entry point: release a virtual pad.
void free_gamepad(int slot) {
  if (slot >= 0 && slot < kMaxVirtualPads) {
    std::lock_guard lock(route_mutex);
    routes[slot] = FeedbackRoute{};
  }
  global_bridge().release(slot);
}

/// Sunshine entry point: submit a full gamepad state.
bool submit_gamepad(int slot, const platf::gamepad_state_t &state) {
  return global_bridge().update(
      slot, state.buttonFlags, state.lt, state.rt,
      state.lsX, state.lsY, state.rsX, state.rsY);
}

// Rumble goes back only to the session that owns the pad: alloc_gamepad() and
// rebind_gamepad() record each slot's feedback queue and client-relative index,
// the same routing libvirtualhid pads get. It stays off unless the caller passes
// a sink (Sunshine's `ojd_rumble` option).

}  // namespace nexus::ojd::sunshine

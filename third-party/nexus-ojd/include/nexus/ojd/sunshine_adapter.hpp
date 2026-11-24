// Declarations for the Sunshine-side OJD adapter.
//
// Kept separate from src/sunshine_adapter.cpp so Sunshine's input backend can
// call these without including Sunshine headers itself. The definitions live in
// the adapter TU, which does include src/platform/common.h.
#pragma once

#include <cstdint>
#include <functional>

// Forward declaration keeps this header usable from Sunshine's backend.
namespace platf {
struct gamepad_state_t;
struct gamepad_feedback_msg_t;
}

namespace nexus::ojd::sunshine {

/// Delivers feedback (rumble) for one pad to the Moonlight session that owns it.
/// Empty means feedback for that pad is dropped.
using FeedbackSink = std::function<void(const platf::gamepad_feedback_msg_t &)>;

/// Allocate a virtual pad in `slot`. `client_relative_index` and `feedback` route
/// the pad's rumble back to its client; pass an empty sink to leave rumble off.
/// Returns 0 on success, -1 when the backend is unavailable or the slot is out of
/// range.
int alloc_gamepad(int slot, std::uint8_t client_relative_index, FeedbackSink feedback);

/// Point an existing pad's feedback at a resumed session. Returns false when
/// `slot` is not an OJD pad, so the caller can try its other backend.
bool rebind_gamepad(int slot, std::uint8_t client_relative_index, FeedbackSink feedback);

/// Release the virtual pad in `slot`. Safe to call for a slot with no pad.
void free_gamepad(int slot);

/// Submit a gamepad state. Returns true when the OJD backend handled it, false
/// when the caller should fall back to libvirtualhid.
bool submit_gamepad(int slot, const platf::gamepad_state_t &state);

}  // namespace nexus::ojd::sunshine

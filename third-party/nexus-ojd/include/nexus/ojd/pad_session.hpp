// Pad sessions: turn Sunshine's per-packet gamepad updates into OJD frames.
//
// Sunshine calls gamepad_update() on every input packet, which can exceed 100 Hz
// per pad. OJD plays a frame for at least 8 ms and stops reading while 256
// frames wait, so sending every update would add latency for no benefit. Each
// session therefore keeps the newest state and a sender thread publishing at a
// bounded rate, sending KeepAlive when a pad goes idle so the 2-second feed
// timeout never fires.
#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "nexus/ojd/feed_client.hpp"
#include "nexus/ojd/state_mapping.hpp"

namespace nexus::ojd {

struct SessionConfig {
  std::string socket_path;
  std::string token;
  std::string token_name;
  Persona persona = Persona::sdl_compatible;
  /// Maximum frames per second published to OJD for one pad.
  int max_fps = 120;
  /// Send KeepAlive when no frame has been published for this long. Must stay
  /// well under OJD's 2-second idle timeout.
  std::chrono::milliseconds keepalive_after{750};
  /// Upper bound on pads this pool will create. OJD serves 4 per endpoint.
  int max_pads = 4;
  /// Reconnect after the feed fails, so a restarted OJD does not require a
  /// stream restart. Backoff doubles from `reconnect_initial` to
  /// `reconnect_max`.
  bool reconnect = true;
  std::chrono::milliseconds reconnect_initial{250};
  std::chrono::milliseconds reconnect_max{5000};
  /// Called on the session's reader thread when a game requests rumble for this
  /// pad. The first argument is the slot this session was created for. Must be
  /// cheap and must not call back into the session.
  std::function<void(int slot, const RumbleCommand &)> on_rumble;
};

/// One virtual gamepad backed by an OJD feed.
class PadSession {
 public:
  PadSession(int slot, SessionConfig config);
  ~PadSession();

  PadSession(const PadSession &) = delete;
  PadSession &operator=(const PadSession &) = delete;

  /// Connect and create the virtual pad. Idempotent while connected.
  [[nodiscard]] ConnectResult start();

  /// Publish new state. Non-blocking; safe to call from the input thread.
  void update(const GamepadState &state);

  /// Close the feed, removing the virtual pad.
  void stop();

  [[nodiscard]] bool running() const;
  [[nodiscard]] int slot() const { return slot_; }
  /// Last connect error, for reporting.
  [[nodiscard]] ConnectError last_error() const;
  /// Number of successful reconnects so far, for diagnostics.
  [[nodiscard]] int reconnect_count() const;

 private:
  void run();
  void read_rumble();
  /// Reconnect after a failed feed. Returns false when the session should stop.
  bool reconnect_locked();

  int slot_;
  SessionConfig config_;
  FeedClient client_;

  std::thread thread_;
  std::thread rumble_thread_;
  mutable std::mutex mutex_;
  std::condition_variable wake_;

  GamepadState pending_{};
  bool has_pending_ = false;
  bool stop_requested_ = false;
  bool running_ = false;
  ConnectError last_error_ = ConnectError::none;
  int reconnect_count_ = 0;
};

/// Owns the sessions for a Sunshine stream's gamepad slots.
class PadPool {
 public:
  explicit PadPool(SessionConfig config);
  ~PadPool();

  PadPool(const PadPool &) = delete;
  PadPool &operator=(const PadPool &) = delete;

  /// Create or update the pad in `slot`. Returns false when the pad could not
  /// be started; the error is reported through last_error().
  bool update(int slot, const GamepadState &state);

  /// Remove the pad in `slot`.
  void release(int slot);

  /// Remove every pad.
  void release_all();

  [[nodiscard]] ConnectError last_error() const;
  [[nodiscard]] const SessionConfig &config() const { return config_; }

 private:
  SessionConfig config_;
  mutable std::mutex mutex_;
  std::vector<std::unique_ptr<PadSession>> sessions_;
};

}  // namespace nexus::ojd

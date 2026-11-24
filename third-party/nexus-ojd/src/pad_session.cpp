#include "nexus/ojd/pad_session.hpp"

#include <algorithm>
#include <optional>

namespace nexus::ojd {

PadSession::PadSession(int slot, SessionConfig config)
    : slot_(slot), config_(std::move(config)) {}

PadSession::~PadSession() {
  stop();
}

bool PadSession::running() const {
  std::lock_guard lock(mutex_);
  return running_;
}

ConnectError PadSession::last_error() const {
  std::lock_guard lock(mutex_);
  return last_error_;
}

int PadSession::reconnect_count() const {
  std::lock_guard lock(mutex_);
  return reconnect_count_;
}

ConnectResult PadSession::start() {
  {
    std::lock_guard lock(mutex_);
    if (running_) {
      return {};
    }
    stop_requested_ = false;
  }

  FeedConfig feed;
  feed.socket_path = config_.socket_path;
  feed.token = config_.token;
  feed.token_name = config_.token_name;
  feed.persona = config_.persona;

  const ConnectResult result = client_.connect(feed);
  if (!result.ok()) {
    std::lock_guard lock(mutex_);
    last_error_ = result.error;
    running_ = false;
    return result;
  }

  {
    std::lock_guard lock(mutex_);
    last_error_ = ConnectError::none;
    running_ = true;
  }
  thread_ = std::thread([this]() { run(); });
  if (config_.on_rumble) {
    rumble_thread_ = std::thread([this]() { read_rumble(); });
  }
  return result;
}

/// Reconnect this pad after the feed failed. Returns false when the session
/// should give up (reconnect disabled, or the pool is shutting down).
///
/// Called from the frame thread, which owns no lock at this point.
bool PadSession::reconnect_locked() {
  {
    std::lock_guard lock(mutex_);
    if (stop_requested_ || !config_.reconnect) {
      last_error_ = ConnectError::io_failed;
      running_ = false;
      return false;
    }
  }

  client_.disconnect();

  auto backoff = config_.reconnect_initial;
  while (true) {
    {
      std::lock_guard lock(mutex_);
      if (stop_requested_) {
        last_error_ = ConnectError::io_failed;
        running_ = false;
        return false;
      }
    }

    FeedConfig feed;
    feed.socket_path = config_.socket_path;
    feed.token = config_.token;
    feed.token_name = config_.token_name;
    feed.persona = config_.persona;

    const auto result = client_.connect(feed);
    if (result.ok()) {
      std::lock_guard lock(mutex_);
      ++reconnect_count_;
      last_error_ = ConnectError::none;
      running_ = true;
      has_pending_ = false;
      return true;
    }

    // A refused token or a missing grant will not fix itself by retrying, so
    // stop and report it instead of spinning.
    if (result.error == ConnectError::not_granted ||
        result.error == ConnectError::endpoint_disabled ||
        result.error == ConnectError::unsupported_api) {
      std::lock_guard lock(mutex_);
      last_error_ = result.error;
      running_ = false;
      return false;
    }

    // Wait out the backoff, waking early for shutdown.
    std::unique_lock lock(mutex_);
    wake_.wait_for(lock, backoff, [this]() { return stop_requested_; });
    backoff = std::min(backoff * 2, config_.reconnect_max);
  }
}

void PadSession::read_rumble() {
  using clock = std::chrono::steady_clock;
  // A SetRumble carries how long the motors should run. A real pad stops on its
  // own when that runs out, but the client forwarding this (Moonlight) keeps
  // rumbling until told otherwise, so synthesize the stop if nothing newer came.
  std::optional<clock::time_point> expires;

  while (true) {
    {
      std::lock_guard lock(mutex_);
      if (stop_requested_) {
        break;
      }
    }

    auto timeout = std::chrono::milliseconds(100);
    if (expires) {
      const auto left =
          std::chrono::ceil<std::chrono::milliseconds>(*expires - clock::now());
      timeout = std::clamp(left, std::chrono::milliseconds(1), timeout);
    }

    const auto command = client_.wait_for_rumble(timeout);
    if (!command) {
      if (expires && clock::now() >= *expires) {
        expires.reset();
        if (config_.on_rumble) {
          config_.on_rumble(slot_, RumbleCommand{});
        }
      }
      continue;
    }

    const bool running = command->set && (command->low_frequency || command->high_frequency ||
                                          command->left_trigger || command->right_trigger);
    if (running && command->duration_milliseconds > 0) {
      expires = clock::now() + std::chrono::milliseconds(command->duration_milliseconds);
    } else {
      expires.reset();
    }
    if (config_.on_rumble) {
      config_.on_rumble(slot_, *command);
    }
  }
}

void PadSession::update(const GamepadState &state) {
  {
    std::lock_guard lock(mutex_);
    if (!running_) {
      return;
    }
    pending_ = state;
    has_pending_ = true;
  }
  wake_.notify_one();
}

void PadSession::run() {
  const auto frame_period = std::chrono::microseconds(
      config_.max_fps > 0 ? 1'000'000 / config_.max_fps : 8'000);
  auto last_send = std::chrono::steady_clock::now() - config_.keepalive_after;

  while (true) {
    GamepadState state;
    bool send = false;
    bool keepalive = false;

    {
      std::unique_lock lock(mutex_);
      if (stop_requested_) {
        break;
      }

      // Wake for a new frame, for the keepalive deadline, or for shutdown.
      wake_.wait_for(lock, std::min<std::chrono::milliseconds>(
                                std::chrono::duration_cast<std::chrono::milliseconds>(frame_period),
                                config_.keepalive_after),
                     [this]() { return stop_requested_ || has_pending_; });

      if (stop_requested_) {
        break;
      }

      const auto now = std::chrono::steady_clock::now();
      if (has_pending_) {
        state = pending_;
        has_pending_ = false;
        send = true;
      } else if (now - last_send >= config_.keepalive_after) {
        keepalive = true;
      }
    }

    if (send) {
      // OJD treats an omitted control as neutral, so every frame carries the whole
      // state. A diff would drop a held stick axis whenever the other axis moved.
      Frame frame = full_frame(state);
      if (!client_.send_frame(frame)) {
        if (!reconnect_locked()) {
          break;
        }
        last_send = std::chrono::steady_clock::now();
        continue;
      }
      last_send = std::chrono::steady_clock::now();
    } else if (keepalive) {
      if (!client_.send_keepalive()) {
        if (!reconnect_locked()) {
          break;
        }
        last_send = std::chrono::steady_clock::now();
        continue;
      }
      last_send = std::chrono::steady_clock::now();
    }
  }

  client_.disconnect();
  std::lock_guard lock(mutex_);
  running_ = false;
}

void PadSession::stop() {
  {
    std::lock_guard lock(mutex_);
    stop_requested_ = true;
  }
  wake_.notify_all();
  if (thread_.joinable()) {
    thread_.join();
  }
  // Join the reader before closing the socket: it owns the read side, and
  // disconnect() also reads a Drained reply.
  if (rumble_thread_.joinable()) {
    rumble_thread_.join();
  }
  client_.disconnect();
  std::lock_guard lock(mutex_);
  running_ = false;
}

PadPool::PadPool(SessionConfig config) : config_(std::move(config)) {}

PadPool::~PadPool() {
  release_all();
}

bool PadPool::update(int slot, const GamepadState &state) {
  if (slot < 0 || slot >= config_.max_pads) {
    return false;
  }

  // Find or create the session without starting it, then release the pool lock
  // before the blocking handshake so other pads keep flowing.
  PadSession *session = nullptr;
  bool need_start = false;
  {
    std::lock_guard lock(mutex_);
    if (static_cast<int>(sessions_.size()) <= slot) {
      sessions_.resize(static_cast<std::size_t>(slot) + 1);
    }
    auto &entry = sessions_[static_cast<std::size_t>(slot)];
    if (!entry) {
      entry = std::make_unique<PadSession>(slot, config_);
      need_start = true;
    }
    session = entry.get();
  }

  session->update(state);
  if (!need_start) {
    // A session that gave up (bad token, reconnect disabled) would otherwise
    // swallow every update silently. Recreate it so the next packet retries.
    if (!session->running() && session->last_error() != ConnectError::none) {
      std::lock_guard lock(mutex_);
      auto &entry = sessions_[static_cast<std::size_t>(slot)];
      entry.reset();
      entry = std::make_unique<PadSession>(slot, config_);
      session = entry.get();
      need_start = true;
    } else {
      return true;
    }
  }

  const auto result = session->start();
  if (!result.ok()) {
    // Keep the failed session so last_error() can report why, but do not retry
    // on every packet; the caller can call release() to clear it.
    return false;
  }

  // Re-publish the newest state now that the feed exists, so the first frame
  // reflects what was pressed during the handshake.
  session->update(state);
  return true;
}

void PadPool::release(int slot) {
  std::lock_guard lock(mutex_);
  if (slot < 0 || static_cast<int>(sessions_.size()) <= slot) {
    return;
  }
  if (auto &entry = sessions_[static_cast<std::size_t>(slot)]) {
    entry->stop();
    entry.reset();
  }
}

void PadPool::release_all() {
  std::vector<std::unique_ptr<PadSession>> sessions;
  {
    std::lock_guard lock(mutex_);
    sessions.swap(sessions_);
  }
  for (auto &session : sessions) {
    if (session) {
      session->stop();
    }
  }
}

ConnectError PadPool::last_error() const {
  std::lock_guard lock(mutex_);
  for (const auto &session : sessions_) {
    if (session) {
      const auto error = session->last_error();
      if (error != ConnectError::none) {
        return error;
      }
    }
  }
  return ConnectError::none;
}

}  // namespace nexus::ojd

// Tests for the OJD endpoint client.
//
// The protocol core builds without OJD, Sunshine, or a socket, so most coverage
// runs anywhere. The integration test stands up a fake endpoint that speaks the
// documented handshake, which validates the wire format without a licensed HID
// backend.
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "nexus/ojd/feed_client.hpp"
#include "nexus/ojd/pad_session.hpp"
#include "nexus/ojd/protocol.hpp"
#include "nexus/ojd/reply.hpp"
#include "nexus/ojd/sha256.hpp"
#include "nexus/ojd/state_mapping.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const std::string &what) {
  if (!condition) {
    std::cerr << "FAIL: " << what << '\n';
    ++g_failures;
  }
}

template <typename T>
std::string describe(const T &value) {
  if constexpr (std::is_same_v<T, std::uint8_t> || std::is_same_v<T, std::int8_t>) {
    return std::to_string(static_cast<int>(value));
  } else if constexpr (std::is_same_v<T, nexus::ojd::ConnectError>) {
    return std::string(nexus::ojd::to_string(value));
  } else {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  }
}

template <typename T>
void check_eq(const T &actual, const T &expected, const std::string &what) {
  if (!(actual == expected)) {
    std::cerr << "FAIL: " << what << " (actual=" << describe(actual)
              << " expected=" << describe(expected) << ")\n";
    ++g_failures;
  }
}

using namespace nexus::ojd;

// -- hashing ---------------------------------------------------------------

void test_sha256_vectors() {
  // FIPS 180-2 / RFC 6234 vectors.
  check_eq(to_hex(sha256("")),
           std::string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
           "sha256 empty");
  check_eq(to_hex(sha256("abc")),
           std::string{"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
           "sha256 abc");
  check_eq(to_hex(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
           std::string{"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
           "sha256 two-block message");
}

void test_hmac_vectors() {
  // RFC 4231 test cases 1, 2 and 6.
  auto hmac = [](std::string_view key, std::string_view data) {
    return to_hex(hmac_sha256(
        reinterpret_cast<const std::uint8_t *>(key.data()), key.size(),
        reinterpret_cast<const std::uint8_t *>(data.data()), data.size()));
  };

  check_eq(hmac(std::string(20, '\x0b'), "Hi There"),
           std::string{"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
           "hmac rfc4231 case 1");

  check_eq(hmac("Jefe", "what do ya want for nothing?"),
           std::string{"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
           "hmac rfc4231 case 2");

  check_eq(hmac(std::string(131, '\xaa'),
                "Test Using Larger Than Block-Size Key - Hash Key First"),
           std::string{"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
           "hmac rfc4231 case 6 (key longer than block)");
}

// -- token proof -----------------------------------------------------------

void test_token_proof_shape() {
  const auto proof = build_token_proof("ojd_test_token", "bm9uY2U");
  check_eq(proof.size(), std::size_t{64}, "proof is 64 hex chars");
  for (const char c : proof) {
    check((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'), "proof is lowercase hex");
  }

  // The proof must depend on both the token and the nonce.
  const auto same_token_other_nonce = build_token_proof("ojd_test_token", "bm9uY2Uy");
  check(proof != same_token_other_nonce, "proof changes with nonce");

  const auto other_token = build_token_proof("ojd_other_token", "bm9uY2U");
  check(proof != other_token, "proof changes with token");
}

// -- message rendering -----------------------------------------------------

void test_hello_token_message() {
  const auto hello = build_hello_token("driver", "ojd_secret", "bm9uY2U");
  check(hello.find("\"kind\":\"Hello\"") != std::string::npos, "hello has kind");
  check(hello.find("openjoystickdriver/v1alpha3") != std::string::npos, "hello has apiVersion");
  check(hello.find("\"scopes\":[\"Control\"]") != std::string::npos, "hello requests Control");
  check(hello.find("\"tokenName\":\"driver\"") != std::string::npos, "hello names token");
  check(hello.find("ojd_secret") == std::string::npos, "token itself is never sent");

  // Must be a single line: OJD is line-delimited.
  check(hello.find('\n') == std::string::npos, "hello is one line");
}

void test_frame_message() {
  Frame frame;
  frame.buttons = {Button::south, Button::dpad_up};
  frame.axes = {{Axis::left_stick_x, -0.75}, {Axis::left_trigger, 1.0}};
  frame.hold_milliseconds = 100;

  const auto text = build_frame(frame);
  check(text.find("\"kind\":\"Frame\"") != std::string::npos, "frame has kind");
  check(text.find("\"buttons\":[\"South\",\"DpadUp\"]") != std::string::npos,
        "frame renders buttons positionally");
  check(text.find("\"LeftStickX\":-0.75") != std::string::npos, "frame renders negative axis");
  check(text.find("\"LeftTrigger\":1") != std::string::npos, "frame trims trailing zeros");
  check(text.find("\"holdMilliseconds\":100") != std::string::npos, "frame renders hold");
  check(text.find('\n') == std::string::npos, "frame is one line");
  // Must contain no whitespace, since it is compact JSON.
  check(text.find(' ') == std::string::npos, "frame is compact");
}

void test_frame_neutral() {
  const auto text = build_frame(Frame{});
  check_eq(text, std::string{"{\"apiVersion\":\"openjoystickdriver/v1alpha3\",\"kind\":\"Frame\"}"},
           "empty frame is just apiVersion and kind");
}

void test_number_rendering_edge_cases() {
  Frame frame;
  frame.axes = {{Axis::left_stick_x, 0.0},
                {Axis::left_stick_y, -0.0},
                {Axis::right_stick_x, 1.0},
                {Axis::right_stick_y, -1.0},
                {Axis::left_trigger, 0.5}};
  const auto text = build_frame(frame);
  check(text.find("\"LeftStickX\":0") != std::string::npos, "zero renders as 0");
  check(text.find("\"LeftStickY\":0") != std::string::npos, "negative zero normalises to 0");
  check(text.find("-0,") == std::string::npos && text.find("-0}") == std::string::npos,
        "no negative zero on the wire");
  check(text.find("\"RightStickX\":1,") != std::string::npos ||
            text.find("\"RightStickX\":1}") != std::string::npos,
        "one renders without decimals");
}

void test_keepalive_and_drain() {
  check(build_keepalive().find("\"kind\":\"KeepAlive\"") != std::string::npos, "keepalive kind");
  check(build_drain().find("\"kind\":\"Drain\"") != std::string::npos, "drain kind");
  check(build_feed_request(Persona::sdl_compatible).find("\"as\":\"SDLCompatible\"") !=
            std::string::npos,
        "feed request persona");
  check(build_feed_request(Persona::generic).find("\"as\":\"Generic\"") != std::string::npos,
        "generic persona");
}

void test_json_escaping() {
  const auto hello = build_hello_token("a\"b\\c", "token", "nonce");
  check(hello.find("a\\\"b\\\\c") != std::string::npos, "quotes and backslashes escaped");
}

// -- reply parsing ---------------------------------------------------------

void test_parse_challenge() {
  const auto reply = parse_reply(
      R"({"apiVersion":"openjoystickdriver/v1alpha3","kind":"Challenge","nonce":"ABC-123"})");
  check(reply.has_value(), "challenge parses");
  if (reply) {
    check_eq(reply->kind, std::string{"Challenge"}, "challenge kind");
    check_eq(reply->nonce, std::string{"ABC-123"}, "challenge nonce");
  }
}

void test_parse_welcome() {
  const auto reply = parse_reply(
      R"({"apiVersion":"openjoystickdriver/v1alpha3","kind":"Welcome","version":"0.6.0-alpha.2","scopes":["Control"]})");
  check(reply.has_value(), "welcome parses");
  if (reply) {
    check_eq(reply->kind, std::string{"Welcome"}, "welcome kind");
    check_eq(reply->version, std::string{"0.6.0-alpha.2"}, "welcome version");
    check(reply->has_scope("Control"), "welcome grants Control");
    check(reply->has_scope("control"), "scope compare is case-insensitive");
    check(!reply->has_scope("Read"), "read not granted");
  }
}

void test_parse_status_failure() {
  const auto reply = parse_reply(
      R"({"apiVersion":"openjoystickdriver/v1alpha3","code":"E1002","kind":"Status","message":"The program has no grant.","status":"Failure"})");
  check(reply.has_value(), "status parses");
  if (reply) {
    check(reply->is_failure(), "status is failure");
    check_eq(reply->code, std::string{"E1002"}, "status code");
  }
}

void test_parse_version_error_details() {
  const auto reply = parse_reply(
      R"({"apiVersion":"x","kind":"Status","status":"Failure","code":"E1009","message":"bad","details":{"supportedAPIVersions":["openjoystickdriver/v1alpha3"]}})");
  check(reply.has_value(), "version error parses");
  if (reply) {
    check_eq(reply->supported_versions.size(), std::size_t{1}, "supported versions captured");
    if (!reply->supported_versions.empty()) {
      check_eq(reply->supported_versions[0], std::string{"openjoystickdriver/v1alpha3"},
               "supported version value");
    }
  }
}

void test_parse_rejects_malformed() {
  check(!parse_reply("").has_value(), "empty rejected");
  check(!parse_reply("not json").has_value(), "garbage rejected");
  check(!parse_reply(R"({"kind":"Challenge")").has_value(), "truncated rejected");
  check(!parse_reply(R"({"kind":123})").has_value(), "non-string kind rejected");
  check(!parse_reply(R"({"nonce":"x"})").has_value(), "missing kind rejected");
  check(!parse_reply(R"({"kind":"Challenge"} trailing)").has_value(), "trailing data rejected");
}

void test_parse_skips_unknown_fields() {
  // Additive upstream fields must not break the client.
  const auto reply = parse_reply(
      R"({"apiVersion":"v","kind":"Challenge","nonce":"n","future":{"a":[1,2,{"b":null}]},"extra":true})");
  check(reply.has_value(), "unknown fields skipped");
  if (reply) {
    check_eq(reply->nonce, std::string{"n"}, "nonce still parsed");
  }
}

// -- state mapping ---------------------------------------------------------

void test_button_mapping_positions() {
  // Moonlight A must become South, not "A": OJD names buttons by position.
  GamepadState state;
  state.button_flags = moonlight::a;
  const auto frame = full_frame(state);
  check_eq(frame.buttons.size(), std::size_t{1}, "one button");
  if (!frame.buttons.empty()) {
    check(frame.buttons[0] == Button::south, "Moonlight A -> South");
  }

  state.button_flags = moonlight::y;
  const auto north = full_frame(state);
  check(!north.buttons.empty() && north.buttons[0] == Button::north, "Moonlight Y -> North");
}

void test_dpad_uses_its_own_field() {
  // OJD ignores "DpadUp" inside `buttons` and requires a separate `dpad` array.
  // Sending them as buttons made the d-pad do nothing at all.
  const std::pair<std::uint32_t, Button> cases[] = {
      {moonlight::dpad_up, Button::dpad_up},
      {moonlight::dpad_down, Button::dpad_down},
      {moonlight::dpad_left, Button::dpad_left},
      {moonlight::dpad_right, Button::dpad_right},
  };

  for (const auto &[bit, expected] : cases) {
    GamepadState state;
    state.button_flags = bit;
    const auto frame = full_frame(state);

    check_eq(frame.dpad.size(), std::size_t{1}, "dpad direction lands in frame.dpad");
    check_eq(frame.buttons.size(), std::size_t{0}, "dpad direction stays out of frame.buttons");
    if (!frame.dpad.empty()) {
      check(frame.dpad[0] == expected, "dpad direction maps to the right OJD control");
    }
  }
}

void test_dpad_frame_json() {
  GamepadState state;
  state.button_flags = moonlight::dpad_up;
  const auto text = build_frame(full_frame(state));
  check(text.find("\"dpad\":[\"DpadUp\"]") != std::string::npos,
        "frame renders a dpad array");
  check(text.find("\"buttons\"") == std::string::npos,
        "a pure d-pad frame carries no buttons key");
}

void test_all_buttons_map() {
  struct Case {
    std::uint32_t bit;
    Button expected;
    const char *name;
  };
  const std::vector<Case> cases{
      {moonlight::a, Button::south, "A"},
      {moonlight::b, Button::east, "B"},
      {moonlight::x, Button::west, "X"},
      {moonlight::y, Button::north, "Y"},
      {moonlight::left_button, Button::left_shoulder, "LB"},
      {moonlight::right_button, Button::right_shoulder, "RB"},
      {moonlight::back, Button::back, "Back"},
      {moonlight::start, Button::start, "Start"},
      {moonlight::home, Button::guide, "Guide"},
      {moonlight::left_stick, Button::left_stick_click, "LS"},
      {moonlight::right_stick, Button::right_stick_click, "RS"},
  };
  for (const auto &test : cases) {
    GamepadState state;
    state.button_flags = test.bit;
    const auto frame = full_frame(state);
    check_eq(frame.buttons.size(), std::size_t{1}, std::string("maps ") + test.name);
    if (!frame.buttons.empty()) {
      check(frame.buttons[0] == test.expected, std::string("correct target for ") + test.name);
    }
  }
}

void test_axis_scaling() {
  GamepadState state;
  state.lx = -32768;
  state.ly = 32767;
  const auto frame = full_frame(state);

  double left_x = 0, left_y = 0;
  for (const auto &axis : frame.axes) {
    if (axis.axis == Axis::left_stick_x) left_x = axis.value;
    if (axis.axis == Axis::left_stick_y) left_y = axis.value;
  }
  check_eq(left_x, -1.0, "int16 min maps to -1.0 on X");
  // OJD's Y is inverted relative to Moonlight: ly=+32767 is "down" in Moonlight,
  // and must reach OJD as a negative LeftStickY.
  check(left_y < -0.999 && left_y >= -1.0, "Moonlight stick-down maps to negative OJD Y");

  GamepadState up;
  up.ly = -32768;
  const auto upFrame = full_frame(up);
  for (const auto &axis : upFrame.axes) {
    if (axis.axis == Axis::left_stick_y) {
      check(axis.value > 0.999 && axis.value <= 1.0, "Moonlight stick-up maps to positive OJD Y");
    }
  }

  GamepadState centered;
  const auto neutral = full_frame(centered);
  for (const auto &axis : neutral.axes) {
    check_eq(axis.value, 0.0, std::string("centred axis is 0: ") + std::string(to_string(axis.axis)));
  }
}

void test_trigger_scaling() {
  GamepadState state;
  state.lt = 0;
  state.rt = 255;
  const auto frame = full_frame(state);
  for (const auto &axis : frame.axes) {
    if (axis.axis == Axis::left_trigger) check_eq(axis.value, 0.0, "lt 0 -> 0.0");
    if (axis.axis == Axis::right_trigger) check_eq(axis.value, 1.0, "rt 255 -> 1.0");
  }

  state.rt = 128;
  const auto half = full_frame(state);
  for (const auto &axis : half.axes) {
    if (axis.axis == Axis::right_trigger) {
      check(axis.value > 0.49 && axis.value < 0.51, "rt 128 -> ~0.5");
    }
  }
}

void test_diff_frame_keeps_held_buttons() {
  GamepadState previous;
  previous.button_flags = moonlight::a;
  GamepadState current;
  current.button_flags = moonlight::a;  // still held

  const auto frame = diff_frame(previous, current);
  // OJD frames are absolute, so a held button must still be listed or it drops.
  check_eq(frame.buttons.size(), std::size_t{1}, "held button re-sent");
  check_eq(frame.axes.size(), std::size_t{0}, "unchanged axes omitted");
}

void test_diff_frame_reports_changes() {
  GamepadState previous;
  GamepadState current;
  current.lx = 16000;

  const auto frame = diff_frame(previous, current);
  check(frame.axes.size() >= 1, "changed axis emitted");
  bool found = false;
  for (const auto &axis : frame.axes) {
    if (axis.axis == Axis::left_stick_x) {
      found = true;
      check(axis.value > 0.4, "axis carries new value");
    }
  }
  check(found, "left stick x present");
}

// -- fake endpoint ---------------------------------------------------------

/// A minimal endpoint that speaks the real handshake, so the client is tested
/// against the wire format rather than mocks.
class FakeEndpoint {
 public:
  explicit FakeEndpoint(std::string nonce = "test-nonce-123")
      : nonce_(std::move(nonce)) {}

  ~FakeEndpoint() {
    stop();
    if (!path_.empty()) ::unlink(path_.c_str());
  }

  bool start() {
    path_ = "/tmp/ojd_test_" + std::to_string(::getpid()) + "_" +
            std::to_string(reinterpret_cast<std::uintptr_t>(this) % 100000) + ".sock";
    ::unlink(path_.c_str());

    listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_ < 0) return false;

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, path_.c_str(), sizeof(address.sun_path) - 1);
    if (::bind(listen_fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
      return false;
    }
    if (::listen(listen_fd_, 4) != 0) return false;

    thread_ = std::thread([this]() { serve(); });
    return true;
  }

  const std::string &path() const { return path_; }
  void set_refuse_feed(std::string code) { refuse_code_ = std::move(code); }
  void set_no_control_scope(bool value) { omit_control_ = value; }
  std::size_t frames_received() const { return frames_.load(); }
  /// Send a line to the client the next time the endpoint is idle.
  void push_line(std::string line) {
    std::lock_guard lock(out_mutex_);
    outbound_.push_back(std::move(line));
  }
  bool saw_keepalive() const { return keepalive_.load(); }
  std::string last_frame() const {
    std::lock_guard lock(frame_mutex_);
    return last_frame_;
  }

  void stop() {
    stop_ = true;
    // The serve thread polls with select(), so it notices stop_ on its own; the
    // socket is closed only after the join to avoid racing the blocked call.
    if (thread_.joinable()) thread_.join();
    if (listen_fd_ >= 0) {
      ::close(listen_fd_);
      listen_fd_ = -1;
    }
  }

 private:
  void send_line(int fd, const std::string &line) {
    const std::string payload = line + "\n";
    // MSG_NOSIGNAL: the client may close before a reply is written.
    ::send(fd, payload.data(), payload.size(), MSG_NOSIGNAL);
  }

  /// Read one newline-terminated line. A receive timeout is not end-of-stream:
  /// it only means the client is idle, so the loop continues while the endpoint
  /// is still running.
  void flush_outbound(int fd) {
    std::vector<std::string> lines;
    {
      std::lock_guard lock(out_mutex_);
      lines.swap(outbound_);
    }
    for (const auto &line : lines) send_line(fd, line);
  }

  std::string read_line(int fd) {
    std::string line;
    char c = 0;
    while (!stop_) {
      const auto n = ::recv(fd, &c, 1, 0);
      if (n == 0) {
        return line;  // peer closed
      }
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          flush_outbound(fd);
          continue;  // idle: keep waiting unless the endpoint is stopping
        }
        return line;
      }
      if (c == '\n') return line;
      line.push_back(c);
      if (line.size() > 65536) return line;
    }
    return line;
  }

  void serve() {
    while (!stop_) {
      // Poll instead of a blocking accept so stop() is observed promptly.
      fd_set readable;
      FD_ZERO(&readable);
      FD_SET(listen_fd_, &readable);
      timeval timeout{};
      timeout.tv_usec = 20'000;
      const int ready = ::select(listen_fd_ + 1, &readable, nullptr, nullptr, &timeout);
      if (ready <= 0) {
        continue;
      }
      const int client = ::accept(listen_fd_, nullptr, nullptr);
      if (client < 0) {
        continue;
      }
      handle(client);
      ::close(client);
    }
  }

  void handle(int fd) {
    // A timeout keeps the serve thread responsive to stop() while it waits for a
    // client line that may never arrive (for example, after a refusal).
    timeval timeout{};
    timeout.tv_usec = 50'000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    send_line(fd, R"({"apiVersion":"openjoystickdriver/v1alpha3","kind":"Challenge","nonce":")" +
                      nonce_ + R"("})");

    const std::string hello = read_line(fd);
    hello_ = hello;

    const std::string scopes = omit_control_ ? R"(["Read"])" : R"(["Control"])";
    send_line(fd, R"({"apiVersion":"openjoystickdriver/v1alpha3","kind":"Welcome","version":"0.6.0-alpha.2","scopes":)" +
                      scopes + "}");

    const std::string feed = read_line(fd);
    feed_request_ = feed;

    if (!refuse_code_.empty()) {
      send_line(fd, R"({"apiVersion":"openjoystickdriver/v1alpha3","kind":"Status","status":"Failure","code":")" +
                        refuse_code_ + R"(","message":"refused"})");
      return;
    }

    send_line(fd,
              R"({"apiVersion":"openjoystickdriver/v1alpha3","kind":"FeedSession","as":"SDLCompatible"})");

    while (!stop_) {
      const std::string line = read_line(fd);
      if (line.empty()) return;
      if (line.find("\"kind\":\"Frame\"") != std::string::npos) {
        {
          std::lock_guard lock(frame_mutex_);
          last_frame_ = line;
        }
        ++frames_;
      } else if (line.find("\"kind\":\"KeepAlive\"") != std::string::npos) {
        keepalive_ = true;
      } else if (line.find("\"kind\":\"Drain\"") != std::string::npos) {
        send_line(fd, R"({"apiVersion":"openjoystickdriver/v1alpha3","kind":"Drained"})");
        return;
      }
    }
  }

  std::string nonce_;
  std::string path_;
  std::string refuse_code_;
  bool omit_control_ = false;
  int listen_fd_ = -1;
  std::thread thread_;
  std::atomic<bool> stop_{false};
  std::atomic<std::size_t> frames_{0};
  std::atomic<bool> keepalive_{false};
  mutable std::mutex frame_mutex_;
  std::mutex out_mutex_;
  std::vector<std::string> outbound_;
  std::string last_frame_;

 public:
  std::string hello_;
  std::string feed_request_;
};

void test_parse_rumble_command() {
  // Exact line shape OJD sends (verified against a real endpoint).
  const auto reply = parse_reply(
      R"({"apiVersion":"openjoystickdriver/v1alpha3","durationMilliseconds":250,"intensities":{"highFrequency":65535,"leftHaptic":0,"leftTrigger":0,"lowFrequency":65535,"rightHaptic":0,"rightTrigger":0},"kind":"RumbleCommand","type":"SetRumble"})");
  check(reply.has_value(), "rumble line parses");
  if (!reply) return;

  const auto command = parse_rumble_command(*reply);
  check(command.has_value(), "rumble command recognised");
  if (!command) return;

  check(command->set, "SetRumble is a set");
  check_eq(command->low_frequency, std::uint16_t{65535}, "low frequency");
  check_eq(command->high_frequency, std::uint16_t{65535}, "high frequency");
  check_eq(command->left_trigger, std::uint16_t{0}, "left trigger");
  check_eq(command->right_trigger, std::uint16_t{0}, "right trigger");
  check_eq(command->duration_milliseconds, std::int32_t{250}, "duration");
}

void test_parse_stop_rumble() {
  const auto reply = parse_reply(
      R"({"apiVersion":"openjoystickdriver/v1alpha3","kind":"RumbleCommand","type":"StopRumble"})");
  check(reply.has_value(), "stop rumble parses");
  if (reply) {
    const auto command = parse_rumble_command(*reply);
    check(command.has_value(), "stop recognised");
    if (command) {
      check(!command->set, "StopRumble is not a set");
    }
  }
}

void test_rumble_ignores_other_kinds() {
  const auto welcome = parse_reply(R"({"kind":"Welcome","scopes":["Control"]})");
  check(welcome.has_value(), "welcome parses");
  if (welcome) {
    check(!parse_rumble_command(*welcome).has_value(), "welcome is not rumble");
  }
}

void test_rumble_clamps_out_of_range() {
  const auto reply = parse_reply(
      R"({"kind":"RumbleCommand","type":"SetRumble","intensities":{"lowFrequency":999999,"highFrequency":-5}})");
  check(reply.has_value(), "clamp line parses");
  if (reply) {
    const auto command = parse_rumble_command(*reply);
    check(command.has_value(), "clamped command recognised");
    if (command) {
      check_eq(command->low_frequency, std::uint16_t{65535}, "oversized value clamps to max");
      check_eq(command->high_frequency, std::uint16_t{0}, "negative value clamps to 0");
    }
  }
}

void test_handshake_success() {
  FakeEndpoint endpoint;
  check(endpoint.start(), "fake endpoint starts");

  FeedClient client;
  FeedConfig config;
  config.socket_path = endpoint.path();
  config.token = "ojd_test_token";
  config.token_name = "driver";
  config.persona = Persona::sdl_compatible;

  const auto result = client.connect(config);
  check(result.ok(), std::string("handshake succeeds: ") + std::string(to_string(result.error)));
  check(client.connected(), "client reports connected");
  check(endpoint.hello_.find("\"kind\":\"Hello\"") != std::string::npos, "server saw Hello");
  check(endpoint.hello_.find("ojd_test_token") == std::string::npos,
        "token never leaves the client");
  check(endpoint.feed_request_.find("SDLCompatible") != std::string::npos,
        "feed request carried persona");

  Frame frame;
  frame.buttons = {Button::south};
  check(client.send_frame(frame), "frame sends");

  // Give the server thread a moment to consume the frame.
  for (int i = 0; i < 50 && endpoint.frames_received() == 0; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  check_eq(endpoint.frames_received(), std::size_t{1}, "server received one frame");
  check(endpoint.last_frame().find("South") != std::string::npos, "frame carried South");

  client.disconnect();
  check(!client.connected(), "disconnect clears connected");
}

void test_handshake_not_granted() {
  FakeEndpoint endpoint;
  endpoint.set_no_control_scope(true);
  check(endpoint.start(), "endpoint starts");

  FeedClient client;
  FeedConfig config;
  config.socket_path = endpoint.path();
  config.token = "t";
  config.token_name = "n";

  const auto result = client.connect(config);
  check_eq(result.error, ConnectError::not_granted, "missing Control scope is reported");
}

void test_handshake_feed_refused() {
  FakeEndpoint endpoint;
  endpoint.set_refuse_feed("E1007");
  check(endpoint.start(), "endpoint starts");

  FeedClient client;
  FeedConfig config;
  config.socket_path = endpoint.path();
  config.token = "t";
  config.token_name = "n";

  const auto result = client.connect(config);
  check_eq(result.error, ConnectError::feed_refused, "feed refusal reported");
  check(result.detail.find("E1007") != std::string::npos, "error code surfaced");
}

void test_connect_missing_socket() {
  FeedClient client;
  FeedConfig config;
  config.socket_path = "/tmp/definitely_not_an_ojd_socket.sock";
  const auto result = client.connect(config);
  check_eq(result.error, ConnectError::socket_failed, "missing socket reported");
}

void test_pad_session_round_trip() {
  FakeEndpoint endpoint;
  check(endpoint.start(), "endpoint starts");

  SessionConfig config;
  config.socket_path = endpoint.path();
  config.token = "t";
  config.token_name = "n";
  config.max_fps = 100;
  config.keepalive_after = std::chrono::milliseconds(100);

  PadPool pool(config);
  GamepadState state;
  state.button_flags = moonlight::a;
  state.lx = 16000;

  check(pool.update(0, state), "pad session starts");

  for (int i = 0; i < 100 && endpoint.frames_received() == 0; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  check(endpoint.frames_received() >= 1, "session published a frame");

  // KeepAlive must appear once the pad goes quiet.
  for (int i = 0; i < 100 && !endpoint.saw_keepalive(); ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  check(endpoint.saw_keepalive(), "keepalive sent while idle");

  pool.release_all();
}

void test_pad_session_keeps_held_axis() {
  FakeEndpoint endpoint;
  check(endpoint.start(), "endpoint starts");

  SessionConfig config;
  config.socket_path = endpoint.path();
  config.token = "t";
  config.token_name = "n";
  config.max_fps = 100;

  PadPool pool(config);
  GamepadState state;
  state.ly = 32767;  // stick held fully forward
  check(pool.update(0, state), "pad session starts");
  for (int i = 0; i < 100 && endpoint.frames_received() == 0; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  check_eq(endpoint.frames_received(), std::size_t{1}, "first frame published");

  // Only X moves; Y is still held, so OJD must still be told about it.
  state.lx = 1000;
  check(pool.update(0, state), "second update accepted");
  for (int i = 0; i < 100 && endpoint.frames_received() < 2; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  check_eq(endpoint.frames_received(), std::size_t{2}, "second frame published");
  check(endpoint.last_frame().find("LeftStickY") != std::string::npos,
        "held stick axis re-sent when the other axis moves");

  pool.release_all();
}

void test_pad_session_rumble_expires() {
  FakeEndpoint endpoint;
  check(endpoint.start(), "endpoint starts");

  std::mutex mutex;
  std::vector<RumbleCommand> received;

  SessionConfig config;
  config.socket_path = endpoint.path();
  config.token = "t";
  config.token_name = "n";
  config.on_rumble = [&](int, const RumbleCommand &command) {
    std::lock_guard lock(mutex);
    received.push_back(command);
  };
  const auto count = [&]() {
    std::lock_guard lock(mutex);
    return received.size();
  };

  PadPool pool(config);
  check(pool.update(0, GamepadState{}), "pad session starts");
  for (int i = 0; i < 100 && endpoint.frames_received() == 0; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  endpoint.push_line(
      R"({"apiVersion":"openjoystickdriver/v1alpha3","durationMilliseconds":60,"intensities":{"highFrequency":1000,"leftHaptic":0,"leftTrigger":0,"lowFrequency":2000,"rightHaptic":0,"rightTrigger":0},"kind":"RumbleCommand","type":"SetRumble"})");
  for (int i = 0; i < 100 && count() < 2; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  {
    std::lock_guard lock(mutex);
    check_eq(received.size(), std::size_t{2}, "rumble forwarded, then stopped");
    if (received.size() == 2) {
      check(received[0].set && received[0].low_frequency == 2000, "first is the SetRumble");
      check(!received[1].set && received[1].low_frequency == 0, "second is a stop");
    }
  }

  pool.release_all();
}

}  // namespace

#define RUN(fn) do { \
    std::cerr << "  " << #fn << " ... " << std::flush; \
    fn(); \
    std::cerr << "ok\n"; \
  } while (0)

int main() {
  RUN(test_sha256_vectors);
  RUN(test_hmac_vectors);
  RUN(test_token_proof_shape);
  RUN(test_hello_token_message);
  RUN(test_frame_message);
  RUN(test_frame_neutral);
  RUN(test_number_rendering_edge_cases);
  RUN(test_keepalive_and_drain);
  RUN(test_json_escaping);
  RUN(test_parse_challenge);
  RUN(test_parse_welcome);
  RUN(test_parse_status_failure);
  RUN(test_parse_version_error_details);
  RUN(test_parse_rejects_malformed);
  RUN(test_parse_skips_unknown_fields);
  RUN(test_button_mapping_positions);
  RUN(test_dpad_uses_its_own_field);
  RUN(test_dpad_frame_json);
  RUN(test_all_buttons_map);
  RUN(test_axis_scaling);
  RUN(test_trigger_scaling);
  RUN(test_diff_frame_keeps_held_buttons);
  RUN(test_diff_frame_reports_changes);
  RUN(test_rumble_ignores_other_kinds);
  RUN(test_parse_rumble_command);
  RUN(test_parse_stop_rumble);
  RUN(test_rumble_clamps_out_of_range);
  RUN(test_handshake_success);
  RUN(test_handshake_not_granted);
  RUN(test_handshake_feed_refused);
  RUN(test_connect_missing_socket);
  RUN(test_pad_session_round_trip);
  RUN(test_pad_session_keeps_held_axis);
  RUN(test_pad_session_rumble_expires);

  if (g_failures == 0) {
    std::cout << "All OJD client tests passed.\n";
    return 0;
  }
  std::cerr << g_failures << " check(s) failed.\n";
  return 1;
}

# Connecting a phone

Every `apex device …` command talks to the phone over ADB (Android Debug
Bridge), as the non-root `shell` user. Nothing is installed on the phone.

## Prerequisites

| On the phone | Why |
|---|---|
| **Unlocked** (the owner's code) | to enable USB debugging and accept the computer's key; Android also refuses some reads while locked |
| **Developer options** enabled | Settings → About phone → tap **Build number** (MIUI: **MIUI version**) 7 times, then enter the code |
| **USB debugging** on | Settings → System → Developer options → **USB debugging** (MIUI: Additional settings → Developer options) |
| A **data** cable | a charge-only cable shows no device at all |

| On the computer | Why |
|---|---|
| No `adb` server running | it holds the USB interface: `adb kill-server` |
| Linux: udev rules installed | see [Installation](Installation#platform-notes) |

Enabling developer options and USB debugging changes the phone's settings:
note it in the procès-verbal (see [Field procedure](Field-Procedure)).

## First connection

1. Plug the phone in and run any device command, for example `apex device listen`.
2. On the phone, accept **Allow USB debugging?** and tick **Always allow from
   this computer**.
3. APEX creates its key at `~/.android/adbkey` on first use (the same path as
   `adb`), so the prompt appears only once per phone. If the phone has not
   answered after a few seconds, APEX says it is waiting.

If the phone asks for a USB mode, choose **File transfer**. Some phones only
show the debugging prompt in that mode.

```sh
apex device listen                  # waits, then prints "Device connected (SERIAL)"
apex device listen --timeout 60     # give up after 60 s (exit code 1)
```

## Several phones

`apex device listen` prints every connected serial. Pick one with
`--serial <SERIAL>` on any device command:

```sh
apex device acquire --serial LJSKNB6HTKVSOVJF -o ./case-42
```

Without `--serial`, APEX refuses to guess when more than one phone is plugged in.

## Over the network

Legacy ADB over TCP, unencrypted. Only on a network you control.

1. Connect the phone over USB once and switch ADB to TCP with the Android
   platform tools: `adb tcpip 5555` (APEX has no command for this step), then
   `adb kill-server`.
2. Unplug, find the phone's IP address (Settings → Wi-Fi → network details).
3. `apex device acquire --tcp 192.168.1.20 -o ./case-42` (port 5555 by default,
   or `HOST:PORT`).

Android 11+ **Wireless debugging** (pairing code, TLS) is not supported.

## A custom ADB key

`--adb-key <PATH>` uses another private key, for example a key per examiner
or per case. The phone asks for authorization again for a new key.

## Before you start an acquisition

- The phone should stay **unlocked and awake** during an acquisition: set the
  screen timeout to the maximum, or keep touching it. A locked phone answers
  most commands but refuses some.
- Keep it **charged** (an acquisition records the battery level at reception).
- **Isolate it from the network** as soon as the remote-wipe check allows (see
  [Field procedure](Field-Procedure)): airplane mode, or a Faraday bag with the
  cable through a filtered port.

See [Troubleshooting](Troubleshooting) if the phone is not found or the
connection fails.

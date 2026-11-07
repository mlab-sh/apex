# Troubleshooting

## `no ADB USB device found`

The computer does not see the phone as an ADB device. In order:

1. **Cable**: a charge-only cable shows nothing. Try another cable and port.
2. **USB debugging** on in Developer options (MIUI sometimes turns it off
   after an update or a reboot).
3. **USB mode**: in the phone's USB notification, choose **File transfer**.
4. Phone **unlocked**.
5. Linux: udev rules and group (see [Installation](Installation#platform-notes)).
6. Check the system sees it at all: macOS `system_profiler SPUSBDataType`,
   Linux `lsusb`. If the phone is not listed there, it is the cable or the
   port.

`apex device listen --timeout 60` waits while you try.

## APEX waits for the phone after connecting

The phone has not authorized this computer. Unlock it and accept **Allow USB
debugging?** (tick **Always allow**). If the prompt does not appear: revoke
USB debugging authorizations in Developer options, unplug, plug back.

## `ADB USB connection failed: wrong response: received CLSE` / `CNXN, expected AUTH`

A previous session was interrupted, or another program holds the USB
interface.

1. Stop any `adb` server: `adb kill-server`.
2. Run the command again; if it repeats, unplug and replug the phone.

## `N ADB devices connected, pick one with --serial`

Several phones are plugged in. `apex device listen` prints their serials; add
`--serial <SERIAL>`.

## `apex` behaves like an older version

Another `apex` comes first on the `PATH`: `which -a apex`, `apex --version`.
See [Installation](Installation#check-which-apex-runs).

## `comms`: `No communications in this case`

The case was acquired or imported without `--mandate`. Acquire or import it
again with the mandate reference.

## `comms`: `⚠ WhatsApp backup …: no working key`

The backup was collected but cannot be decrypted. `.crypt14` needs `files/key`
from a lab extraction; `.crypt15` needs `files/encrypted_backup.key` from an
extraction or the 64-digit key (`--wa-key`, no spaces). See
[Communications and app data](Communications-and-App-Data#keys).

## `comms`: `⚠ Signal: database encrypted with a Keystore-protected secret`

Newer Signal versions protect the database secret with the Android Keystore.
The lab must recover it; pass it with `--signal-key <hex>`.

## `media`: `No shared storage in this case`

Acquire with `device acquire --storage`, or import with `--storage`.

## `verify` lists unlisted files

Files were written inside the case after acquisition (`timeline.csv`,
`report.html`). Not tampering, but keep outputs outside the case with `-o`.

## `report` / `timeline`: `is not a device acquire case`

The path is not a case directory (no `device/packages.txt`). Point to the
directory given to `-o` at acquisition or import.

## `seal`: `Connection failed`

`seal` needs the computer online and a reachable TSA URL. The phone does not
need a network.

## Times look shifted by one or two hours

The case lacks the phone's time zone (an extraction without
`persist.sys.timezone`): times are UTC, and APEX says so when importing.

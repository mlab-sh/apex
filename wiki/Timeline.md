# timeline

One chronological file of everything dated in a case, with the Timesketch
columns.

## Prerequisites

- A case from [`device acquire`](Device-Acquire) or [`import`](Import).
- Correct times need the phone's time zone (recorded by the acquisition; read
  from `persist.sys.timezone` in an extraction). Without it, times are UTC and
  APEX says so.

No phone, no network.

## Usage

```sh
apex timeline ./case-42 -o ./case-42-timeline.csv     # CSV (Timesketch)
apex timeline ./case-42 -o ./case-42-timeline.jsonl   # JSONL
apex timeline ./case-42                               # → ./case-42/timeline.csv
```

Write it **outside** the case (`-o`): a file added inside the case shows as
unlisted in [`verify`](Verify).

## Columns

`datetime, timestamp_desc, source, package, message`. Each `datetime` carries
the UTC offset in force at that moment in the phone's time zone, so summer
and winter times are both right.

## Sources

App install / update times; installs and uninstalls (package manager log,
battery history in the bugreport); uploads over 1 MB per app and period
(network statistics); app-op accesses (camera, microphone, location…); usage
events; logcat; camera service events; notifications active at acquisition;
file modification times; communications (under mandate); dated media with
their position; with the [APEX agent](Agent), the usage events the system
keeps: **phone unlocked**, lock screen, screen on / off, app in front, boot
and shutdown (`usage:*`).

The terminal prints the count per source.

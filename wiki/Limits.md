# Accuracy and limits

- **Findings are indicators, not proof.** Legitimate apps (MDM, accessibility
  tools, password managers, parental control) can match a stalkerware
  profile. Corroborate before concluding; where abuse is suspected, do not
  remove an app abruptly.
- **Live acquisition is not a forensic image.** It reads what the `shell` user
  can read. App-private data, deleted files and unallocated space need a lab
  extraction ([`import`](Import)).
- **Formats vary** across Android versions, phone makers and app versions.
  Parsers are best-effort: an unrecognized artifact produces no finding rather
  than an error. Validated on Android 13 (Xiaomi / MIUI) and on synthetic
  extractions; app databases marked "best effort" on
  [Communications and app data](Communications-and-App-Data) have not been
  checked against every app version.
- **Root and verified-boot signals** come from system properties, which can be
  spoofed.
- **Times** depend on the phone's clock and time zone; `CASE_CLOCK_SKEW`
  reports the difference with the examiner's clock at acquisition.
- **Recovered deleted records** were in the database at some point; their
  dates are the record's own fields. See [Deleted records](Deleted-Records).
- **Static analysis** shows what an app embeds and requests; what it contacts
  at runtime needs dynamic analysis.
- **Not supported**: Android 11+ wireless debugging (TLS pairing), Windows,
  physical images, proprietary extraction containers (unpack them first).

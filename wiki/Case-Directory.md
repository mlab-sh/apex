# Case directory

What [`device acquire`](Device-Acquire) and [`import`](Import) write. Every
file is hashed in `manifest.json`.

```
case-42/
  manifest.json, manifest.json.sha256   evidence manifest and its detached hash
  audit.jsonl                           every ADB action (acquisitions only)
  manifest.json.tsq, .tsr               RFC 3161 timestamp (after `apex seal`)
  device/
    clock.txt              device time + UTC offset (read first, for clock skew)
    accounts.txt, device_policy.txt, connectivity.txt   read first, for the remote-wipe alert
    processes.txt          ps -A
    proc_exe.txt           real executable of each shell-user process (/proc/PID/exe)
    net_sockets.txt        /proc/net/{tcp,tcp6,udp,udp6}
    local_tmp.txt          ls -laR /data/local/tmp
    screen.png             screenshot at acquisition time
    iphonesubinfo.txt      IMEI / IMSI / ICCID / line number (read-only getters)
    getprop.txt, identifiers.json
    packages.txt           pm list packages -f -i -u (path, installer)
    packages_{3,system,uid}.txt
    users.txt              users: work profile, secondary users, clone space
    packages_3_user<N>.txt third-party apps of each other user
    package_messages.txt   package manager log: first boot, uninstalls and who did them
    appops.txt             permission use history
    launcher_activities.txt
    settings_{secure,global,system}.txt
    usagestats.txt, logcat.txt
    netstats.txt           per-app traffic history (weeks)
    activity_*.txt, dbinfo.txt, notification.txt, jobscheduler.txt, alarm.txt,
    role.txt, input_method.txt, vpn_management.txt, camera.txt, audio.txt,
    location.txt, wifi.txt, wifi_networks.txt, bluetooth.txt
    sdcard_listing.txt     ls -laR of shared storage (metadata only)
    bugreport.zip          full dumpstate: every dumpsys, tombstones, ANRs, battery history
  apps/<package>/          base.apk + every split APK, dumpsys_package.txt
  comms/                   only with --mandate
    sms.txt, mms.txt, mms_part.txt, mms_addr.txt, calls.txt, contacts.txt, calendar.txt   (live)
    mms_parts/             MMS attachments
    db/                    SMS / call / contact / WhatsApp / Telegram / Chrome / calendar databases (extraction)
    app/<package>/…        app data: Signal, WhatsApp keys and backups, Maps, Meta, Snapchat, Gboard, Gmail, wallets
  storage/                 only with --storage: shared storage
  backup/                  only with --backup: unpacked Android backup
```

A `--triage` case has the volatile and identity files only (no apps, no
history). An imported case has the files the extraction allowed; `import`
prints what was missing.

Analysis outputs (`timeline.csv`, `report.html`, `_comms`, `_media`,
`_search`) go next to the case by default or wherever `-o` says. Keep them
outside the case so [`verify`](Verify) stays clean.

# identifiers

Every identifier needed for legal requests, from a case: device, telephony,
network, accounts, and the apps whose operator holds data.

## Prerequisites

- A case from [`device acquire`](Device-Acquire) (full or `--triage`) or
  [`import`](Import).
- Telephony identifiers (IMEI, IMSI, ICCID, line number) come from a live
  acquisition (`iphonesubinfo`); an extraction usually does not hold them.

No phone, no network.

## Usage

```sh
apex identifiers ./case-42                          # terminal sheet
apex identifiers ./case-42 --json -o identifiers.json
```

## What it lists

| Section | Fields | Source |
|---|---|---|
| Device | manufacturer, model, device name, serial, Android ID, Android version, build fingerprint | properties, settings |
| Telephony | IMEI, IMSI, ICCID, line number (MSISDN), SIM and network operator, SIM country | read-only getters of `service call iphonesubinfo`, classified on the computer (Luhn check for IMEI, SIM MCC/MNC prefix for IMSI) |
| Network | factory Wi-Fi MAC, Bluetooth MAC and name | `dumpsys wifi`, settings |
| Accounts | every account on the phone, with the service a request goes to (Google, WhatsApp, Instagram / Threads user IDs, Telegram, Samsung, Xiaomi…) | `dumpsys account` / `accounts_*.db` |
| Apps whose operator holds data | ride-hailing (Uber, Bolt, Heetch…), delivery, payment (PayPal, Lydia, Revolut), crypto wallets and exchanges, encrypted messaging, social, marketplaces | installed packages |

The line number is only known if the SIM or the operator stored it; it is
often missing.

The same sheet is in the [HTML report](Report) and the [procès-verbal](PV).

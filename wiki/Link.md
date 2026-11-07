# link

What several exhibits of the same case have in common: the shared numbers,
e-mail addresses, accounts, crypto wallets, IBANs, Wi-Fi networks, Bluetooth
devices and sideloaded apps. It shows who talked to whom, who was where
together, and the same malware on several phones.

## Prerequisites

- At least two cases ([`device acquire`](Device-Acquire) or [`import`](Import)),
  one per exhibit. Give `--seal` or `--case-id` at acquisition: the output
  names each exhibit by them.
- Communications are compared only if collected under `--mandate`.

No phone, no network.

## Usage

```sh
apex link ./scelle-1 ./scelle-2 ./scelle-3
apex link ./scelle-1 ./scelle-2 -o links.csv
```

| Option | Effect |
|---|---|
| `<CASES>…` | two or more case directories |
| `-o, --output <FILE>` | also write `kind,value,cases` as CSV |

## What is compared

| Kind | From |
|---|---|
| `phone` | message and call peers, contacts, numbers found anywhere; matched on the last nine digits (`+33 6…`, `06…`, `33…@s.whatsapp.net` are the same) |
| `email` | addresses found anywhere |
| `account` | accounts on the phones (masked names are skipped) |
| `wallet`, `iban` | Bitcoin / Ethereum addresses and IBANs found anywhere |
| `wifi` | saved Wi-Fi networks: two phones that know the same network were probably in the same place |
| `bluetooth` | paired devices (with the [agent](Agent)) |
| `sideloaded_app` | apps not installed from a store: the same rare app on two phones is a lead |

Only values found in at least two exhibits are listed. Two acquisitions of
the same phone share everything; that is expected.

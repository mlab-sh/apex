# search

Searches a whole case for words or regular expressions, and extracts entities:
phone numbers, e-mail addresses, IBANs, Bitcoin and Ethereum addresses,
@handles.

## Prerequisites

- A case. Communications are searched only if they were collected under
  `--mandate` (see [comms](Comms)).

No phone, no network.

## Usage

```sh
apex search ./case-42 "parking" "rdv"                 # any of the words, case-insensitive
apex search ./case-42 --regex "\b0[67]\d{8}\b"        # regular expression
apex search ./case-42 --entities                      # entities only
apex search ./case-42 "colis" --entities -o ./case-42-search
```

| Option | Effect |
|---|---|
| `[PATTERNS]…` | words or phrases; several = any of them |
| `--regex` | treat the patterns as regular expressions |
| `--entities` | extract entities |
| `-o, --output <DIR>` | CSV output directory (default `<case>_search`) |

## What is searched

Every text file of the case (`.txt`, `.json`, `.csv`, `.xml`, `.log`, `.html`,
`.vcf`, `.ics`…), including those in shared storage and app settings, the text
entries of `bugreport.zip`, and the communications (`comms`). Binary files
(databases, images) are not searched directly: their content is searched
through `comms`.

## Entities

| Kind | Check |
|---|---|
| phone | international (E.164) everywhere; national formats only in messages and documents |
| email | false positives filtered (file names, package names, hardware names) |
| iban | mod-97 checked |
| bitcoin | Base58Check or Bech32 / Bech32m checked |
| ethereum | `0x` + 40 hex digits |
| handle | `@name`, only in messages |

## Output

| File | Content |
|---|---|
| `hits.csv` | source, line, text of every match |
| `entities.csv` | kind, value, count, sources |

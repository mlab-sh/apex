# Deleted records

Android apps store messages in SQLite. Deleting a row does not erase it at
once: older versions of the page stay in the **write-ahead log** (WAL) until a
checkpoint, and freed pages keep their content until reused.

## What APEX does

1. Databases are copied **with their `-wal` file** ([`import --mandate`](Import),
   `--backup`).
2. Every WAL frame is parsed, older page versions included, and every page of
   the database's freelist (trunk and leaf pages).
3. Table leaf pages found there are decoded record by record, following
   overflow chains.
4. A record whose row ID is no longer in the live table, with the table's
   column count and plausible values (a date, a text), is reported as
   **recovered**.

Recovered records show `recovered = true` in [`comms`](Comms), `[recovered
deleted record]` in the [timeline](Timeline), and raise the finding
`CASE_DELETED_COMMS_RECOVERED`.

## Where it applies

SMS, call log, contacts (plus contacts flagged deleted), WhatsApp, Telegram,
Messenger, Instagram, Snapchat. Calendar events flagged deleted are reported
too.

## Limits

- Unallocated space inside live pages is not carved.
- Once the WAL is checkpointed and the free pages reused, the content is gone.
  The sooner the extraction, the more is left.
- Encrypted databases (Signal) cannot be carved: their free pages stay
  encrypted.
- A recovered row is a former version of a row: it was in the database at
  some point, not necessarily at the date it shows. Corroborate.

The evidence is never modified: databases are opened from temporary copies,
because opening a database applies its WAL.

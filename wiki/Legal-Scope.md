# Legal scope

What APEX collects by default, what needs a mandate, what it never does. The
mandate reference you give is recorded in the manifest and stated in the
[procès-verbal](PV). Whether a given operation is covered by your legal
framework is for you and the magistrate to decide; APEX only enforces that
content is not collected without an explicit reference.

## By default (no mandate)

The phone's state and its apps: identifiers, accounts (names only), installed
and removed apps and when, permissions and their use, processes, network
connections and traffic per app, settings, users and profiles, system logs,
Wi-Fi network names, Bluetooth devices, file listings (names, sizes, dates).
Notifications are captured **redacted** (which app, when; no text).

## Only with `--mandate <reference>`

- SMS and MMS with attachments, call log, contacts, calendar.
- WhatsApp backups found on shared storage.
- From an extraction: messaging databases and app data (WhatsApp, Signal,
  Telegram, Messenger, Instagram, Snapchat, Gmail, browser history, Google
  Maps, keyboard, wallets). See [Communications and app data](Communications-and-App-Data).
- `--notification-content`: notification texts, which include message
  previews.

## Only when asked

- `--storage`: shared storage (photos, videos, downloads, messaging media).
- `--backup`: Android backup of the apps that allow it, confirmed on the phone.

## Never

- Wi-Fi passwords, saved passwords, authentication tokens.
- Lock-screen bypass, rooting, exploits. A locked phone goes to a lab; APEX
  reads the lab's extraction with [`import`](Import).
- Entering the phone's code: the owner or the examiner does it.
- Any network call during acquisition or analysis. Only [`seal`](Seal) goes
  online, and sends a hash.

## Changes to the phone

Enabling developer options and USB debugging, airplane mode, confirming a
backup: these are made by the examiner and must be written in the PV. What
APEX itself writes on the phone is listed on
[device acquire](Device-Acquire#what-it-changes-on-the-phone).

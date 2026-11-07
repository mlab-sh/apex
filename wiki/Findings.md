# Findings

Investigation findings raised by [`analyze`](Analyze), [`report`](Report),
[`pv`](PV) and [`diff`](Diff) on a case. Static-analysis findings on packages
are described on [scan](Scan).

Each finding has a severity (Critical, High, Medium, Low, Info) and its
evidence (`--detail`). They are **indicators**: see [Accuracy and limits](Limits).

## Stalkerware and spyware

| ID | Meaning |
|---|---|
| `DEV_STALKERWARE`, `PKG_STALKERWARE` | package name in the Echap stalkerware set |
| `PKG_STALKERWARE_CERT` | APK signed with a known stalkerware certificate (catches renamed builds) |
| `IOC_MATCH` | a STIX2 indicator matched: package, APK hash, signing certificate, or a domain / IP / URL in collected text, the bugreport or live sockets |
| `CASE_STALKERWARE_PROFILE` | an app combines accessibility, device admin, notification access, no icon, sideloading, sensitive permission use |
| `CASE_STALKERWARE_REMOVED` | a known stalkerware package was installed, then uninstalled (date and who removed it) |
| `CASE_HIDDEN_APP` | third-party app with no launcher icon |
| `CASE_SYSTEM_IMPERSONATION` | sideloaded app using a platform or OEM package name |
| `CASE_SENSITIVE_USE` | when each app last used the microphone, camera, location, SMS, call log, contacts, screen capture… |
| `CASE_ROLE_HOLDER` | a third-party app is the SMS, phone, call-screening, assistant, browser or launcher app |
| `CASE_THIRD_PARTY_KEYBOARD` | third-party keyboard enabled (sees everything typed) |

## Network

| ID | Meaning |
|---|---|
| `CASE_ALWAYS_ON_VPN`, `CASE_VPN_ACTIVE`, `CASE_PRIVATE_DNS` | something can see or redirect all traffic |
| `CASE_NET_CONNECTIONS`, `CASE_APP_LISTENING` | open sockets per app; user apps reachable from the network |
| `CASE_NET_USAGE` | traffic per user app over the period the system keeps |
| `CASE_BACKGROUND_UPLOAD` | a user app sent more than 20 MB in the background, more than it received |

## History and traces

| ID | Meaning |
|---|---|
| `CASE_APPS_REMOVED` | every app uninstalled and no longer on the phone, with date and caller |
| `CASE_UNINSTALL_BY_UNUSUAL_CALLER` | an app removed over adb or by another user app, not by the launcher, settings or a store |
| `CASE_UNINSTALLED_DATA_KEPT` | apps removed with their data kept (`pm uninstall -k`) |
| `CASE_FIRST_BOOT` | when the phone was set up or last factory reset: nothing older survives |
| `CASE_STAGING_PROCESS` | process running from `/data/local/tmp` or shared storage, or from a binary deleted after launch (real executable, so a disguised name does not hide it) |
| `CASE_LOCAL_TMP_FILES` | files left in `/data/local/tmp`, where adb-pushed tools are staged |
| `CASE_APK_ON_STORAGE` | APK files on shared storage (sideloading traces) |
| `CASE_CLOCK_SKEW` | the phone's clock differs from the examiner's |

## Device and users

| ID | Meaning |
|---|---|
| `CASE_REMOTE_WIPE` | a find-my-device service, an MDM or a device admin can erase the phone remotely |
| `CASE_USER_PROFILE` | another user exists: work profile (its admin sees the profile's apps and traffic), secondary user, guest, clone space |
| `CASE_PROFILE_ONLY_APP` | app installed only in another user, absent from the owner's app list |
| `CASE_WIFI_SAVED`, `CASE_BT_BONDED`, `CASE_BT_TRACKER` | saved networks, paired devices, item trackers |

## Mandate, media, operators

| ID | Meaning |
|---|---|
| `CASE_COMMUNICATIONS` | communications collected under mandate, counts per kind |
| `CASE_DELETED_COMMS_RECOVERED` | deleted records recovered (see [Deleted records](Deleted-Records)) |
| `CASE_MEDIA` | shared storage collected, and how many items have a location |
| `HASH_SET_MATCH` | a file matches an alert hash set (`--hashes`) |
| `CASE_APPS_OF_INTEREST` | installed apps whose operator holds data worth a legal request (ride-hailing, delivery, payment, wallets, encrypted messaging, social) |

"Sideloaded" means installed through a package-installer screen, by another
user app, or over adb. Preloads installed by system or OEM components are
not.

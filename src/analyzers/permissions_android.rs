//! Android permissions analyzer — categorize, flag dangerous perms, map to code usage.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{find_files_by_ext, line_of, read_text, rel, rx};
use crate::xml;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use Severity::*;

// (category, permission_suffix, description, severity), in declaration order.
const PERM_DB: &[(&str, &str, &str, Severity)] = &[
    ("location", "ACCESS_FINE_LOCATION", "Precise GPS location access", High),
    ("location", "ACCESS_COARSE_LOCATION", "Approximate network-based location access", Medium),
    ("location", "ACCESS_BACKGROUND_LOCATION", "Background location access (even when app is not visible)", High),
    ("location", "ACCESS_LOCATION_EXTRA_COMMANDS", "Extra location provider commands", Low),
    ("location", "ACCESS_MEDIA_LOCATION", "Access photo/video location metadata", Medium),
    ("connectivity", "ACCESS_WIFI_STATE", "Read WiFi network state and connection info", Low),
    ("connectivity", "CHANGE_WIFI_STATE", "Change WiFi connectivity state", Medium),
    ("connectivity", "ACCESS_NETWORK_STATE", "Read network connectivity state", Info),
    ("connectivity", "CHANGE_NETWORK_STATE", "Change network connectivity state", Medium),
    ("connectivity", "INTERNET", "Full network access (internet)", Info),
    ("connectivity", "BLUETOOTH", "Bluetooth pairing and connection", Low),
    ("connectivity", "BLUETOOTH_ADMIN", "Bluetooth device discovery and pairing management", Medium),
    ("connectivity", "BLUETOOTH_CONNECT", "Connect to paired Bluetooth devices", Medium),
    ("connectivity", "BLUETOOTH_SCAN", "Discover and pair Bluetooth devices", Medium),
    ("connectivity", "BLUETOOTH_ADVERTISE", "Advertise to nearby Bluetooth devices", Low),
    ("connectivity", "NFC", "Near-field communication access", Low),
    ("connectivity", "CHANGE_WIFI_MULTICAST_STATE", "WiFi multicast mode (battery drain)", Low),
    ("connectivity", "ACCESS_VPN_SERVICE", "VPN service access (can intercept traffic)", High),
    ("connectivity", "BIND_VPN_SERVICE", "Bind to VPN service", High),
    ("communication", "SEND_SMS", "Send SMS messages (potential premium SMS fraud)", High),
    ("communication", "RECEIVE_SMS", "Receive and read SMS messages", High),
    ("communication", "READ_SMS", "Read SMS messages", High),
    ("communication", "RECEIVE_MMS", "Receive MMS messages", High),
    ("communication", "RECEIVE_WAP_PUSH", "Receive WAP push messages", Medium),
    ("communication", "READ_PHONE_STATE", "Read phone state (IMEI, phone number, call state)", High),
    ("communication", "READ_PHONE_NUMBERS", "Read device phone numbers", High),
    ("communication", "CALL_PHONE", "Make phone calls without user interaction", High),
    ("communication", "READ_CALL_LOG", "Read call history", High),
    ("communication", "WRITE_CALL_LOG", "Modify call history", High),
    ("communication", "ADD_VOICEMAIL", "Add voicemail messages", Medium),
    ("communication", "USE_SIP", "SIP internet telephony", Medium),
    ("communication", "ANSWER_PHONE_CALLS", "Answer incoming phone calls", High),
    ("communication", "READ_VOICEMAIL", "Read voicemail", High),
    ("media_audio", "CAMERA", "Camera access (photo/video capture)", High),
    ("media_audio", "RECORD_AUDIO", "Microphone access (audio recording)", High),
    ("media_audio", "MODIFY_AUDIO_SETTINGS", "Modify audio settings (volume, routing)", Low),
    ("media_audio", "CAPTURE_AUDIO_OUTPUT", "Capture audio output from other apps", High),
    ("media_audio", "READ_MEDIA_IMAGES", "Read images from shared storage", Medium),
    ("media_audio", "READ_MEDIA_VIDEO", "Read videos from shared storage", Medium),
    ("media_audio", "READ_MEDIA_AUDIO", "Read audio files from shared storage", Medium),
    ("media_audio", "READ_EXTERNAL_STORAGE", "Read external storage (broad file access)", Medium),
    ("media_audio", "WRITE_EXTERNAL_STORAGE", "Write to external storage", Medium),
    ("media_audio", "MANAGE_EXTERNAL_STORAGE", "Full external storage management (all files access)", High),
    ("contacts_accounts", "READ_CONTACTS", "Read user contacts", High),
    ("contacts_accounts", "WRITE_CONTACTS", "Modify user contacts", High),
    ("contacts_accounts", "GET_ACCOUNTS", "List device accounts (Google, etc.)", Medium),
    ("contacts_accounts", "MANAGE_ACCOUNTS", "Manage device accounts", High),
    ("contacts_accounts", "READ_CALENDAR", "Read calendar events", High),
    ("contacts_accounts", "WRITE_CALENDAR", "Modify calendar events", High),
    ("device_features", "VIBRATE", "Vibration motor control", Info),
    ("device_features", "USE_FINGERPRINT", "Fingerprint sensor access (deprecated, use BiometricPrompt)", Low),
    ("device_features", "USE_BIOMETRIC", "Biometric sensor access", Low),
    ("device_features", "SET_WALLPAPER", "Change device wallpaper", Info),
    ("device_features", "TRANSMIT_IR", "Infrared transmitter access", Low),
    ("device_features", "FLASHLIGHT", "Flashlight/torch control", Info),
    ("device_features", "BODY_SENSORS", "Body sensor data access (heart rate, etc.)", High),
    ("device_features", "ACTIVITY_RECOGNITION", "Physical activity recognition (walking, driving)", Medium),
    ("device_features", "HIGH_SAMPLING_RATE_SENSORS", "Access sensors at high sampling rate", Low),
    ("system_admin", "BIND_DEVICE_ADMIN", "Device administrator binding (can lock/wipe device)", High),
    ("system_admin", "SYSTEM_ALERT_WINDOW", "Draw overlay windows on top of other apps", High),
    ("system_admin", "WRITE_SETTINGS", "Modify system settings", High),
    ("system_admin", "WRITE_SECURE_SETTINGS", "Modify secure system settings", High),
    ("system_admin", "REQUEST_INSTALL_PACKAGES", "Request app installation from unknown sources", High),
    ("system_admin", "REQUEST_DELETE_PACKAGES", "Request app deletion", Medium),
    ("system_admin", "INSTALL_PACKAGES", "Install packages (system-level)", High),
    ("system_admin", "DELETE_PACKAGES", "Delete packages (system-level)", High),
    ("system_admin", "MOUNT_UNMOUNT_FILESYSTEMS", "Mount/unmount filesystems", High),
    ("system_admin", "REBOOT", "Reboot the device", High),
    ("app_management", "KILL_BACKGROUND_PROCESSES", "Kill background processes of other apps", Medium),
    ("app_management", "GET_TASKS", "Get info about running tasks (deprecated)", Medium),
    ("app_management", "QUERY_ALL_PACKAGES", "Query all installed packages", Medium),
    ("app_management", "PACKAGE_USAGE_STATS", "Access app usage statistics", High),
    ("app_management", "FOREGROUND_SERVICE", "Run foreground services with persistent notification", Info),
    ("app_management", "FOREGROUND_SERVICE_LOCATION", "Foreground service with location access", Medium),
    ("app_management", "FOREGROUND_SERVICE_CAMERA", "Foreground service with camera access", Medium),
    ("app_management", "FOREGROUND_SERVICE_MICROPHONE", "Foreground service with microphone access", Medium),
    ("app_management", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "Request exemption from battery optimization", Low),
    ("user_interaction", "RECEIVE_BOOT_COMPLETED", "Auto-start on device boot", Medium),
    ("user_interaction", "WAKE_LOCK", "Prevent device from sleeping", Low),
    ("user_interaction", "DISABLE_KEYGUARD", "Disable the lock screen", High),
    ("user_interaction", "EXPAND_STATUS_BAR", "Expand/collapse status bar", Info),
    ("user_interaction", "POST_NOTIFICATIONS", "Show notifications to the user", Info),
    ("user_interaction", "SCHEDULE_EXACT_ALARM", "Schedule exact alarms (precise timing)", Low),
    ("user_interaction", "USE_EXACT_ALARM", "Use exact alarms for time-critical operations", Low),
    ("user_interaction", "USE_FULL_SCREEN_INTENT", "Show full-screen intents (e.g. incoming call UI)", Medium),
    ("privileged_ops", "READ_LOGS", "Read system log files (sensitive data exposure)", High),
    ("privileged_ops", "DUMP", "Dump system state for debugging", High),
    ("privileged_ops", "MANAGE_DOCUMENTS", "Manage documents provider", Medium),
    ("privileged_ops", "ACCESS_NOTIFICATION_POLICY", "Access Do Not Disturb policy", Low),
    ("privileged_ops", "BIND_ACCESSIBILITY_SERVICE", "Bind accessibility service (can read all screen content)", High),
    ("privileged_ops", "BIND_NOTIFICATION_LISTENER_SERVICE", "Read all notifications from other apps", High),
];

// (permission_suffix, api_regex, api_description), in declaration order.
const PERM_TO_API: &[(&str, &str, &str)] = &[
    ("ACCESS_FINE_LOCATION", r#"(LocationManager|requestLocationUpdates|getLastKnownLocation|FusedLocationProviderClient|LocationRequest|LocationCallback)"#, "Location APIs (GPS)"),
    ("ACCESS_COARSE_LOCATION", r#"(LocationManager|requestLocationUpdates|getLastKnownLocation|FusedLocationProviderClient|NetworkProvider)"#, "Location APIs (network)"),
    ("ACCESS_BACKGROUND_LOCATION", r#"(requestLocationUpdates|FusedLocationProviderClient|LocationRequest\.setInterval)"#, "Background location APIs"),
    ("INTERNET", r#"(HttpURLConnection|HttpsURLConnection|OkHttpClient|Retrofit|Volley|Socket\s*\(|URL\s*\(|WebView|openConnection|HttpClient)"#, "Network/HTTP APIs"),
    ("ACCESS_NETWORK_STATE", r#"(ConnectivityManager|NetworkInfo|getActiveNetworkInfo|getActiveNetwork|NetworkCapabilities)"#, "Network state APIs"),
    ("ACCESS_WIFI_STATE", r#"(WifiManager|WifiInfo|getConnectionInfo|getSSID|getBSSID|getScanResults)"#, "WiFi APIs"),
    ("BLUETOOTH_CONNECT", r#"(BluetoothDevice|BluetoothSocket|BluetoothGatt|createRfcommSocket|connectGatt)"#, "Bluetooth connection APIs"),
    ("BLUETOOTH_SCAN", r#"(BluetoothLeScanner|startDiscovery|startScan|BluetoothAdapter\.startLeScan)"#, "Bluetooth scan APIs"),
    ("NFC", r#"(NfcAdapter|NdefMessage|NdefRecord|IsoDep|HostApduService)"#, "NFC APIs"),
    ("SEND_SMS", r#"(SmsManager|sendTextMessage|sendMultipartTextMessage|sendDataMessage)"#, "SMS sending APIs"),
    ("RECEIVE_SMS", r#"(SmsMessage|createFromPdu|SMS_RECEIVED|SmsRetriever)"#, "SMS receiving APIs"),
    ("READ_SMS", r#"(content://sms|Telephony\.Sms|SmsMessage)"#, "SMS reading APIs"),
    ("READ_PHONE_STATE", r#"(TelephonyManager|getDeviceId|getImei|getSubscriberId|getSimSerialNumber|getLine1Number|PhoneStateListener)"#, "Telephony state APIs"),
    ("READ_PHONE_NUMBERS", r#"(getLine1Number|TelephonyManager\.getPhoneNumber|SubscriptionInfo\.getNumber)"#, "Phone number APIs"),
    ("CALL_PHONE", r#"(Intent\.ACTION_CALL|tel:|CallRedirectionService|TelecomManager\.placeCall)"#, "Phone call APIs"),
    ("READ_CALL_LOG", r#"(CallLog|content://call_log|CallLog\.Calls)"#, "Call log reading APIs"),
    ("ANSWER_PHONE_CALLS", r#"(TelecomManager\.acceptRingingCall|InCallService|acceptRinging)"#, "Call answering APIs"),
    ("CAMERA", r#"(android\.hardware\.Camera|Camera\.open|CameraManager|camera2|CameraDevice|ImageCapture|CameraX)"#, "Camera APIs"),
    ("RECORD_AUDIO", r#"(AudioRecord|MediaRecorder\.setAudioSource|MediaRecorder\.AudioSource|SpeechRecognizer)"#, "Audio recording APIs"),
    ("READ_EXTERNAL_STORAGE", r#"(Environment\.getExternalStorageDirectory|MediaStore|openFileDescriptor|ContentResolver.*external)"#, "External storage read APIs"),
    ("WRITE_EXTERNAL_STORAGE", r#"(Environment\.getExternalStorageDirectory|MediaStore\.Images\.Media\.insertImage|ContentResolver.*insert.*external)"#, "External storage write APIs"),
    ("MANAGE_EXTERNAL_STORAGE", r#"(Environment\.getExternalStorageDirectory|ACTION_MANAGE_ALL_FILES_ACCESS|MANAGE_EXTERNAL_STORAGE)"#, "All files access APIs"),
    ("READ_CONTACTS", r#"(ContactsContract|content://com\.android\.contacts|ContactsProvider)"#, "Contacts reading APIs"),
    ("WRITE_CONTACTS", r#"(ContactsContract.*insert|ContactsContract.*update|ContactsContract.*delete)"#, "Contacts writing APIs"),
    ("GET_ACCOUNTS", r#"(AccountManager|getAccounts|getAccountsByType)"#, "Account listing APIs"),
    ("READ_CALENDAR", r#"(CalendarContract|content://com\.android\.calendar|CalendarProvider)"#, "Calendar reading APIs"),
    ("WRITE_CALENDAR", r#"(CalendarContract.*insert|CalendarContract.*update|CalendarContract.*delete)"#, "Calendar writing APIs"),
    ("USE_BIOMETRIC", r#"(BiometricPrompt|BiometricManager|FingerprintManager|authenticate\s*\([^)]*CryptoObject)"#, "Biometric APIs"),
    ("BODY_SENSORS", r#"(SensorManager|Sensor\.TYPE_HEART_RATE|TYPE_STEP_COUNTER|HealthConnect)"#, "Body sensor APIs"),
    ("ACTIVITY_RECOGNITION", r#"(ActivityRecognitionClient|ActivityRecognition|DetectedActivity|ActivityTransition)"#, "Activity recognition APIs"),
    ("VIBRATE", r#"(Vibrator|vibrate\s*\(|VibrationEffect|HapticFeedback)"#, "Vibration APIs"),
    ("SYSTEM_ALERT_WINDOW", r#"(WindowManager\.LayoutParams\.TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|SYSTEM_ALERT_WINDOW|canDrawOverlays)"#, "Overlay window APIs"),
    ("REQUEST_INSTALL_PACKAGES", r#"(ACTION_INSTALL_PACKAGE|PackageInstaller|canRequestPackageInstalls|installPackage)"#, "Package install APIs"),
    ("BIND_DEVICE_ADMIN", r#"(DeviceAdminReceiver|DevicePolicyManager|isAdminActive|lockNow|wipeData)"#, "Device admin APIs"),
    ("BIND_ACCESSIBILITY_SERVICE", r#"(AccessibilityService|AccessibilityEvent|AccessibilityNodeInfo|onAccessibilityEvent)"#, "Accessibility APIs"),
    ("QUERY_ALL_PACKAGES", r#"(getInstalledPackages|getInstalledApplications|queryIntentActivities|resolveActivity)"#, "Package query APIs"),
    ("PACKAGE_USAGE_STATS", r#"(UsageStatsManager|UsageStats|queryUsageStats|UsageEvents)"#, "Usage stats APIs"),
    ("FOREGROUND_SERVICE", r#"(startForeground|ServiceCompat\.startForeground|FOREGROUND_SERVICE|ForegroundServiceType)"#, "Foreground service APIs"),
    ("RECEIVE_BOOT_COMPLETED", r#"(BOOT_COMPLETED|BootReceiver|LOCKED_BOOT_COMPLETED|ACTION_BOOT_COMPLETED)"#, "Boot receiver APIs"),
    ("POST_NOTIFICATIONS", r#"(NotificationManager|NotificationCompat|NotificationChannel|createNotificationChannel|notify\s*\()"#, "Notification APIs"),
    ("WAKE_LOCK", r#"(PowerManager|WakeLock|newWakeLock|PARTIAL_WAKE_LOCK)"#, "Wake lock APIs"),
    ("DISABLE_KEYGUARD", r#"(KeyguardManager|disableKeyguard|requestDismissKeyguard|KeyguardLock)"#, "Keyguard APIs"),
    ("READ_LOGS", r#"(logcat|Runtime\.getRuntime\(\)\.exec.*log|android\.util\.Log\.readLogs)"#, "Log reading APIs"),
    ("BIND_NOTIFICATION_LISTENER_SERVICE", r#"(NotificationListenerService|onNotificationPosted|StatusBarNotification|getActiveNotifications)"#, "Notification listener APIs"),
];

fn lookup() -> HashMap<&'static str, (&'static str, &'static str, Severity)> {
    let mut m = HashMap::new();
    for (cat, suffix, desc, sev) in PERM_DB {
        m.insert(*suffix, (*cat, *desc, *sev));
    }
    m
}

fn suffix_of(perm: &str) -> &str {
    match perm.rsplit_once('.') {
        Some((_, s)) => s,
        None => perm,
    }
}

pub struct AndroidPermissionsAnalyzer;

impl Analyzer for AndroidPermissionsAnalyzer {
    fn name(&self) -> &'static str {
        "Android Permissions"
    }
    fn category(&self) -> &'static str {
        "permissions"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let manifest = extracted.join("AndroidManifest.xml");
        if !manifest.exists() {
            return vec![];
        }
        let raw = match std::fs::read(&manifest) {
            Ok(r) => r,
            Err(_) => return vec![],
        };
        let root = match xml::parse_axml_or_xml(&raw) {
            Some(r) => r,
            None => return vec![],
        };

        let lut = lookup();
        let mut findings = Vec::new();

        let mut requested: Vec<String> = Vec::new();
        for tag in ["uses-permission", "uses-permission-sdk-23"] {
            for el in root.iter(tag) {
                if let Some(p) = el.android("name") {
                    requested.push(p.to_string());
                }
            }
        }

        if requested.is_empty() {
            findings.push(Finding::new(
                "PERM_NONE",
                "No permissions requested",
                "The app does not request any permissions. This is unusual for most apps.",
                Info,
                "permissions",
            ));
            return findings;
        }

        // Categorize preserving first-seen category order.
        let mut cat_order: Vec<String> = Vec::new();
        let mut categorized: HashMap<String, Vec<(String, &'static str, Severity)>> = HashMap::new();
        let mut unknown: Vec<String> = Vec::new();

        for perm in &requested {
            let suffix = suffix_of(perm);
            if let Some((cat, desc, sev)) = lut.get(suffix) {
                if !categorized.contains_key(*cat) {
                    cat_order.push(cat.to_string());
                }
                categorized
                    .entry(cat.to_string())
                    .or_default()
                    .push((perm.clone(), *desc, *sev));
            } else {
                unknown.push(perm.clone());
            }
        }

        // Per-category summary, sorted by category name.
        let mut sorted_cats: Vec<&String> = categorized.keys().collect();
        sorted_cats.sort();
        for cat in sorted_cats {
            let perms = &categorized[cat];
            let sevs: Vec<Severity> = perms.iter().map(|p| p.2).collect();
            let mut max_sev = Severity::py_max(&sevs).unwrap_or(Info);
            if max_sev == High {
                max_sev = Medium;
            }
            let perm_list: Vec<String> = perms.iter().map(|p| format!("{} — {}", p.0, p.1)).collect();
            let dangerous = perms.iter().filter(|p| matches!(p.2, High | Critical)).count();
            findings.push(
                Finding::new(
                    &format!("PERM_{}", cat.to_uppercase()),
                    format!(
                        "Permissions: {} ({}, {} dangerous)",
                        cat.replace('_', " "),
                        perms.len(),
                        dangerous
                    ),
                    format!(
                        "{} permission(s) in category '{}': {}",
                        perms.len(),
                        cat,
                        perm_list.join("; ")
                    ),
                    max_sev,
                    "permissions",
                )
                .masvs("MASVS-PLATFORM")
                .meta("category", json!(cat))
                .meta("permissions", json!(perms.iter().map(|p| p.0.clone()).collect::<Vec<_>>()))
                .meta("count", json!(perms.len()))
                .meta("dangerous", json!(dangerous)),
            );
        }

        if !unknown.is_empty() {
            findings.push(
                Finding::new(
                    "PERM_UNKNOWN",
                    format!("Custom/unknown permissions ({})", unknown.len()),
                    format!(
                        "The app requests {} non-standard permission(s): {}. Verify these are legitimate and properly protected.",
                        unknown.len(),
                        unknown.join("; ")
                    ),
                    Info,
                    "permissions",
                )
                .meta("permissions", json!(unknown)),
            );
        }

        // Permission-to-code mapping.
        findings.extend(check_permission_mapping(&requested, extracted, &lut));

        // Summary.
        let mut categories_map = Map::new();
        for cat in &cat_order {
            categories_map.insert(cat.clone(), json!(categorized[cat].len()));
        }
        findings.push(
            Finding::new(
                "PERM_SUMMARY",
                format!("Total permissions requested: {}", requested.len()),
                format!(
                    "The app requests {} permission(s) across {} categories.",
                    requested.len(),
                    cat_order.len()
                ),
                Info,
                "permissions",
            )
            .meta("total", json!(requested.len()))
            .meta("categories", Value::Object(categories_map))
            .meta("unknown_count", json!(unknown.len())),
        );

        findings
    }
}

fn check_permission_mapping(
    requested: &[String],
    extracted: &Path,
    lut: &HashMap<&'static str, (&'static str, &'static str, Severity)>,
) -> Vec<Finding> {
    let code_files = find_files_by_ext(extracted, &["java", "kt", "smali"]);
    let mut all_code = String::new();
    let mut per_file: Vec<(String, String)> = Vec::new();
    for fpath in &code_files {
        if let Some(c) = read_text(fpath) {
            all_code.push_str(&c);
            all_code.push('\n');
            per_file.push((rel(fpath, extracted), c));
        }
    }
    if all_code.is_empty() {
        return vec![];
    }

    let api_map: HashMap<&str, (&str, &str)> = PERM_TO_API
        .iter()
        .map(|(s, p, d)| (*s, (*p, *d)))
        .collect();

    let mut requested_suffixes: Vec<String> = requested.iter().map(|p| suffix_of(p).to_string()).collect();
    requested_suffixes.sort();
    requested_suffixes.dedup();
    let req_set: HashSet<&str> = requested_suffixes.iter().map(|s| s.as_str()).collect();

    let mut findings = Vec::new();

    // Over-privileged: requested but no matching API.
    for suffix in &requested_suffixes {
        if let Some((pattern, api_desc)) = api_map.get(suffix.as_str()) {
            if !rx(pattern).is_match(&all_code).unwrap_or(false) {
                findings.push(
                    Finding::new(
                        "PERM_UNUSED",
                        format!("Unused permission: {suffix}"),
                        format!(
                            "Permission {suffix} is requested but no matching API usage found ({api_desc}). The app may be over-privileged. Remove unused permissions to reduce attack surface."
                        ),
                        Medium,
                        "permissions",
                    )
                    .cwe("CWE-250")
                    .masvs("MASVS-PLATFORM")
                    .meta("permission", json!(suffix))
                    .meta("expected_apis", json!(api_desc)),
                );
            }
        }
    }

    // Missing: API used but permission not requested (PERM_TO_API order).
    for (suffix, pattern, api_desc) in PERM_TO_API {
        if req_set.contains(suffix) {
            continue;
        }
        if !lut.contains_key(suffix) {
            continue;
        }
        let re = rx(pattern);
        if re.is_match(&all_code).unwrap_or(false) {
            let mut matched_file: Option<String> = None;
            let mut matched_line: u64 = 0;
            for (rel_path, content) in &per_file {
                if let Ok(Some(m)) = re.find(content) {
                    matched_file = Some(rel_path.clone());
                    matched_line = line_of(content, m.start());
                    break;
                }
            }
            let mut f = Finding::new(
                "PERM_MISSING",
                format!("Missing permission: {suffix}"),
                format!(
                    "Code uses {api_desc} but {suffix} is not declared in the manifest. This may cause SecurityException at runtime or indicate dead code."
                ),
                High,
                "permissions",
            )
            .cwe("CWE-862")
            .masvs("MASVS-PLATFORM")
            .meta("permission", json!(suffix))
            .meta("apis_found", json!(api_desc));
            if let Some(mf) = matched_file {
                f = f.file_path(mf);
            }
            if matched_line != 0 {
                f = f.line(matched_line);
            }
            findings.push(f);
        }
    }

    findings
}

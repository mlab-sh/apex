//! Android API usage detection — sensitive API calls in Java/Kotlin/Smali/XML.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{find_files_by_ext, line_of, read_text, rel, rx_flags};
use fancy_regex::Regex;
use std::collections::HashSet;
use std::path::Path;

struct Rule {
    id: &'static str,
    title: &'static str,
    desc: &'static str,
    sev: Severity,
    pat: &'static str,
    i: bool,
    cwe: Option<&'static str>,
    masvs: Option<&'static str>,
}

use Severity::*;

fn rules() -> Vec<Rule> {
    vec![
        Rule { id: "API_NATIVE_CODE", title: "Native code loading", desc: "App loads native libraries via System.loadLibrary() or System.load(). Native code can bypass Java-level security controls.", sev: Info, pat: r#"System\.(loadLibrary|load)\s*\("#, i: false, cwe: None, masvs: Some("MASVS-CODE") },
        Rule { id: "API_DYNAMIC_CLASS", title: "Dynamic class loading", desc: "App loads classes dynamically via DexClassLoader, PathClassLoader, or ClassLoader. Can be used to load code at runtime.", sev: Medium, pat: r#"(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|URLClassLoader|Class\.forName\s*\()"#, i: false, cwe: Some("CWE-94"), masvs: Some("MASVS-CODE") },
        Rule { id: "API_DEX_MANIPULATION", title: "DEX file manipulation", desc: "App manipulates DEX files directly. May indicate dynamic code loading, packing, or code injection.", sev: Medium, pat: r#"(DexFile|dalvik\.system\.DexFile|\.loadDex\s*\(|openDexFile|classes\.dex)"#, i: false, cwe: Some("CWE-94"), masvs: Some("MASVS-CODE") },
        Rule { id: "API_REFLECTION", title: "Reflection usage", desc: "App uses Java reflection to access methods/fields at runtime. Can bypass access controls and obfuscate behavior.", sev: Info, pat: r#"(java\.lang\.reflect\.|\.getMethod\s*\(|\.getDeclaredMethod\s*\(|\.getDeclaredField\s*\(|\.getField\s*\(|\.invoke\s*\(|Method\.invoke)"#, i: false, cwe: None, masvs: Some("MASVS-CODE") },
        Rule { id: "API_OS_COMMAND", title: "OS command execution", desc: "App executes operating system commands via Runtime.exec() or ProcessBuilder. Can be used for privilege escalation or data exfiltration.", sev: High, pat: r#"(Runtime\.getRuntime\(\)\s*\.exec\s*\(|ProcessBuilder\s*\(|\.start\s*\(\s*\).*Process)"#, i: false, cwe: Some("CWE-78"), masvs: Some("MASVS-CODE") },
        Rule { id: "API_IPC_ACTIVITY", title: "IPC: Activity invocation", desc: "App starts activities via startActivity/startActivityForResult. Inter-component communication detected.", sev: Info, pat: r#"(startActivity|startActivityForResult|startActivityIfNeeded)\s*\("#, i: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_IPC_SERVICE", title: "IPC: Service invocation", desc: "App starts or binds to services. Background processing or inter-app communication detected.", sev: Info, pat: r#"(startService|bindService|startForegroundService|stopService)\s*\("#, i: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_IPC_BROADCAST", title: "IPC: Broadcast operations", desc: "App sends or registers broadcast receivers. Can be used for inter-app messaging.", sev: Info, pat: r#"(sendBroadcast|sendOrderedBroadcast|sendStickyBroadcast|registerReceiver|LocalBroadcastManager)\s*\("#, i: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_IPC_CONTENT_PROVIDER", title: "IPC: ContentProvider access", desc: "App accesses ContentProviders via ContentResolver. May read/write data from other apps.", sev: Info, pat: r#"(ContentResolver|getContentResolver\s*\(\)|content://|ContentProvider|ContentValues)"#, i: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_HTTP_CONNECTION", title: "HTTP/HTTPS connections", desc: "App makes HTTP/HTTPS connections via HttpURLConnection, OkHttp, or HttpClient.", sev: Info, pat: r#"(HttpURLConnection|HttpsURLConnection|OkHttpClient|HttpClient|DefaultHttpClient|AndroidHttpClient|Retrofit|Volley\.newRequestQueue)"#, i: false, cwe: None, masvs: Some("MASVS-NETWORK") },
        Rule { id: "API_TCP_UDP_SOCKET", title: "TCP/UDP socket operations", desc: "App creates raw TCP or UDP sockets. Low-level network communication detected.", sev: Medium, pat: r#"(new\s+Socket\s*\(|new\s+ServerSocket\s*\(|DatagramSocket|DatagramPacket|SocketChannel\.open|java\.net\.Socket)"#, i: false, cwe: None, masvs: Some("MASVS-NETWORK") },
        Rule { id: "API_URL_CONNECTION", title: "URL connections", desc: "App opens URL connections directly. Network data transfer detected.", sev: Info, pat: r#"(URL\s*\([^)]*\)\s*\.openConnection|URLConnection|openStream\s*\(\s*\))"#, i: false, cwe: None, masvs: Some("MASVS-NETWORK") },
        Rule { id: "API_WEBVIEW_REQUEST", title: "WebView requests", desc: "App loads URLs in WebView components. Web content rendering detected.", sev: Info, pat: r#"\.(loadUrl|loadData|loadDataWithBaseURL|postUrl)\s*\("#, i: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_FILE_OPS", title: "File operations", desc: "App performs file I/O operations (FileInputStream, FileOutputStream, FileReader, FileWriter).", sev: Info, pat: r#"(FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|openFileInput|openFileOutput)"#, i: false, cwe: None, masvs: Some("MASVS-STORAGE") },
        Rule { id: "API_SHARED_PREFS", title: "SharedPreferences access", desc: "App uses SharedPreferences for local data storage.", sev: Info, pat: r#"(getSharedPreferences|getDefaultSharedPreferences|SharedPreferences\.Editor|PreferenceManager)"#, i: false, cwe: None, masvs: Some("MASVS-STORAGE") },
        Rule { id: "API_DATABASE", title: "Database access", desc: "App accesses SQLite databases. Local data persistence detected.", sev: Info, pat: r#"(SQLiteDatabase|SQLiteOpenHelper|openOrCreateDatabase|\.rawQuery\s*\(|\.execSQL\s*\(|Room\.databaseBuilder|RoomDatabase)"#, i: false, cwe: None, masvs: Some("MASVS-STORAGE") },
        Rule { id: "API_CLIPBOARD", title: "Clipboard operations", desc: "App accesses the system clipboard. Copied data is readable by all apps (pre-Android 10).", sev: Medium, pat: r#"(ClipboardManager|ClipData|setPrimaryClip|getPrimaryClip|android\.content\.ClipboardManager)"#, i: false, cwe: Some("CWE-200"), masvs: Some("MASVS-STORAGE") },
        Rule { id: "API_LOCAL_STORAGE", title: "Local storage access", desc: "App accesses internal or cache storage directories.", sev: Info, pat: r#"(getFilesDir|getCacheDir|getDir\s*\(|getDataDir|getNoBackupFilesDir|context\.openFileOutput)"#, i: false, cwe: None, masvs: Some("MASVS-STORAGE") },
        Rule { id: "API_ENCRYPTION", title: "Encryption APIs", desc: "App uses encryption APIs (Cipher, KeyGenerator, SecretKeyFactory). Cryptographic operations detected.", sev: Info, pat: r#"(javax\.crypto\.Cipher|Cipher\.getInstance|KeyGenerator\.getInstance|SecretKeyFactory|SecretKeySpec|KeyAgreement)"#, i: false, cwe: None, masvs: Some("MASVS-CRYPTO") },
        Rule { id: "API_MESSAGE_DIGEST", title: "Message digest operations", desc: "App computes message digests (hashes). Data integrity or fingerprinting operations detected.", sev: Info, pat: r#"(MessageDigest\.getInstance|DigestInputStream|DigestOutputStream|Mac\.getInstance|HmacUtils)"#, i: false, cwe: None, masvs: Some("MASVS-CRYPTO") },
        Rule { id: "API_BASE64", title: "Base64 encoding/decoding", desc: "App uses Base64 encoding/decoding. May be used to encode sensitive data or tokens.", sev: Info, pat: r#"(Base64\.(encode|decode|encodeToString)|android\.util\.Base64|java\.util\.Base64)"#, i: false, cwe: None, masvs: Some("MASVS-CRYPTO") },
        Rule { id: "API_KEYSTORE", title: "Keystore access", desc: "App uses the Android Keystore system for secure key storage.", sev: Info, pat: r#"(KeyStore\.getInstance|AndroidKeyStore|KeyGenParameterSpec|KeyPairGenerator\.getInstance|KeyProperties)"#, i: false, cwe: None, masvs: Some("MASVS-CRYPTO") },
        Rule { id: "API_TELEPHONY", title: "Telephony data access (IMEI, SIM, phone number)", desc: "App accesses telephony data including IMEI, SIM serial, subscriber ID, or phone number. Sensitive device identifier access.", sev: High, pat: r#"(TelephonyManager|getDeviceId\s*\(|getImei\s*\(|getSubscriberId\s*\(|getSimSerialNumber\s*\(|getLine1Number\s*\(|getMeid\s*\()"#, i: false, cwe: Some("CWE-359"), masvs: Some("MASVS-PRIVACY") },
        Rule { id: "API_WIFI_INFO", title: "WiFi information access", desc: "App accesses WiFi information (SSID, BSSID, MAC address). Network fingerprinting detected.", sev: Medium, pat: r#"(WifiManager|WifiInfo|getConnectionInfo|getSSID|getBSSID|getMacAddress\s*\()"#, i: false, cwe: Some("CWE-359"), masvs: Some("MASVS-PRIVACY") },
        Rule { id: "API_NETWORK_INTERFACE", title: "Network interface enumeration", desc: "App enumerates network interfaces. Can be used for device fingerprinting or network reconnaissance.", sev: Info, pat: r#"(NetworkInterface\.getNetworkInterfaces|getHardwareAddress|getInetAddresses|ConnectivityManager\.getActiveNetworkInfo)"#, i: false, cwe: None, masvs: Some("MASVS-PRIVACY") },
        Rule { id: "API_GPS_LOCATION", title: "GPS location access", desc: "App accesses GPS or network location. User location tracking detected.", sev: High, pat: r#"(LocationManager|LocationListener|requestLocationUpdates|getLastKnownLocation|FusedLocationProviderClient|LocationRequest|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION)"#, i: false, cwe: Some("CWE-359"), masvs: Some("MASVS-PRIVACY") },
        Rule { id: "API_INSTALLED_APPS", title: "Installed apps enumeration", desc: "App lists installed applications. Can be used for user profiling or detecting security tools.", sev: Medium, pat: r#"(getInstalledPackages|getInstalledApplications|queryIntentActivities|PackageManager\.GET_META_DATA|getLaunchIntentForPackage)"#, i: false, cwe: Some("CWE-200"), masvs: Some("MASVS-PRIVACY") },
        Rule { id: "API_SMS_SEND", title: "SMS sending", desc: "App can send SMS messages. May be used for premium SMS fraud or data exfiltration.", sev: High, pat: r#"(SmsManager|sendTextMessage|sendMultipartTextMessage|sendDataMessage|SEND_SMS)"#, i: false, cwe: Some("CWE-927"), masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_KILL_PROCESS", title: "Process termination", desc: "App can kill processes. May be used to terminate security tools or other apps.", sev: Medium, pat: r#"(Process\.killProcess|killBackgroundProcesses|Runtime\.getRuntime\(\)\.exit|System\.exit|android\.os\.Process\.myPid)"#, i: false, cwe: None, masvs: Some("MASVS-CODE") },
        Rule { id: "API_OBFUSCATION_CHECK", title: "Obfuscation detection", desc: "References to obfuscation tools detected (ProGuard, R8, DexGuard mapping). May indicate code protection.", sev: Info, pat: r#"(proguard|ProGuard|mapping\.txt|R8|dexguard|DexGuard|-keepclassmembers|-dontwarn)"#, i: true, cwe: None, masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "API_ICON_HIDE", title: "App icon hiding", desc: "App can hide its launcher icon via setComponentEnabledSetting. Suspicious behavior for non-utility apps.", sev: High, pat: r#"(setComponentEnabledSetting\s*\([^)]*COMPONENT_ENABLED_STATE_DISABLED|PackageManager\.COMPONENT_ENABLED_STATE_DISABLED)"#, i: false, cwe: Some("CWE-451"), masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "API_WEBVIEW_INTERFACE", title: "WebView JavaScript interface", desc: "App exposes Java objects to JavaScript via addJavascriptInterface(). Potential code execution bridge.", sev: Medium, pat: r#"\.addJavascriptInterface\s*\("#, i: false, cwe: Some("CWE-749"), masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_JS_BRIDGE", title: "JavaScript bridge evaluation", desc: "App evaluates JavaScript in WebView via evaluateJavascript() or loadUrl('javascript:...'). Code injection risk.", sev: Medium, pat: r#"(\.evaluateJavascript\s*\(|loadUrl\s*\(\s*["']javascript:)"#, i: false, cwe: Some("CWE-94"), masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_CERT_HANDLING", title: "Certificate handling", desc: "App handles X.509 certificates directly. Custom certificate validation or pinning detected.", sev: Info, pat: r#"(X509Certificate|CertificateFactory|X509TrustManager|TrustManagerFactory|CertPathValidator|PKIXParameters)"#, i: false, cwe: None, masvs: Some("MASVS-NETWORK") },
        Rule { id: "API_NOTIFICATIONS", title: "Notification access", desc: "App creates notifications or accesses the NotificationManager. May display content to the user.", sev: Info, pat: r#"(NotificationManager|NotificationCompat|NotificationChannel|Notification\.Builder|createNotificationChannel)"#, i: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_RUNNING_PROCESSES", title: "Running processes access", desc: "App lists running processes or services. Can be used to detect security tools or profile the device.", sev: Medium, pat: r#"(getRunningAppProcesses|getRunningServices|getRunningTasks|ActivityManager\.RunningAppProcessInfo)"#, i: false, cwe: Some("CWE-200"), masvs: Some("MASVS-PRIVACY") },
        Rule { id: "API_PASSKEYS", title: "Passkeys support", desc: "App uses FIDO2/Passkeys APIs for passwordless authentication.", sev: Info, pat: r#"(Fido2ApiClient|PublicKeyCredential|AuthenticatorAttestationResponse|CredentialManager\.create|CreatePublicKeyCredentialRequest)"#, i: false, cwe: None, masvs: Some("MASVS-AUTH") },
        Rule { id: "API_CREDENTIAL_MANAGER", title: "Credential management", desc: "App uses the Credential Manager API for secure credential storage and retrieval.", sev: Info, pat: r#"(CredentialManager|GetCredentialRequest|CreatePasswordRequest|GetPasswordOption|SmartLockPasswords|Credentials\.getClient)"#, i: false, cwe: None, masvs: Some("MASVS-AUTH") },
        Rule { id: "API_CAMERA", title: "Camera access", desc: "App accesses the device camera. Photo/video capture detected.", sev: Info, pat: r#"(android\.hardware\.Camera|Camera\.open|CameraManager|camera2|MediaRecorder\.setVideoSource|CAMERA_SERVICE)"#, i: false, cwe: None, masvs: Some("MASVS-PRIVACY") },
        Rule { id: "API_MICROPHONE", title: "Microphone/audio recording", desc: "App records audio via MediaRecorder or AudioRecord. Potential eavesdropping capability.", sev: High, pat: r#"(AudioRecord|MediaRecorder\.setAudioSource|MediaRecorder\.AudioSource\.MIC|RECORD_AUDIO|AudioManager\.startBluetoothSco)"#, i: false, cwe: Some("CWE-359"), masvs: Some("MASVS-PRIVACY") },
        Rule { id: "API_BIOMETRIC", title: "Biometric authentication", desc: "App uses biometric authentication (fingerprint, face). BiometricPrompt or FingerprintManager detected.", sev: Info, pat: r#"(BiometricPrompt|BiometricManager|FingerprintManager|FingerprintManagerCompat|authenticate\s*\([^)]*CryptoObject)"#, i: false, cwe: None, masvs: Some("MASVS-AUTH") },
        Rule { id: "API_ACCESSIBILITY", title: "Accessibility service usage", desc: "App uses or registers an AccessibilityService. Can monitor all user interactions and screen content.", sev: High, pat: r#"(AccessibilityService|AccessibilityEvent|AccessibilityNodeInfo|android\.accessibilityservice|performAction\s*\(\s*AccessibilityNodeInfo)"#, i: false, cwe: Some("CWE-200"), masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_DEVICE_ADMIN", title: "Device administrator usage", desc: "App requests device administrator privileges. Can enforce policies, lock device, or wipe data.", sev: High, pat: r#"(DeviceAdminReceiver|DevicePolicyManager|BIND_DEVICE_ADMIN|isAdminActive|lockNow|wipeData)"#, i: false, cwe: Some("CWE-250"), masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_BLUETOOTH", title: "Bluetooth operations", desc: "App uses Bluetooth APIs for device discovery, pairing, or data transfer.", sev: Info, pat: r#"(BluetoothAdapter|BluetoothDevice|BluetoothSocket|BluetoothGatt|BluetoothLeScanner|startDiscovery|createBond)"#, i: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_NFC", title: "NFC operations", desc: "App uses NFC for near-field communication (payment, tag reading, beam).", sev: Info, pat: r#"(NfcAdapter|NdefMessage|NdefRecord|IsoDep|NfcManager|enableForegroundDispatch|HCE|HostApduService)"#, i: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_USB", title: "USB host/accessory operations", desc: "App communicates with USB devices. May access external hardware or transfer data.", sev: Medium, pat: r#"(UsbManager|UsbDevice|UsbInterface|UsbAccessory|USB_SERVICE|openDevice)"#, i: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_ALARM_SCHEDULER", title: "Alarm/job scheduling", desc: "App schedules background tasks via AlarmManager, JobScheduler, or WorkManager.", sev: Info, pat: r#"(AlarmManager|JobScheduler|WorkManager|JobInfo\.Builder|PeriodicWorkRequest|OneTimeWorkRequest|setExactAndAllowWhileIdle)"#, i: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "API_PACKAGE_INSTALL", title: "Package installation", desc: "App can install other packages. May be used for dropper behavior or silent installs.", sev: High, pat: r#"(ACTION_INSTALL_PACKAGE|PackageInstaller|installPackage|canRequestPackageInstalls|REQUEST_INSTALL_PACKAGES)"#, i: false, cwe: Some("CWE-94"), masvs: Some("MASVS-CODE") },
        Rule { id: "API_SCREEN_CAPTURE", title: "Screen capture/projection", desc: "App uses MediaProjection API for screen capture or recording.", sev: High, pat: r#"(MediaProjection|MediaProjectionManager|createScreenCaptureIntent|getMediaProjection|VirtualDisplay)"#, i: false, cwe: Some("CWE-200"), masvs: Some("MASVS-PRIVACY") },
        Rule { id: "API_CONTACTS", title: "Contacts access", desc: "App reads or writes to the contacts database. PII access detected.", sev: High, pat: r#"(ContactsContract|ContactsProvider|READ_CONTACTS|WRITE_CONTACTS|content://com\.android\.contacts)"#, i: false, cwe: Some("CWE-359"), masvs: Some("MASVS-PRIVACY") },
    ]
}

pub struct AndroidApiAnalyzer;

impl Analyzer for AndroidApiAnalyzer {
    fn name(&self) -> &'static str {
        "Android API Detection"
    }
    fn category(&self) -> &'static str {
        "api"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let files = find_files_by_ext(extracted, &["java", "kt", "smali", "xml"]);
        if files.is_empty() {
            return vec![];
        }

        let compiled: Vec<(Rule, Regex)> = rules()
            .into_iter()
            .map(|r| {
                let re = rx_flags(r.pat, r.i, false, false);
                (r, re)
            })
            .collect();

        let mut findings = Vec::new();
        let mut seen: HashSet<&'static str> = HashSet::new();

        for fpath in &files {
            let content = match read_text(fpath) {
                Some(c) => c,
                None => continue,
            };
            let rel_path = rel(fpath, extracted);

            for (rule, re) in &compiled {
                if seen.contains(rule.id) {
                    continue;
                }
                let m = match re.find(&content) {
                    Ok(Some(m)) => m,
                    _ => continue,
                };
                seen.insert(rule.id);
                let line = line_of(&content, m.start());

                let mut f = Finding::new(rule.id, rule.title, rule.desc, rule.sev, "api")
                    .file_path(rel_path.clone())
                    .line(line);
                if let Some(c) = rule.cwe {
                    f = f.cwe(c);
                }
                if let Some(m) = rule.masvs {
                    f = f.masvs(m);
                }
                findings.push(f);
            }
        }

        findings
    }
}

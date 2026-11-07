package sh.mlab.apex.agent;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStatsManager;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.ContentProvider;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.database.Cursor;
import android.media.ExifInterface;
import android.media.MediaMetadataRetriever;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import android.provider.CalendarContract;
import android.provider.CallLog;
import android.provider.ContactsContract;
import android.provider.MediaStore;
import android.service.notification.StatusBarNotification;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import android.util.JsonWriter;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * One JSON document per read: `content read --uri content://sh.mlab.apex.agent/dump/<s1,s2,…>`.
 * Sections: packages accounts telephony bluetooth usage media | under mandate: contacts calllog calendar media_gps,
 * and in the full build only: sms notifications (the lite build lacks those permissions; the sections come back empty).
 * A section that fails is reported under "errors" and the others go on.
 */
public class DumpProvider extends ContentProvider {
    static final int VERSION = 1;

    @Override public boolean onCreate() { return true; }
    @Override public Cursor query(Uri u, String[] p, String s, String[] a, String o) { return null; }
    @Override public String getType(Uri u) { return "application/json"; }
    @Override public Uri insert(Uri u, ContentValues v) { return null; }
    @Override public int delete(Uri u, String s, String[] a) { return 0; }
    @Override public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) {
        Context ctx = getContext();
        Set<String> want = new HashSet<>();
        List<String> seg = uri.getPathSegments();
        if (seg.size() > 1) want.addAll(Arrays.asList(seg.get(1).split(",")));
        File out = new File(ctx.getCacheDir(), "dump.json");
        // Each section is written to its own buffer: one that fails is reported
        // under "errors" and leaves the document valid.
        StringBuilder errors = new StringBuilder();
        try (Writer f = new OutputStreamWriter(new FileOutputStream(out), "UTF-8")) {
            f.write("{\"agent_version\":" + VERSION + ",\"time_ms\":" + System.currentTimeMillis() + ",\"sdk\":" + Build.VERSION.SDK_INT + ",\"sections\":{");
            boolean first = true;
            for (String s : new String[]{"packages", "accounts", "telephony", "bluetooth", "usage", "media", "ca_certs", "contacts", "calllog", "sms", "calendar", "notifications"}) {
                if (!want.isEmpty() && !want.contains(s)) continue;
                StringWriter sw = new StringWriter();
                try (JsonWriter w = new JsonWriter(sw)) {
                    section(ctx, s, want.contains("media_gps"), w);
                } catch (Throwable t) {
                    errors.append(s).append(": ").append(t).append('\n');
                    continue;
                }
                f.write((first ? "" : ",") + JSONObject.quote(s) + ":" + sw);
                first = false;
            }
            f.write("},\"errors\":" + JSONObject.quote(errors.toString()) + "}");
        } catch (Exception e) {
            return null;
        }
        try {
            return ParcelFileDescriptor.open(out, ParcelFileDescriptor.MODE_READ_ONLY);
        } catch (Exception e) {
            return null;
        }
    }

    private static void section(Context ctx, String s, boolean gps, JsonWriter w) throws Exception {
        switch (s) {
            case "packages": packages(ctx, w); break;
            case "accounts": accounts(ctx, w); break;
            case "telephony": telephony(ctx, w); break;
            case "bluetooth": bluetooth(w); break;
            case "usage": usage(ctx, w); break;
            case "media": media(ctx, gps, w); break;
            case "ca_certs": caCerts(w); break;
            case "contacts": cursor(ctx, ContactsContract.Data.CONTENT_URI, w); break;
            case "calllog": cursor(ctx, CallLog.Calls.CONTENT_URI, w); break;
            case "sms": cursor(ctx, Uri.parse("content://sms"), w); break;
            case "calendar": cursor(ctx, CalendarContract.Events.CONTENT_URI, w); break;
            case "notifications": notifications(w); break;
            default: w.beginArray(); w.endArray();
        }
    }

    /** Every non-blob column of every row. */
    private static void cursor(Context ctx, Uri uri, JsonWriter w) throws Exception {
        w.beginArray();
        try (Cursor c = ctx.getContentResolver().query(uri, null, null, null, null)) {
            while (c != null && c.moveToNext()) {
                w.beginObject();
                for (int i = 0; i < c.getColumnCount(); i++) {
                    int t = c.getType(i);
                    if (t == Cursor.FIELD_TYPE_NULL || t == Cursor.FIELD_TYPE_BLOB) continue;
                    w.name(c.getColumnName(i));
                    if (t == Cursor.FIELD_TYPE_INTEGER) w.value(c.getLong(i));
                    else if (t == Cursor.FIELD_TYPE_FLOAT) w.value(c.getDouble(i));
                    else w.value(c.getString(i));
                }
                w.endObject();
            }
        }
        w.endArray();
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    /** Certificate authorities trusted by the phone; "user:" aliases were added by the user. */
    private static void caCerts(JsonWriter w) throws Exception {
        java.security.KeyStore ks = java.security.KeyStore.getInstance("AndroidCAStore");
        ks.load(null, null);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        java.text.SimpleDateFormat iso = new java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.ROOT);
        w.beginArray();
        java.util.Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            boolean user = alias.startsWith("user:");
            if (!user) continue; // system ones are the same on every phone of a version
            java.security.cert.Certificate c = ks.getCertificate(alias);
            if (!(c instanceof java.security.cert.X509Certificate)) continue;
            java.security.cert.X509Certificate x = (java.security.cert.X509Certificate) c;
            w.beginObject();
            w.name("alias").value(alias);
            w.name("user").value(true);
            w.name("subject").value(x.getSubjectX500Principal().getName());
            w.name("issuer").value(x.getIssuerX500Principal().getName());
            w.name("not_before").value(iso.format(x.getNotBefore()));
            w.name("not_after").value(iso.format(x.getNotAfter()));
            w.name("sha256").value(hex(sha256.digest(x.getEncoded())));
            w.endObject();
        }
        w.endArray();
    }

    @SuppressWarnings("deprecation")
    private static void packages(Context ctx, JsonWriter w) throws Exception {
        PackageManager pm = ctx.getPackageManager();
        int flags = PackageManager.GET_PERMISSIONS | PackageManager.MATCH_UNINSTALLED_PACKAGES | PackageManager.MATCH_DISABLED_COMPONENTS
                | (Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256"), sha1 = MessageDigest.getInstance("SHA-1");
        w.beginArray();
        for (PackageInfo p : pm.getInstalledPackages(flags)) {
            ApplicationInfo a = p.applicationInfo;
            w.beginObject();
            w.name("package").value(p.packageName);
            w.name("label").value(a != null ? String.valueOf(a.loadLabel(pm)) : "");
            w.name("version_name").value(p.versionName);
            w.name("version_code").value(Build.VERSION.SDK_INT >= 28 ? p.getLongVersionCode() : p.versionCode);
            w.name("first_install_ms").value(p.firstInstallTime);
            w.name("last_update_ms").value(p.lastUpdateTime);
            if (a != null) {
                w.name("system").value((a.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
                w.name("enabled").value(a.enabled);
                w.name("installed").value((a.flags & ApplicationInfo.FLAG_INSTALLED) != 0);
                w.name("debuggable").value((a.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
                w.name("uid").value(a.uid);
                w.name("target_sdk").value(a.targetSdkVersion);
                w.name("apk").value(a.sourceDir);
                w.name("data_dir").value(a.dataDir);
                w.name("splits").beginArray();
                if (a.splitSourceDirs != null) for (String x : a.splitSourceDirs) w.value(x);
                w.endArray();
            }
            try {
                if (Build.VERSION.SDK_INT >= 30) {
                    InstallSourceInfo i = pm.getInstallSourceInfo(p.packageName);
                    w.name("installer").value(i.getInstallingPackageName());
                    w.name("initiator").value(i.getInitiatingPackageName());
                    w.name("originator").value(i.getOriginatingPackageName());
                } else {
                    w.name("installer").value(pm.getInstallerPackageName(p.packageName));
                }
            } catch (Exception ignored) { }
            Signature[] sigs = null;
            if (Build.VERSION.SDK_INT >= 28 && p.signingInfo != null) {
                sigs = p.signingInfo.hasMultipleSigners() ? p.signingInfo.getApkContentsSigners() : p.signingInfo.getSigningCertificateHistory();
            } else if (p.signatures != null) {
                sigs = p.signatures;
            }
            w.name("certs").beginArray();
            if (sigs != null) for (Signature g : sigs) {
                w.beginObject();
                w.name("sha256").value(hex(sha256.digest(g.toByteArray())));
                w.name("sha1").value(hex(sha1.digest(g.toByteArray())));
                w.endObject();
            }
            w.endArray();
            w.name("permissions").beginArray();
            if (p.requestedPermissions != null) for (int i = 0; i < p.requestedPermissions.length; i++) {
                boolean granted = p.requestedPermissionsFlags != null && (p.requestedPermissionsFlags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0;
                w.beginObject().name("name").value(p.requestedPermissions[i]).name("granted").value(granted).endObject();
            }
            w.endArray();
            w.endObject();
        }
        w.endArray();
    }

    private static void accounts(Context ctx, JsonWriter w) throws Exception {
        w.beginArray();
        for (Account a : AccountManager.get(ctx).getAccounts()) {
            w.beginObject().name("name").value(a.name).name("type").value(a.type).endObject();
        }
        w.endArray();
    }

    @SuppressWarnings({"deprecation", "MissingPermission"})
    private static void telephony(Context ctx, JsonWriter w) throws Exception {
        w.beginArray();
        TelephonyManager tm = (TelephonyManager) ctx.getSystemService(Context.TELEPHONY_SERVICE);
        SubscriptionManager sm = (SubscriptionManager) ctx.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
        List<SubscriptionInfo> subs = sm != null ? sm.getActiveSubscriptionInfoList() : null;
        if (subs != null) for (SubscriptionInfo s : subs) {
            w.beginObject();
            w.name("subscription_id").value(s.getSubscriptionId());
            w.name("slot").value(s.getSimSlotIndex());
            w.name("display_name").value(String.valueOf(s.getDisplayName()));
            w.name("carrier").value(String.valueOf(s.getCarrierName()));
            w.name("country").value(s.getCountryIso());
            if (Build.VERSION.SDK_INT >= 29) {
                w.name("mcc").value(s.getMccString());
                w.name("mnc").value(s.getMncString());
            }
            String number = null;
            try {
                number = Build.VERSION.SDK_INT >= 33 ? sm.getPhoneNumber(s.getSubscriptionId()) : s.getNumber();
            } catch (Exception ignored) { }
            if (number == null || number.isEmpty()) {
                try { number = tm.createForSubscriptionId(s.getSubscriptionId()).getLine1Number(); } catch (Exception ignored) { }
            }
            w.name("number").value(number);
            try { w.name("iccid").value(s.getIccId()); } catch (Exception ignored) { }
            if (Build.VERSION.SDK_INT >= 28) w.name("embedded").value(s.isEmbedded());
            w.endObject();
        }
        if (tm != null) {
            w.beginObject();
            w.name("network_operator").value(tm.getNetworkOperatorName());
            w.name("network_country").value(tm.getNetworkCountryIso());
            w.name("sim_operator").value(tm.getSimOperatorName());
            w.name("phone_count").value(Build.VERSION.SDK_INT >= 30 ? tm.getActiveModemCount() : tm.getPhoneCount());
            w.endObject();
        }
        w.endArray();
    }

    @SuppressWarnings("MissingPermission")
    private static void bluetooth(JsonWriter w) throws Exception {
        w.beginArray();
        BluetoothAdapter a = BluetoothAdapter.getDefaultAdapter();
        if (a != null && a.getBondedDevices() != null) for (BluetoothDevice d : a.getBondedDevices()) {
            w.beginObject().name("name").value(d.getName()).name("address").value(d.getAddress())
                    .name("type").value(d.getType()).name("class").value(d.getBluetoothClass() != null ? d.getBluetoothClass().getDeviceClass() : 0).endObject();
        }
        w.endArray();
    }

    /** Usage events the system still keeps: app in front, screen on / off, unlock, boot. */
    private static void usage(Context ctx, JsonWriter w) throws Exception {
        UsageStatsManager um = (UsageStatsManager) ctx.getSystemService(Context.USAGE_STATS_SERVICE);
        long now = System.currentTimeMillis();
        UsageEvents ev = um.queryEvents(now - 400L * 24 * 3600 * 1000, now);
        UsageEvents.Event e = new UsageEvents.Event();
        w.beginArray();
        while (ev != null && ev.hasNextEvent()) {
            ev.getNextEvent(e);
            int t = e.getEventType();
            // 1 resumed, 2 paused, 7 user interaction, 15/16 screen on/off, 17/18 keyguard shown/hidden, 19/20 foreground service, 26/27 shutdown/startup
            if (t != 1 && t != 2 && t != 7 && t != 15 && t != 16 && t != 17 && t != 18 && t != 19 && t != 20 && t != 26 && t != 27) continue;
            w.beginObject().name("time_ms").value(e.getTimeStamp()).name("type").value(t).name("package").value(e.getPackageName())
                    .name("class").value(e.getClassName()).endObject();
        }
        w.endArray();
    }

    /** MediaStore rows (every column: path, sizes, dates, owner app…); GPS from the files with media_gps. */
    @SuppressWarnings("deprecation")
    private static void media(Context ctx, boolean gps, JsonWriter w) throws Exception {
        Uri files = MediaStore.Files.getContentUri("external");
        w.beginArray();
        try (Cursor c = ctx.getContentResolver().query(files, null, null, null, null)) {
            int idCol = c != null ? c.getColumnIndex(MediaStore.MediaColumns._ID) : -1;
            int mimeCol = c != null ? c.getColumnIndex(MediaStore.MediaColumns.MIME_TYPE) : -1;
            while (c != null && c.moveToNext()) {
                w.beginObject();
                for (int i = 0; i < c.getColumnCount(); i++) {
                    int t = c.getType(i);
                    if (t == Cursor.FIELD_TYPE_NULL || t == Cursor.FIELD_TYPE_BLOB) continue;
                    w.name(c.getColumnName(i));
                    if (t == Cursor.FIELD_TYPE_INTEGER) w.value(c.getLong(i));
                    else if (t == Cursor.FIELD_TYPE_FLOAT) w.value(c.getDouble(i));
                    else w.value(c.getString(i));
                }
                String mime = mimeCol >= 0 ? c.getString(mimeCol) : null;
                if (gps && mime != null && idCol >= 0) {
                    Uri u = ContentUris.withAppendedId(files, c.getLong(idCol));
                    try {
                        if (Build.VERSION.SDK_INT >= 29) u = MediaStore.setRequireOriginal(u);
                        if (mime.startsWith("image/")) {
                            try (InputStream in = ctx.getContentResolver().openInputStream(u)) {
                                ExifInterface x = new ExifInterface(in);
                                float[] ll = new float[2];
                                if (x.getLatLong(ll)) w.name("gps_lat").value(ll[0]).name("gps_lon").value(ll[1]);
                                String dt = x.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL);
                                if (dt != null) w.name("exif_datetime").value(dt);
                                String make = x.getAttribute(ExifInterface.TAG_MAKE), model = x.getAttribute(ExifInterface.TAG_MODEL);
                                if (make != null) w.name("exif_make").value(make);
                                if (model != null) w.name("exif_model").value(model);
                            }
                        } else if (mime.startsWith("video/")) {
                            MediaMetadataRetriever r = new MediaMetadataRetriever();
                            try {
                                r.setDataSource(ctx, u);
                                String loc = r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_LOCATION);
                                if (loc != null) w.name("gps_iso6709").value(loc);
                            } finally {
                                r.release();
                            }
                        }
                    } catch (Exception ignored) { }
                }
                w.endObject();
            }
        }
        w.endArray();
    }

    /** Full build: active notifications, with the messages messaging apps keep in them. */
    private static void notifications(JsonWriter w) throws Exception {
        w.beginArray();
        Listener l = Listener.instance;
        StatusBarNotification[] all = l != null ? l.getActiveNotifications() : null;
        if (all != null) for (StatusBarNotification n : all) {
            Bundle x = n.getNotification().extras;
            w.beginObject();
            w.name("package").value(n.getPackageName());
            w.name("post_time_ms").value(n.getPostTime());
            w.name("key").value(n.getKey());
            for (String k : new String[]{"android.title", "android.text", "android.bigText", "android.subText", "android.conversationTitle", "android.summaryText"}) {
                CharSequence v = x.getCharSequence(k);
                if (v != null) w.name(k.substring(8)).value(v.toString());
            }
            Parcelable[] msgs = x.getParcelableArray("android.messages");
            w.name("messages").beginArray();
            if (msgs != null) for (Parcelable p : msgs) {
                if (!(p instanceof Bundle)) continue;
                Bundle b = (Bundle) p;
                CharSequence text = b.getCharSequence("text"), sender = b.getCharSequence("sender");
                w.beginObject().name("time_ms").value(b.getLong("time")).name("sender").value(sender != null ? sender.toString() : null)
                        .name("text").value(text != null ? text.toString() : null).endObject();
            }
            w.endArray();
            w.endObject();
        }
        w.endArray();
    }
}

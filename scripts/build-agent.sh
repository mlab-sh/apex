#!/usr/bin/env bash
# Build the APEX agent APK (agent/apex-agent.apk), embedded in the apex binary.
# Needs a JDK (javac, keytool) and the Android SDK: platforms;android-34 and
# build-tools;34.0.0 (ANDROID_HOME, default ~/Library/Android/sdk). No Gradle.
set -euo pipefail
cd "$(dirname "$0")/.."

SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/34.0.0"
JAR="$SDK/platforms/android-34/android.jar"
for f in "$JAR" "$BT/d8" "$BT/aapt2" "$BT/apksigner" "$BT/zipalign"; do
  [ -e "$f" ] || { echo "missing $f: install platforms;android-34 and build-tools;34.0.0" >&2; exit 1; }
done

OUT=agent/build
rm -rf "$OUT" && mkdir -p "$OUT/classes"

javac -nowarn -Xlint:-options -source 8 -target 8 -bootclasspath "$JAR" -classpath "$JAR" \
  -d "$OUT/classes" $(find agent/src -name '*.java')
"$BT/d8" --release --min-api 26 --lib "$JAR" --output "$OUT" $(find "$OUT/classes" -name '*.class')
# A signing key of its own: the agent is not an app store app.
KS=agent/apex-agent.keystore
[ -f "$KS" ] || keytool -genkeypair -keystore "$KS" -storepass apexagent -keypass apexagent -alias apex \
  -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=APEX agent, O=mlab.sh" >/dev/null 2>&1

# Full build, and lite without the FULL-ONLY blocks (SMS, notification access).
sed '/<!-- FULL-ONLY -->/,/<!-- \/FULL-ONLY -->/d' agent/AndroidManifest.xml > "$OUT/lite.xml"
for variant in full lite; do
  manifest=agent/AndroidManifest.xml; name=apex-agent.apk
  [ $variant = lite ] && { manifest="$OUT/lite.xml"; name=apex-agent-lite.apk; }
  "$BT/aapt2" link -o "$OUT/$variant.apk" -I "$JAR" --manifest "$manifest"
  (cd "$OUT" && zip -q "$variant.apk" classes.dex)
  "$BT/zipalign" -f 4 "$OUT/$variant.apk" "$OUT/$variant-aligned.apk"
  "$BT/apksigner" sign --ks "$KS" --ks-pass pass:apexagent --key-pass pass:apexagent --out "agent/$name" "$OUT/$variant-aligned.apk"
  rm -f "agent/$name.idsig"
done
rm -rf "$OUT"
ls -l agent/apex-agent.apk agent/apex-agent-lite.apk
shasum -a 256 agent/apex-agent.apk agent/apex-agent-lite.apk

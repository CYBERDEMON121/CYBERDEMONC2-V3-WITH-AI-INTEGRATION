[app]

title = CYBERDEMON C2
package.name = cyberdemonc2
package.domain = org.cyberdemon

source.dir = .
source.include_exts = py,png,jpg,kv,atlas

version = 1.0
requirements = python3,kivy,pyjnius,android

orientation = portrait

fullscreen = 1
android.permissions = INTERNET,ACCESS_NETWORK_STATE
android.api = 33
android.minapi = 24
android.ndk = 25b
android.sdk = 33
android.accept_sdk_license = True
android.arch = arm64-v8a
android.archarmeabi-v7a = False

android.release_artifact = apk
android.debug_artifact = apk

icon.filename = %(source.dir)s/icon.png
presplash.filename = %(source.dir)s/presplash.png

launcher.category = default
launcher.icon = %(icon.filename)

log_level = 2

[buildozer]
warn_on_root = 0

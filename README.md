# phantom-frida

Build anti-detection Frida server from source. Covers 16 Android detection vectors with ~90 patches, plus an iOS path producing phantom-ised gadget dylib + server (Mach-O `install_name` rewrite, ad-hoc codesign, symbol-table sweep).

Extended beyond [ajeossida](https://github.com/hackcatml/ajeossida) with additional stealth techniques: custom port, binary string sweep, internal symbol renaming, temp path obfuscation, and more.

## How it works

Phantom-frida clones Frida source, applies patches in 4 phases (source, targeted, post-build, binary), and compiles a custom server where all identifiable "frida" strings, symbols, thread names, and file paths are replaced with a custom name.

Standard Frida client (`pip install frida-tools`) connects to the patched server normally — the client-server protocol is preserved.

## Quick Start

### GitHub Actions (recommended)

**Android** — Actions > **Build Custom Frida** > Run workflow (runs on `ubuntu-22.04` with NDK r29).

**iOS** — Actions > **Build iOS dylib** > Run workflow (runs on `macos-14` with Xcode CLT). Defaults to `ios-arm64,ios-arm64e`.

Both fork-then-trigger. Artifacts ready in ~8 min with cache, ~35 min cold.

### Weekly auto-builds

The **Weekly Stealth Build** workflow runs every Sunday:
- Detects latest Frida version automatically
- Generates a random name and port via `namegen.py`
- Builds with `--extended` for maximum stealth
- Creates a GitHub Release with binary + `build-info.json`

### Local build (WSL Ubuntu)

```bash
python3 build.py --version 17.7.2

# Full options:
python3 build.py --version 17.7.2 --name myserver --port 27142 --extended --verify

# Patch only (inspect changes without compiling):
python3 build.py --version 17.7.2 --skip-build
```

### WSL helper script

```bash
wsl -d Ubuntu bash build-wsl.sh

# With options:
FRIDA_VERSION=17.7.2 CUSTOM_NAME=myserver CUSTOM_PORT=27142 EXTENDED=1 \
  wsl -d Ubuntu bash build-wsl.sh
```

### Local iOS build (macOS only)

iOS targets need Xcode CLT (`xcode-select --install`) and Homebrew `meson` + `pkg-config`. Linux can't cross-compile against the iphoneos SDK.

```bash
brew install meson pkg-config
python3 build.py --version 17.7.2 --arch ios-arm64,ios-arm64e --extended
```

Output: `output/<name>-gadget-17.7.2-ios-{arm64,arm64e}.dylib` and `output/<name>-server-17.7.2-ios-{arm64,arm64e}` — both ad-hoc signed, ready for Dopamine / iOS 16 rootless.

## Detection Vectors

| # | Vector | Detection method | Base | Extended |
|---|--------|-----------------|------|----------|
| 1 | Process name `frida-server` | `/proc/*/cmdline`, `ps` | Renamed | Renamed |
| 2 | `libfrida-agent.so` in maps | `/proc/self/maps` scan | Renamed | Renamed |
| 3 | Thread names `gum-js-loop`, `gmain`, `gdbus` | `/proc/self/task/*/comm` | Renamed | Renamed |
| 4 | memfd name `frida-agent-64.so` | `/proc/self/fd/` readlink | `jit-cache` | `jit-cache` |
| 5 | `frida_agent_main` symbol | `dlsym` / memory scan | Renamed | Renamed |
| 6 | SELinux labels `frida_file` | SELinux context check | Renamed | Renamed |
| 7 | libc hooks (exit, signal) | Hook detection | Disabled | Disabled |
| 8 | D-Bus service `re.frida.server` | D-Bus introspection | Renamed | Renamed |
| 9 | Default port 27042 | `connect()` scan | - | `--port N` |
| 10 | D-Bus interfaces | Protocol inspection | - | Renamed |
| 11 | Internal C symbols | Memory string scan | - | Renamed |
| 12 | GType names `FridaServer` | GObject introspection | - | Renamed |
| 13 | Temp paths `.frida`, `frida-` | Filesystem scan | - | Renamed |
| 14 | Binary string residuals | Binary `strings` scan | - | Swept |
| 15 | Build config defines | Memory scan | - | Renamed |
| 16 | Asset directory `libdir/frida` | Path inspection | - | Renamed |

### iOS-specific vectors

The 16 Android vectors above use `gum-linux` / `linjector` / SELinux / DEX paths that don't exist on iOS. iOS targets cover the cross-platform vectors plus an iOS-specific subset:

| # | Vector | Detection method | Coverage |
|---|--------|-----------------|----------|
| i1 | Mach-O `LC_ID_DYLIB` install_name | `dlopen` / dyld image enumeration | `install_name_tool -id @rpath/lib<name>-gadget.dylib` |
| i2 | ObjC class names `Frida*`, `FridaGadget.dylib` plist | `objc_getClass` / Bundle plist scan | Source patches (extended) |
| i3 | Mach-O symbol table `_frida_*` / `_FRIDA_*` / `_Frida*` | `nm` / runtime `dlsym` | `nm`-driven length-preserving byte sweep |
| i4 | `re.frida.*` Mach service names | XPC / Mach lookup | Source patches (cross-platform) |
| i5 | Process name `frida-server` | `ps`, `proc_listpids` | Renamed via file rename |
| i6 | Code signature mismatch | `codesign -dv` | Re-signed ad-hoc with `--identifier lib<name>-gadget` |
| i7 | Vala-emitted GType names `FridaXxx` (e.g. `FridaAgentSession`, `FridaGadgetController`) | `objc_getClass` / `g_type_from_name` / `strings` scan | 26-pattern PascalCase byte sweep (`Frida[A-Z]` → `<Cap><name[1:5]>[A-Z]`), length-preserving |

The lowercase `Frida\0` JS-runtime API global is intentionally preserved — replacing it crashes the embedded JS engine ([upstream issue #1](https://github.com/TheQmaks/phantom-frida/issues/1)).

Not yet covered (planned):

- JS runtime asset paths `/frida/runtime/*.js` (~91 occurrences). These are paths into the embedded JS asset bundle; renaming requires rebuilding the gum-js-runtime bundle.
- Active dyld image hiding (intercept `_dyld_image_count` / `_dyld_get_image_name` from gadget constructor) — current iOS path relies on rename-only
- universal `lipo` arm64 + arm64e merging — currently two separate dylib files
- Apple Developer codesign for non-jailbroken IPA repackaging — current ad-hoc signature is only valid on jailbroken devices

### iOS verification log

Verified end-to-end on iPhone 14 (A15, arm64e), iOS 16.1, Dopamine rootless:

- Build: `gh workflow run "Build iOS dylib" -f arch=ios-arm64,ios-arm64e` produces gadget dylib + server for both archs in ~12 min (cache-hit rebuild).
- Static: Mach-O 64-bit arm64e (caps PAC00), `install_name=@rpath/libajeossida-gadget.dylib`, `Signature=adhoc Identifier=libajeossida-gadget`, `nm -gU` exported `_frida*` count = 0, `strings | grep '\bFrida[A-Z]'` = 0.
- Deploy: `scp` to `/var/jb/usr/sbin/ajeossida-server` and `/var/jb/usr/lib/libajeossida-gadget.dylib`.
- Runtime (server): `ajeossida-server -l 0.0.0.0:27145` starts cleanly; `frida-ps -H ...:27145` lists 372 processes; `frida -H ...:27145 -p PID --eval 'Frida.version'` returns `"17.7.2"` — JS runtime intact.
- Runtime (gadget): drop the dylib at `/var/jb/usr/lib/libajeossida-gadget.dylib` plus a config at `/var/jb/usr/lib/libajeossida-gadget.config` (note: basename without `.dylib`, plus `.config` — not `.dylib.config`). Inject via `DYLD_INSERT_LIBRARIES=/var/jb/usr/lib/libajeossida-gadget.dylib /var/jb/usr/bin/sleep 120 &`, then `frida-ps -H ...:27146` reports `27294 Gadget` and a script eval returns the expected payload — gadget mode confirmed.

```json
// libajeossida-gadget.config (listen mode)
{
  "interaction": {
    "type": "listen",
    "address": "0.0.0.0",
    "port": 27146,
    "on_port_conflict": "fail",
    "on_load": "resume"
  }
}
```

## Options

```
--version, -v    Frida version to build (required)
--name, -n       Custom name replacing 'frida' (default: ajeossida; use random for stealth)
--arch, -a       Target arch (default: android-arm64)
--port, -p       Custom listening port (default: 27042)
--extended, -e   Enable extended anti-detection (vectors 9-16)
--temp-fixes     Stability fixes (perfetto skip, cloak detach)
--verify         Scan output for residual 'frida' strings
--skip-build     Apply patches only, don't compile
--skip-clone     Use existing source in work-dir
--ndk-path       Path to existing Android NDK r29
```

## Deploy

### Android

```bash
# Push to device
adb push output/myserver-server-17.7.2-android-arm64 /data/local/tmp/myserver-server
adb shell chmod 755 /data/local/tmp/myserver-server

# Start (default port 27042)
adb shell /data/local/tmp/myserver-server -D &
frida -U -f com.example.app

# Start (custom port)
adb shell /data/local/tmp/myserver-server -D &
adb forward tcp:27142 tcp:27142
frida -H 127.0.0.1:27142 -f com.example.app
```

### iOS (Dopamine / rootless)

```bash
DEVICE=root@192.168.x.x

# Server (jailbroken only) — rootless paths under /var/jb/
scp output/myserver-server-17.7.2-ios-arm64e $DEVICE:/var/jb/usr/sbin/myserver-server
ssh $DEVICE "chmod +x /var/jb/usr/sbin/myserver-server && /var/jb/usr/sbin/myserver-server -D &"
frida-ps -H ${DEVICE#root@}:27042

# Gadget — drop into target app's Frameworks (jailbroken Tweak) or repackaged IPA
scp output/myserver-gadget-17.7.2-ios-arm64e.dylib $DEVICE:/var/jb/usr/lib/libmyserver-gadget.dylib
```

Each weekly release includes a `build-info.json` with the name, port, version, and architecture.

## Build Phases

1. **Source patches**: Global string replacement across the entire Frida source tree. Renames all `frida-agent`, `frida-helper`, `frida-server`, `re.frida.*` references. Rebuilds Android helper DEX with renamed Java package.

2. **Targeted patches**: Specific fixes for build system files (meson.build), memfd names, libc hook disabling, SELinux labels.

3. **Post-build patches**: After first compilation, renames `frida_agent_main` symbol (generated by Vala compiler, only exists in build output). Requires a second incremental build.

4. **Binary patches**: Hex-level replacements in compiled binaries — thread names (`gmain`, `gdbus`, `pool-spawner`), and optional binary string sweep for residual `frida`/`Frida` strings.

## Architecture

```
build.py                Main build script (clone, patch, compile, collect)
patches.py              All patch definitions (87 patches + 17 rollbacks)
namegen.py              Random name/port generator for stealth builds
build-wsl.sh            WSL helper script
test_comprehensive.js   Anti-detection + Java bridge verification script
.github/workflows/
  build.yml             Android manual build workflow
  build-ios.yml         iOS manual build workflow (macos-14 runner)
  scheduled-build.yml   Weekly auto-build with releases (Android)
```

## Requirements

**Android**
- Ubuntu 22.04+ (WSL works) or other Linux
- Android NDK r29 (auto-downloaded)

**iOS**
- macOS 14+ with Xcode 15+ Command Line Tools (`xcode-select --install`)
- Homebrew `meson` + `pkg-config`
- iphoneos SDK (`xcrun --sdk iphoneos --show-sdk-path` must succeed)

**Both**
- Python 3.10+
- Git, curl, unzip, make
- ~20 GB free disk space

## Version Support

| Frida | Status |
|-------|--------|
| 17.x | Fully verified against source |
| 16.x | Compatible (auto-detects API differences) |

## Tested Apps

Verified on arm64 Android 14 device with `--extended`:

| App | Java bridge | Hooks | Anti-detection |
|-----|-------------|-------|----------------|
| Telegram | 28,772 classes | SSL+crypto | All clean |
| Google Play Store | 47,305 classes | Activity hooks | All clean |
| Facebook | 54,064 classes | Basic hooks | All clean |
| Magisk | 27,737 classes | Activity hooks | All clean |

## Known Limitations

- **arm32 apps** (Chrome): Frida upstream bug [#2878](https://github.com/frida/frida/issues/2878) — `invalid instruction` in `_patchCode`. Not a phantom-frida issue.
- **D-Bus interface names** (`re.frida.HostSession17` etc.): Intentionally NOT renamed in base mode. These are the client-server protocol — renaming server-side would break standard `frida` client. Not a detection vector (only visible over USB/TCP channel).
- **iOS reach is narrower than Android**: SELinux / memfd / libc-hook / DEX vectors are Linux-specific and don't apply. iOS gets cross-platform vectors plus `install_name_tool`, Mach-O symbol sweep, ad-hoc codesign. Active dyld image hiding is not yet implemented.
- **iOS ad-hoc signature is jailbreak-only**: Apps repackaged for non-jailbroken devices need to re-sign with an Apple Developer cert (overwrites the ad-hoc signature, which is fine).

## Credits

- [Frida](https://frida.re/) by Ole Andre Ravnas
- [ajeossida](https://github.com/hackcatml/ajeossida) by hackcatml — original stealth Frida concept
- Detection vector research from the Android security community

## License

MIT

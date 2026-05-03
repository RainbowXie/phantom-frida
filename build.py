#!/usr/bin/env python3
"""
Custom Frida Builder — build anti-detection Frida server from source.

Extended beyond ajeossida with additional stealth techniques.
Verified against Frida 17.7.2 source code.

Usage (Android, run in Ubuntu/WSL):
    python3 build.py --version 17.7.2
    python3 build.py --version 17.7.2 --name stealth --port 27142
    python3 build.py --version 17.7.2 --arch android-arm64,android-arm --extended
    python3 build.py --version 17.7.2 --skip-build  # only patch, don't compile

Usage (iOS, run on macOS with Xcode CLT):
    python3 build.py --version 17.7.2 --arch ios-arm64 --extended
    python3 build.py --version 17.7.2 --arch ios-arm64,ios-arm64e --extended

Requirements:
    Android build:
        - Ubuntu 22.04+ (WSL works) or other Linux
        - Android NDK r29 (auto-downloaded if missing)
    iOS build:
        - macOS 14+ with Xcode 15+ Command Line Tools
        - Xcode SDK iphoneos available (xcrun --sdk iphoneos --show-sdk-path)
    Both:
        - Python 3.10+
        - Git, ~20 GB free disk space
        - Internet connection (clones Frida)
"""

import argparse
import gzip
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

from patches import (
    get_source_patches,
    get_targeted_patches,
    get_binary_patches,
    get_binary_string_patches,
    get_rollback_patches,
    get_port_patches,
    get_transport_patches,
    get_internal_patches,
    get_temp_path_patches,
    get_stability_patches_17,
    MEMFD_PATCHES,
    LIBC_HOOK_PATCHES,
    SELINUX_PATCHES,
    DETECTION_VECTORS,
)

# --- Constants ---

NDK_VERSION = "r29"
NDK_URL = f"https://dl.google.com/android/repository/android-ndk-{NDK_VERSION}-linux.zip"
ANDROID_ARCHS = ["android-arm64", "android-arm", "android-x86_64", "android-x86"]
IOS_ARCHS = ["ios-arm64", "ios-arm64e"]
ALL_ARCHS = ANDROID_ARCHS + IOS_ARCHS


def is_ios_arch(arch: str) -> bool:
    return arch.startswith("ios-")


def is_android_arch(arch: str) -> bool:
    return arch.startswith("android-")


def log(msg: str, level: str = "INFO"):
    colors = {
        "INFO": "\033[36m",
        "OK": "\033[32m",
        "WARN": "\033[33m",
        "ERROR": "\033[31m",
        "STEP": "\033[35m",
        "HEADER": "\033[1;37m",
    }
    reset = "\033[0m"
    color = colors.get(level, "")
    print(f"{color}[{level}]{reset} {msg}", flush=True)


def run(cmd: str, cwd: str | None = None, env: dict | None = None,
        check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command with inherited env + overrides."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    log(f"$ {cmd}", "INFO")
    result = subprocess.run(
        cmd, shell=True, cwd=cwd, env=full_env,
        capture_output=False, text=True,
    )
    if check and result.returncode != 0:
        log(f"Command failed with exit code {result.returncode}", "ERROR")
        sys.exit(1)
    return result


def detect_frida_major(version: str) -> int:
    return int(version.split(".")[0])


# ============================================================================
# File operations
# ============================================================================

def replace_in_file(filepath: Path, old: str, new: str) -> int:
    """Replace string in a single file. Returns number of replacements."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, IsADirectoryError, OSError):
        return 0
    if old not in content:
        return 0
    count = content.count(old)
    content = content.replace(old, new)
    filepath.write_text(content, encoding="utf-8")
    return count


def replace_in_tree(root: Path, old: str, new: str,
                    include_build: bool = False) -> int:
    """Recursively replace string in all text files under root."""
    total = 0
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv"}
    if not include_build:
        skip_dirs.add("build")

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.is_symlink():
                continue
            # Skip binary files by extension. .dat covers meson pickles
            # (build.dat, coredata.dat, install.dat) — when replacing a string
            # with a different-length one, text-mode rewrite corrupts the
            # length-prefixed pickle structure. iOS post-build hits this on
            # frida_agent_main -> {name}_agent_main (length delta varies).
            # .pkl/.pickle defensive coverage; .ninja_deps/.ninja_log binary too.
            if fpath.suffix in {".o", ".a", ".so", ".gz", ".zip", ".png", ".jpg", ".pyc",
                                ".dex", ".jar", ".class", ".elf", ".wasm", ".dylib", ".dll",
                                ".dat", ".pkl", ".pickle"}:
                continue
            if fname in {".ninja_deps", ".ninja_log"}:
                continue
            total += replace_in_file(fpath, old, new)

    return total


# ============================================================================
# NDK
# ============================================================================

def ensure_ndk(work_dir: Path) -> Path:
    """Download and extract Android NDK if needed."""
    ndk_dir = work_dir / f"android-ndk-{NDK_VERSION}"
    if ndk_dir.exists():
        log(f"NDK already at {ndk_dir}", "OK")
        return ndk_dir

    ndk_zip = work_dir / f"android-ndk-{NDK_VERSION}-linux.zip"
    if not ndk_zip.exists():
        log(f"Downloading NDK {NDK_VERSION} (~1.5 GB)...", "STEP")
        run(f"curl -L -o {ndk_zip} {NDK_URL}", cwd=str(work_dir))

    log("Extracting NDK...", "STEP")
    run(f"unzip -q {ndk_zip}", cwd=str(work_dir))

    if ndk_dir.exists():
        log(f"NDK ready at {ndk_dir}", "OK")
        ndk_zip.unlink(missing_ok=True)
        return ndk_dir
    else:
        log("NDK extraction failed", "ERROR")
        sys.exit(1)


# ============================================================================
# Clone
# ============================================================================

def clone_frida(version: str, work_dir: Path) -> Path:
    """Clone Frida source at the specified version tag."""
    frida_dir = work_dir / "frida"
    if frida_dir.exists():
        log(f"Frida source already at {frida_dir}", "OK")
        return frida_dir

    log(f"Cloning Frida {version} (with submodules)...", "STEP")
    run(
        f"git clone --recurse-submodules --branch {version} --depth 1 "
        f"https://github.com/frida/frida.git {frida_dir}",
        cwd=str(work_dir),
    )
    log(f"Frida {version} cloned", "OK")
    return frida_dir


# ============================================================================
# PHASE 1: Source-level patches (before build)
# ============================================================================

def rename_frida_files(frida_dir: Path, custom_name: str):
    """
    Rename files on disk whose names contain 'frida-helper' or 'frida-agent' etc.
    After global source patches rename references in meson.build/Vala/C files,
    the actual files on disk must also be renamed to match.

    IMPORTANT: Skip build system files (.symbols, .version, .def, .plist, .xcent)
    because rollback patches revert their references to original names.
    Also skip releng/frida_version.py (not renamed by our patches).
    """
    rename_patterns = [
        ("frida-helper", f"{custom_name}-helper"),
        ("frida-agent", f"{custom_name}-agent"),
        ("frida-gadget", f"{custom_name}-gadget"),
        ("frida-server", f"{custom_name}-server"),
    ]

    # Build system file extensions that rollback patches keep with original names
    skip_extensions = {".symbols", ".version", ".def", ".plist", ".xcent"}
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "build"}
    # Specific files to never rename
    skip_names = {"frida_version.py", "frida-version.py"}
    renamed_count = 0

    for dirpath, dirnames, filenames in os.walk(frida_dir, topdown=False):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if fname in skip_names:
                continue
            # Skip build system files (rollback patches keep their original names)
            if Path(fname).suffix in skip_extensions:
                continue
            new_fname = fname
            for old_pat, new_pat in rename_patterns:
                if old_pat in new_fname:
                    new_fname = new_fname.replace(old_pat, new_pat)
            if new_fname != fname:
                old_path = Path(dirpath) / fname
                new_path = Path(dirpath) / new_fname
                if old_path.exists() and not new_path.exists():
                    old_path.rename(new_path)
                    renamed_count += 1

    if renamed_count:
        log(f"  Renamed {renamed_count} files on disk", "OK")


def rebuild_helper_dex(frida_dir: Path, custom_name: str):
    """Rebuild the Android helper DEX with renamed Java package.

    The pre-compiled helper.dex in the repo contains 're.frida.Helper'.
    We need to recompile it with the new package name so that:
    1. The DEX string table doesn't contain 'frida' (binary sweep safe)
    2. The class name matches what the renamed Vala code expects
    """
    helper_dir = frida_dir / "subprojects" / "frida-core" / "src" / "android-helper"
    old_pkg_dir = helper_dir / "re" / "frida"
    new_pkg_dir = helper_dir / "re" / custom_name
    java_file = old_pkg_dir / "Helper.java"

    if not java_file.exists():
        # Package might already be renamed (e.g., from cache)
        java_file = new_pkg_dir / "Helper.java"
        if not java_file.exists():
            log("  Helper.java not found, skipping DEX rebuild", "WARN")
            return

    # Rename directory: re/frida/ -> re/{name}/
    if old_pkg_dir.exists() and not new_pkg_dir.exists():
        old_pkg_dir.rename(new_pkg_dir)
        log(f"  Renamed {old_pkg_dir.name}/ -> {new_pkg_dir.name}/", "OK")

    java_file = new_pkg_dir / "Helper.java"
    if not java_file.exists():
        log("  Helper.java not found after rename", "WARN")
        return

    # The Java source was already patched by replace_in_tree:
    #   "package re.frida;" -> "package re.{name};"
    #   "re.frida.Helper" -> "re.{name}.Helper"
    # Verify:
    content = java_file.read_text(encoding="utf-8")
    if f"package re.{custom_name};" not in content:
        log("  Helper.java package not patched, fixing...", "WARN")
        content = content.replace("package re.frida;", f"package re.{custom_name};")
        java_file.write_text(content, encoding="utf-8")

    # Try to recompile the DEX
    dex_file = helper_dir / "helper.dex"
    build_dir = helper_dir / "build"
    build_dir.mkdir(exist_ok=True)
    java_build = build_dir / "java"
    java_build.mkdir(exist_ok=True)

    # Check if javac is available
    javac_check = subprocess.run(["javac", "-version"], capture_output=True, text=True)
    if javac_check.returncode != 0:
        log("  javac not available, keeping pre-compiled DEX (may contain 'frida' strings)", "WARN")
        return

    # We need android.jar for compilation. Check common locations.
    android_jar = None
    possible_jars = [
        # GitHub Actions / CI
        Path("/usr/local/lib/android/sdk/platforms/android-34/android.jar"),
        Path("/usr/local/lib/android/sdk/platforms/android-33/android.jar"),
        # Try any available platform
    ]
    # Also search in ANDROID_SDK_ROOT if set
    sdk_root = os.environ.get("ANDROID_SDK_ROOT", os.environ.get("ANDROID_HOME", ""))
    if sdk_root:
        platforms_dir = Path(sdk_root) / "platforms"
        if platforms_dir.exists():
            for p in sorted(platforms_dir.iterdir(), reverse=True):
                jar = p / "android.jar"
                if jar.exists():
                    possible_jars.insert(0, jar)

    for jar in possible_jars:
        if jar.exists():
            android_jar = jar
            break

    if android_jar is None:
        # Search more broadly
        result = subprocess.run(
            "find /usr/local/lib/android -name 'android.jar' 2>/dev/null | head -1",
            shell=True, capture_output=True, text=True
        )
        if result.stdout.strip():
            android_jar = Path(result.stdout.strip())

    if android_jar is None:
        log("  android.jar not found, keeping pre-compiled DEX", "WARN")
        return

    log(f"  Recompiling helper DEX (android.jar: {android_jar.name})...", "STEP")

    # Step 1: javac -> .class files
    javac_cmd = (
        f"javac -cp .:{android_jar} -bootclasspath {android_jar} "
        f"-source 1.8 -target 1.8 "
        f"-Xlint:-options "  # suppress bootclasspath warning
        f"{java_file} -d {java_build}"
    )
    result = subprocess.run(javac_cmd, shell=True, cwd=str(helper_dir),
                            capture_output=True, text=True)
    if result.returncode != 0:
        log(f"  javac failed: {result.stderr[:200]}", "WARN")
        log("  Keeping pre-compiled DEX", "WARN")
        return

    # Collect ALL .class files (including inner classes like Helper$1.class)
    class_dir = java_build / "re" / custom_name
    class_files = list(class_dir.glob("*.class"))
    if not class_files:
        log("  No .class files generated", "WARN")
        return
    log(f"  Compiled {len(class_files)} class files (including inner classes)", "OK")

    # Step 2: Package into JAR first (avoids d8 "defined multiple times" error)
    jar_file = build_dir / f"{custom_name}-helper.jar"
    jar_cmd = f"jar cfe {jar_file} re.{custom_name}.Helper -C {java_build} ."
    result = subprocess.run(jar_cmd, shell=True, cwd=str(helper_dir),
                            capture_output=True, text=True)
    if result.returncode != 0:
        log(f"  jar failed: {result.stderr[:200]}", "WARN")
        return

    # Step 3: Convert JAR to DEX using d8
    d8_path = None
    d8_check = subprocess.run(["which", "d8"], capture_output=True, text=True)
    if d8_check.returncode == 0:
        d8_path = "d8"
    else:
        # Try d8 from Android SDK build-tools
        if sdk_root:
            bt_dir = Path(sdk_root) / "build-tools"
            if bt_dir.exists():
                for bt in sorted(bt_dir.iterdir(), reverse=True):
                    candidate = bt / "d8"
                    if candidate.exists():
                        d8_path = str(candidate)
                        break
        if d8_path is None:
            find_result = subprocess.run(
                "find /usr/local/lib/android -name 'd8' -type f 2>/dev/null | head -1",
                shell=True, capture_output=True, text=True
            )
            if find_result.stdout.strip():
                d8_path = find_result.stdout.strip()

    if d8_path is None:
        log("  d8 not found, keeping pre-compiled DEX", "WARN")
        return
    dex_cmd = f"{d8_path} --lib {android_jar} --output {build_dir} {jar_file}"

    result = subprocess.run(dex_cmd, shell=True, cwd=str(helper_dir),
                            capture_output=True, text=True)
    if result.returncode != 0:
        log(f"  d8 failed: {result.stderr[:200]}", "WARN")
        log("  Keeping pre-compiled DEX", "WARN")
        return

    # Step 3: Replace helper.dex with new one
    new_dex = build_dir / "classes.dex"
    if new_dex.exists():
        shutil.copy2(new_dex, dex_file)
        log(f"  Helper DEX rebuilt: {dex_file.stat().st_size} bytes (package: re.{custom_name})", "OK")
    else:
        log("  classes.dex not generated, keeping pre-compiled DEX", "WARN")


def apply_source_patches(frida_dir: Path, custom_name: str, has_android: bool = True):
    """Apply global recursive string replacements across the source tree."""
    log("=" * 60, "HEADER")
    log("PHASE 1: Global source patches", "STEP")
    log("=" * 60, "HEADER")

    cap_name = custom_name[0].upper() + custom_name[1:]

    patches = get_source_patches(custom_name, cap_name)
    for old, new in patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  {old} -> {new} ({count})", "OK")
        else:
            log(f"  {old} -> (not found)", "WARN")

    # Rollback accidental renames of build system files
    log("Rolling back build file renames...", "STEP")
    rollbacks = get_rollback_patches(custom_name)
    for old, new in rollbacks:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  [rollback] {old} ({count})", "INFO")

    # Rename actual files on disk to match source references
    rename_frida_files(frida_dir, custom_name)

    # Rebuild helper DEX with renamed Java package (Android-only)
    if has_android:
        rebuild_helper_dex(frida_dir, custom_name)
    else:
        log("  Skipping DEX rebuild (no Android arch in build)", "INFO")

    log("Global source patches complete", "OK")


def apply_targeted_patches(frida_dir: Path, custom_name: str, frida_major: int,
                            has_android: bool = True):
    """Apply patches to specific files (memfd, libc hooks, SELinux, build system).

    The memfd / libc-hook / SELinux blocks are Linux/Android-specific and skipped
    when only iOS targets are being built.
    """
    log("=" * 60, "HEADER")
    log("PHASE 2: Targeted file patches", "STEP")
    log("=" * 60, "HEADER")

    cap_name = custom_name[0].upper() + custom_name[1:]
    core_dir = frida_dir / "subprojects" / "frida-core"
    gum_dir = frida_dir / "subprojects" / "frida-gum"

    if has_android:
        # --- memfd_create: hide agent name in /proc/pid/fd ---
        memfd_cfg = MEMFD_PATCHES.get(frida_major, MEMFD_PATCHES[17])
        memfd_file = core_dir / memfd_cfg["file"]
        if memfd_file.exists():
            count = replace_in_file(memfd_file, memfd_cfg["old"], memfd_cfg["new"])
            if count:
                log(f"  memfd_create -> 'jit-cache' in {memfd_cfg['file']}", "OK")
            else:
                log(f"  memfd_create: pattern not found in {memfd_cfg['file']}", "WARN")
        else:
            log(f"  memfd file missing: {memfd_cfg['file']}", "WARN")

        # --- Disable exit monitor (prevents detection via hooked exit/_exit/abort) ---
        exit_monitor = core_dir / "lib" / "payload" / "exit-monitor.vala"
        if exit_monitor.exists():
            for old, new in LIBC_HOOK_PATCHES["exit_monitor"]:
                count = replace_in_file(exit_monitor, old, new)
                if count:
                    log(f"  exit-monitor: disabled interceptor.attach ({count})", "OK")

        # --- Disable signal/sigaction hooking ---
        exceptor = gum_dir / "gum" / "backend-posix" / "gumexceptor-posix.c"
        if exceptor.exists():
            for old, new in LIBC_HOOK_PATCHES["exceptor"]:
                count = replace_in_file(exceptor, old, new)
                if count:
                    log(f"  gumexceptor: disabled hook ({count})", "OK")

        # --- SELinux labels (in linjector.vala for 17.x) ---
        for old, new in SELINUX_PATCHES(custom_name):
            count = replace_in_tree(frida_dir, old, new)
            if count:
                log(f"  SELinux: {old} -> {new} ({count})", "OK")
    else:
        log("  Skipping memfd/libc/SELinux patches (no Android arch in build)", "INFO")

    # --- Build system files ---
    targets = {
        "server_meson": core_dir / "server" / "meson.build",
        "compat_build": core_dir / "compat" / "build.py",
        "core_meson": core_dir / "meson.build",
        "gadget_meson": core_dir / "lib" / "gadget" / "meson.build",
        "agent_meson": core_dir / "lib" / "agent" / "meson.build",
    }

    for target_name, target_file in targets.items():
        if target_file.exists():
            patches = get_targeted_patches(custom_name, cap_name, target_name)
            applied = 0
            for old, new in patches:
                applied += replace_in_file(target_file, old, new)
            if applied:
                log(f"  {target_name}: {applied} patches", "OK")
        else:
            log(f"  {target_name}: file not found", "WARN")

    log("Targeted patches complete", "OK")


def apply_extended_patches(frida_dir: Path, custom_name: str, port: int | None):
    """Apply extended anti-detection patches beyond ajeossida."""
    log("=" * 60, "HEADER")
    log("PHASE 2.5: Extended anti-detection patches", "STEP")
    log("=" * 60, "HEADER")

    cap_name = custom_name[0].upper() + custom_name[1:]

    # --- Port change ---
    if port and port != 27042:
        port_patches = get_port_patches(port)
        for patch in port_patches:
            for fpath in patch["files"]:
                full_path = frida_dir / fpath
                if full_path.exists():
                    count = replace_in_file(full_path, patch["pattern"], patch["replacement"])
                    if count:
                        log(f"  Port: {patch['description']} in {Path(fpath).name} ({count})", "OK")
        # Also do a global sweep for the port number in less obvious places
        count = replace_in_tree(frida_dir / "subprojects" / "frida-core", "27042", str(port))
        if count:
            log(f"  Port: global sweep found {count} more occurrences", "OK")

    # --- D-Bus interface names ---
    # NOTE: Transport/D-Bus interface renames (re.frida.HostSession etc.) are DISABLED.
    # These interface names are part of the Frida client-server protocol.
    # Renaming them on the server breaks communication with the standard frida client.
    # They are NOT visible to other apps (only over USB/TCP channel), so not a detection vector.
    # The D-Bus service name (re.frida.server) IS renamed by global source patches — that's safe.

    # --- Internal identifiers (C symbols, GType names) ---
    internal_patches = get_internal_patches(custom_name, cap_name)
    for old, new in internal_patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  Internal: {old} -> {new} ({count})", "OK")

    # --- Temp file paths ---
    temp_patches = get_temp_path_patches(custom_name)
    for old, new in temp_patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  Temp paths: {old} -> {new} ({count})", "OK")

    log("Extended patches complete", "OK")


def apply_stability_fixes(frida_dir: Path, frida_major: int):
    """Apply optional stability/crash fixes."""
    log("Applying stability fixes...", "STEP")

    core_dir = frida_dir / "subprojects" / "frida-core"

    if frida_major >= 17:
        patches = get_stability_patches_17(frida_dir)
        for patch in patches:
            fpath = frida_dir / patch["file"]
            if fpath.exists():
                count = replace_in_file(fpath, patch["old"], patch["new"])
                if count:
                    log(f"  {patch['description']}", "OK")
                else:
                    log(f"  Pattern not found: {patch['description']}", "WARN")

    # DirListCloaker interceptor detach — safe to disable to prevent crash
    cloak = core_dir / "lib" / "payload" / "cloak.vala"
    if cloak.exists():
        # 17.x: DirListCloaker uses Gum.Interceptor.detach in destructor
        old = "Gum.Interceptor.obtain ().detach (listener);"
        new = "// Gum.Interceptor.obtain ().detach (listener);"
        count = replace_in_file(cloak, old, new)
        if count:
            log(f"  cloak.vala: disabled interceptor detach ({count})", "OK")

    log("Stability fixes complete", "OK")


# ============================================================================
# PHASE 3: Post-build patches (after first compilation)
# ============================================================================

def apply_post_build_patches(frida_dir: Path, custom_name: str):
    """Patch frida_agent_main symbol (generated during first build).

    Must include build/ directory because:
    - agent-glue.c (source) CALLS frida_agent_main
    - meson-generated_agent.c (build output) DEFINES frida_agent_main
    Both must be renamed together, otherwise linker error.
    """
    log("PHASE 3: Post-build patches (frida_agent_main)...", "STEP")
    count = replace_in_tree(frida_dir, "frida_agent_main", f"{custom_name}_agent_main",
                            include_build=True)
    log(f"  frida_agent_main -> {custom_name}_agent_main ({count})", "OK")


# ============================================================================
# PHASE 4: Binary-level patches (after second compilation)
# ============================================================================

def find_dex_regions(data: bytes) -> list[tuple[int, int]]:
    """Find embedded DEX sections in binary data by scanning for DEX magic.
    Returns list of (start, end) byte ranges to protect from modification."""
    regions = []
    dex_magics = [b'dex\n035\x00', b'dex\n037\x00', b'dex\n038\x00', b'dex\n039\x00']
    for magic in dex_magics:
        idx = 0
        while True:
            pos = data.find(magic, idx)
            if pos == -1:
                break
            # Read header_size and file_size from DEX header
            if pos + 0x28 < len(data):
                file_size = struct.unpack_from('<I', data, pos + 0x20)[0]
                header_size = struct.unpack_from('<I', data, pos + 0x24)[0]
                # Valid DEX: header_size=112 (0x70), file_size > header_size
                if header_size == 112 and file_size > 112 and file_size < 10_000_000:
                    regions.append((pos, pos + file_size))
                    log(f"    [dex] Protected DEX region: 0x{pos:08x}-0x{pos+file_size:08x} ({file_size} bytes)", "INFO")
            idx = pos + 8
    return regions


def replace_bytes_outside_regions(data: bytes, old: bytes, new: bytes,
                                   skip_regions: list[tuple[int, int]]) -> tuple[bytes, int]:
    """Replace byte pattern in data, skipping protected regions.
    Returns (modified_data, replacement_count)."""
    assert len(old) == len(new), "Replacement must be same length"
    result = bytearray(data)
    count = 0
    idx = 0
    while True:
        pos = data.find(old, idx)
        if pos == -1:
            break
        # Check if this position falls inside any protected region
        in_protected = any(start <= pos < end for start, end in skip_regions)
        if not in_protected:
            result[pos:pos + len(new)] = new
            count += 1
        idx = pos + 1
    return bytes(result), count


def apply_binary_patches(binary_path: Path, custom_name: str, extended: bool = False):
    """Apply hex-level patches to compiled binaries.
    DEX-aware: protects embedded DEX sections from string sweep corruption."""
    data = binary_path.read_bytes()
    original_size = len(data)
    patched = False

    # Find embedded DEX regions to protect
    dex_regions = find_dex_regions(data) if extended else []

    # Standard thread name patches (safe — these patterns don't appear in DEX)
    for old_hex, new_hex, description in get_binary_patches():
        old_bytes = bytes.fromhex(old_hex)
        new_bytes = bytes.fromhex(new_hex)
        if old_bytes in data:
            data = data.replace(old_bytes, new_bytes)
            log(f"    {description}", "OK")
            patched = True

    # Extended: sweep for residual "frida" strings in binary
    # MUST skip DEX regions to avoid corrupting embedded helper DEX
    if extended:
        for old_hex, new_hex, description in get_binary_string_patches(custom_name):
            old_bytes = bytes.fromhex(old_hex)
            new_bytes = bytes.fromhex(new_hex)
            if old_bytes in data:
                if dex_regions:
                    data, count = replace_bytes_outside_regions(data, old_bytes, new_bytes, dex_regions)
                else:
                    count = data.count(old_bytes)
                    data = data.replace(old_bytes, new_bytes)
                if count:
                    log(f"    [ext] {description} ({count}x, skipped DEX regions)", "OK")
                    patched = True

    if patched:
        assert len(data) == original_size, "Binary size changed — patches are not same-length!"
        binary_path.write_bytes(data)


# ============================================================================
# Build
# ============================================================================

def configure_arch(frida_dir: Path, arch: str, ndk_path: Path | None):
    log(f"Configuring for {arch}...", "STEP")
    env: dict[str, str] = {}
    if is_android_arch(arch):
        if ndk_path is None:
            log(f"NDK required for {arch} but ndk_path is None", "ERROR")
            sys.exit(1)
        env["ANDROID_NDK_ROOT"] = str(ndk_path)
    # iOS: rely on Xcode CLT picked up automatically by Frida's meson cross-files.
    run(
        f"./configure --host={arch}",
        cwd=str(frida_dir),
        env=env,
    )


def build_frida(frida_dir: Path, arch: str, ndk_path: Path | None):
    cpus = os.cpu_count() or 4
    log(f"Building {arch} ({cpus} threads)...", "STEP")
    env: dict[str, str] = {}
    if is_android_arch(arch) and ndk_path is not None:
        env["ANDROID_NDK_ROOT"] = str(ndk_path)
    run(
        f"make -j{cpus}",
        cwd=str(frida_dir),
        env=env,
    )


# ============================================================================
# Collect artifacts
# ============================================================================

def fix_macho_install_name(dylib: Path, custom_name: str):
    """Rewrite LC_ID_DYLIB so dyld image enumeration sees @rpath/lib{name}-gadget.dylib
    instead of any 'frida' / 'Frida' substring. install_name_tool invalidates
    the existing signature, so caller must re-codesign afterwards.
    """
    new_id = f"@rpath/lib{custom_name}-gadget.dylib"
    log(f"    install_name_tool -id {new_id}", "STEP")
    run(f"install_name_tool -id {new_id} {dylib}", check=False)


def sweep_macho_symbols(binary: Path, custom_name: str):
    """Byte-replace residual _frida_* / _FRIDA_* / _Frida* symbols in the Mach-O
    string table. Length-preserving — skips any symbol where the rename would
    change the byte length. Must run AFTER apply_binary_patches (thread names)
    and BEFORE codesign (which seals the final bytes).
    """
    result = subprocess.run(
        f"nm -gU {binary} 2>/dev/null | awk '{{print $NF}}' "
        f"| grep -E '^_(frida|FRIDA|Frida)' | sort -u",
        shell=True, capture_output=True, text=True
    )
    syms = [s.strip() for s in result.stdout.splitlines() if s.strip()]
    if not syms:
        log("    Mach-O symbol sweep: no residual frida/Frida/FRIDA symbols", "OK")
        return

    cap = custom_name[0].upper() + custom_name[1:]
    data = binary.read_bytes()
    original_size = len(data)
    replaced = 0
    skipped: list[str] = []

    for sym in syms:
        bare = sym[1:] if sym.startswith("_") else sym
        if bare.startswith("frida"):
            new_bare = custom_name + bare[5:]
        elif bare.startswith("FRIDA"):
            new_bare = custom_name.upper() + bare[5:]
        elif bare.startswith("Frida"):
            new_bare = cap + bare[5:]
        else:
            continue
        if len(new_bare) != len(bare):
            skipped.append(f"{bare}->{new_bare}")
            continue
        old_b = bare.encode()
        new_b = new_bare.encode()
        if old_b in data:
            count = data.count(old_b)
            data = data.replace(old_b, new_b)
            replaced += count

    if skipped:
        log(f"    Mach-O symbol sweep: skipped {len(skipped)} length-mismatch (e.g. {skipped[0]})", "WARN")
    if replaced:
        assert len(data) == original_size, "symbol sweep changed binary size"
        binary.write_bytes(data)
        log(f"    Mach-O symbol sweep: {replaced} byte replacements across {len(syms)} symbol names", "OK")


def merge_ios_universal(output_dir: Path, ios_archs: list[str],
                         custom_name: str, version: str):
    """Combine per-arch iOS slices into a single fat binary via `lipo -create`.
    Re-codesigns ad-hoc afterwards (lipo invalidates the existing signature).
    Skipped when only one iOS arch was built — there's nothing to merge.
    """
    arch_shorts = [a.replace("ios-", "") for a in ios_archs]

    targets = [
        ("server", f"{custom_name}-server-{version}-ios-{{arch}}",
         f"{custom_name}-server-{version}-ios-universal",
         f"{custom_name}-server"),
        ("gadget", f"{custom_name}-gadget-{version}-ios-{{arch}}.dylib",
         f"{custom_name}-gadget-{version}-ios-universal.dylib",
         f"lib{custom_name}-gadget"),
    ]

    for label, per_arch_pat, out_name, codesign_id in targets:
        slices = [output_dir / per_arch_pat.format(arch=s) for s in arch_shorts]
        missing = [str(p) for p in slices if not p.is_file()]
        if missing:
            log(f"  {label}: skipping universal — missing {missing}", "WARN")
            continue

        out_path = output_dir / out_name
        slice_args = " ".join(str(p) for p in slices)
        log(f"  lipo -create {slice_args} -output {out_path.name}", "STEP")
        run(f"lipo -create {slice_args} -output {out_path}", check=True)
        os.chmod(out_path, 0o755)

        # lipo invalidates ad-hoc signatures of the input slices when fusing.
        codesign_adhoc(out_path, identifier=codesign_id)

        # Compressed sibling (matches per-arch convention)
        out_gz = output_dir / f"{out_name}.gz"
        with open(out_path, "rb") as f_in, gzip.open(out_gz, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        log(f"    -> {out_path.name} ({out_path.stat().st_size / 1024 / 1024:.1f} MB) "
            f"+ {out_gz.name} ({out_gz.stat().st_size / 1024 / 1024:.1f} MB)", "OK")


def codesign_adhoc(path: Path, identifier: str | None = None):
    """Re-apply ad-hoc signature. Must be the last step in the iOS post-process
    chain — install_name_tool / byte patches / symbol sweep all invalidate it.

    Pass `identifier` to override the codesign identifier — without this,
    codesign reuses the existing one (which Frida's modulator sets to
    `libfrida-gadget-modulated-<hash>`, leaking the original name).
    """
    cmd = "codesign --force --sign -"
    if identifier:
        cmd += f" --identifier {identifier}"
    cmd += f" {path}"
    log(f"    {cmd.split(' ', 1)[1]} {path.name}", "STEP")
    run(cmd, check=False)


def collect_artifacts(frida_dir: Path, arch: str, custom_name: str,
                      version: str, output_dir: Path, extended: bool):
    """Find, binary-patch, and package build artifacts."""
    log(f"Collecting artifacts for {arch}...", "STEP")

    if is_ios_arch(arch):
        os_tag = "ios"
        arch_short = arch.replace("ios-", "")
        lib_ext = "dylib"
    else:
        os_tag = "android"
        arch_short = arch.replace("android-", "")
        lib_ext = "so"

    def find_artifact(subdir: str, patterns: list[str]) -> Path | None:
        base = frida_dir / "build" / "subprojects" / "frida-core" / subdir
        for pattern in patterns:
            candidate = base / pattern
            if candidate.exists():
                return candidate
        # List directory for debugging
        if base.exists():
            log(f"    Looking in {base}:", "INFO")
            for f in sorted(base.iterdir()):
                if f.is_file() and f.stat().st_size > 1000:
                    log(f"      {f.name} ({f.stat().st_size:,} bytes)", "INFO")
        return None

    def save_artifact(src: Path, out_name: str):
        # Save compressed
        out_gz = output_dir / f"{out_name}.gz"
        with open(src, "rb") as f_in:
            with gzip.open(out_gz, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        log(f"    -> {out_gz.name} ({out_gz.stat().st_size / 1024 / 1024:.1f} MB)", "OK")

        # Save uncompressed
        out_bin = output_dir / out_name
        shutil.copy2(src, out_bin)
        os.chmod(out_bin, 0o755)

    def post_process(binary: Path, *, is_dylib: bool, codesign_identifier: str | None = None):
        """iOS: install_name_tool -> byte patches -> symbol sweep -> codesign.
        Android: byte patches only. Order matters — codesign must be last.
        """
        if is_ios_arch(arch):
            if is_dylib:
                fix_macho_install_name(binary, custom_name)
            apply_binary_patches(binary, custom_name, extended)
            sweep_macho_symbols(binary, custom_name)
            codesign_adhoc(binary, identifier=codesign_identifier)
        else:
            apply_binary_patches(binary, custom_name, extended)

    # --- Server ---
    server = find_artifact("server", [
        f"{custom_name}-server",
        f"{custom_name}-server-raw",
        "frida-server",
        "frida-server-raw",
    ])
    if server:
        log(f"  Server: {server.name}", "OK")
        post_process(server, is_dylib=False,
                     codesign_identifier=f"{custom_name}-server")
        save_artifact(server, f"{custom_name}-server-{version}-{os_tag}-{arch_short}")
    else:
        log("  Server: NOT FOUND", "ERROR")

    # --- Agent ---
    agent = find_artifact("lib/agent", [
        f"lib{custom_name}-agent.{lib_ext}",
        f"lib{custom_name}-agent-modulated.{lib_ext}",
        f"lib{custom_name}-agent-raw.{lib_ext}",
        f"libfrida-agent.{lib_ext}",
        f"libfrida-agent-modulated.{lib_ext}",
    ])
    if agent:
        log(f"  Agent: {agent.name}", "OK")
        post_process(agent, is_dylib=(lib_ext == "dylib"),
                     codesign_identifier=f"lib{custom_name}-agent")

    # --- Gadget ---
    gadget = find_artifact("lib/gadget", [
        f"lib{custom_name}-gadget.{lib_ext}",
        f"lib{custom_name}-gadget-modulated.{lib_ext}",
        f"libfrida-gadget.{lib_ext}",
        f"libfrida-gadget-modulated.{lib_ext}",
    ])
    if gadget:
        log(f"  Gadget: {gadget.name}", "OK")
        post_process(gadget, is_dylib=(lib_ext == "dylib"),
                     codesign_identifier=f"lib{custom_name}-gadget")
        save_artifact(gadget, f"{custom_name}-gadget-{version}-{os_tag}-{arch_short}.{lib_ext}")


# ============================================================================
# Verification
# ============================================================================

def verify_binary(binary_path: Path):
    """Check compiled binary for residual 'frida' strings."""
    if not binary_path.exists():
        return

    data = binary_path.read_bytes()
    # Search for null-terminated "frida" (case-sensitive)
    frida_bytes = b"frida\x00"
    count = data.count(frida_bytes)
    if count:
        log(f"  WARNING: {binary_path.name} still contains 'frida\\0' x{count}", "WARN")

        # Show context around each occurrence
        idx = 0
        shown = 0
        while shown < 5:
            pos = data.find(frida_bytes, idx)
            if pos == -1:
                break
            # Extract surrounding context
            start = max(0, pos - 20)
            end = min(len(data), pos + 30)
            context = data[start:end]
            # Show printable chars only
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in context)
            log(f"    @ 0x{pos:08x}: ...{printable}...", "WARN")
            idx = pos + 1
            shown += 1
    else:
        log(f"  {binary_path.name}: clean (no 'frida' strings)", "OK")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Build custom anti-detection Frida server from source",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 build.py --version 17.7.2
  python3 build.py --version 17.7.2 --name stealth --port 27142
  python3 build.py --version 17.7.2 --arch android-arm64,android-arm --extended
  python3 build.py --version 17.7.2 --arch ios-arm64,ios-arm64e --extended  (macOS only)
  python3 build.py --version 17.7.2 --skip-build  # patch only, no compilation
  python3 build.py --version 17.7.2 --temp-fixes   # add stability patches

Detection vectors covered:
""" + DETECTION_VECTORS,
    )

    parser.add_argument("--version", "-v", required=True,
                        help="Frida version to build (e.g. 17.7.2)")
    parser.add_argument("--arch", "-a", default="android-arm64",
                        help=f"Comma-separated architectures. Options: {', '.join(ALL_ARCHS)}")
    parser.add_argument("--name", "-n", default="ajeossida",
                        help="Custom name replacing 'frida' everywhere (default: ajeossida)")
    parser.add_argument("--port", "-p", type=int, default=None,
                        help="Custom listening port (default: 27042 unchanged)")
    parser.add_argument("--extended", "-e", action="store_true",
                        help="Apply extended anti-detection (D-Bus interfaces, symbols, paths, binary sweep)")
    parser.add_argument("--temp-fixes", action="store_true",
                        help="Apply stability fixes (perfetto skip, cloak detach)")
    parser.add_argument("--work-dir", "-w", default=None,
                        help="Working directory (default: ./build)")
    parser.add_argument("--output-dir", "-o", default=None,
                        help="Output directory (default: ./output)")
    parser.add_argument("--ndk-path", default=None,
                        help="Path to existing Android NDK r29 (skip download)")
    parser.add_argument("--skip-clone", action="store_true",
                        help="Use existing source in work-dir")
    parser.add_argument("--skip-build", action="store_true",
                        help="Only apply patches, don't compile")
    parser.add_argument("--verify", action="store_true",
                        help="After build, scan binaries for residual 'frida' strings")

    args = parser.parse_args()

    # Validate
    version = args.version
    frida_major = detect_frida_major(version)
    custom_name = args.name.lower()
    archs = [a.strip() for a in args.arch.split(",")]

    for arch in archs:
        if arch not in ALL_ARCHS:
            log(f"Unknown architecture: {arch}. Valid: {', '.join(ALL_ARCHS)}", "ERROR")
            sys.exit(1)

    if len(custom_name) < 3:
        log("Custom name must be at least 3 characters", "ERROR")
        sys.exit(1)

    has_android = any(is_android_arch(a) for a in archs)
    has_ios = any(is_ios_arch(a) for a in archs)

    # iOS build needs macOS + Xcode CLT
    if has_ios and sys.platform != "darwin":
        log("iOS targets require running on macOS (Xcode CLT for iphoneos SDK)", "ERROR")
        sys.exit(1)

    # Directories
    script_dir = Path(__file__).parent.resolve()
    work_dir = Path(args.work_dir) if args.work_dir else script_dir / "build"
    output_dir = Path(args.output_dir) if args.output_dir else script_dir / "output"
    work_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Banner
    log("=" * 60, "HEADER")
    log("Custom Frida Builder", "HEADER")
    log("=" * 60, "HEADER")
    log(f"  Version:  Frida {version} (major: {frida_major})", "INFO")
    log(f"  Name:     '{custom_name}'", "INFO")
    log(f"  Archs:    {', '.join(archs)}", "INFO")
    log(f"  Port:     {args.port or '27042 (default)'}", "INFO")
    log(f"  Extended: {args.extended}", "INFO")
    log(f"  Work dir: {work_dir}", "INFO")
    log(f"  Output:   {output_dir}", "INFO")

    # Step 1: NDK (Android only)
    ndk_path: Path | None = None
    if has_android:
        if args.ndk_path:
            ndk_path = Path(args.ndk_path).resolve()
            if not ndk_path.exists():
                log(f"NDK path does not exist: {ndk_path}", "ERROR")
                sys.exit(1)
        else:
            ndk_path = ensure_ndk(work_dir)
        log(f"  NDK:      {ndk_path}", "INFO")
    else:
        log("  NDK:      not needed (iOS-only build)", "INFO")

    # Step 2: Clone
    frida_dir = work_dir / "frida"
    if not args.skip_clone:
        if frida_dir.exists():
            log("Removing existing frida dir...", "WARN")
            shutil.rmtree(frida_dir)
        frida_dir = clone_frida(version, work_dir)
    else:
        if not frida_dir.exists():
            log("--skip-clone requires existing source in work-dir", "ERROR")
            sys.exit(1)
        log(f"Using existing source at {frida_dir}", "OK")

    # Step 3: Source patches
    apply_source_patches(frida_dir, custom_name, has_android=has_android)
    apply_targeted_patches(frida_dir, custom_name, frida_major, has_android=has_android)

    # Step 3.5: Extended patches
    if args.extended:
        apply_extended_patches(frida_dir, custom_name, args.port)
    elif args.port:
        # Apply port patch even without --extended
        apply_extended_patches(frida_dir, custom_name, args.port)

    # Step 4: Stability fixes
    if args.temp_fixes:
        apply_stability_fixes(frida_dir, frida_major)

    if args.skip_build:
        log("=" * 60, "HEADER")
        log("Patches applied. Build skipped (--skip-build).", "OK")
        log(f"Source ready at: {frida_dir}", "INFO")
        log("To build manually:", "INFO")
        log(f"  cd {frida_dir}", "INFO")
        if has_android:
            log(f"  ANDROID_NDK_ROOT={ndk_path} ./configure --host=android-arm64", "INFO")
            log(f"  ANDROID_NDK_ROOT={ndk_path} make -j$(nproc)", "INFO")
        if has_ios:
            log("  ./configure --host=ios-arm64", "INFO")
            log("  make -j$(sysctl -n hw.ncpu)", "INFO")
        return

    # Step 5: Build loop
    for arch in archs:
        log("=" * 60, "HEADER")
        log(f"Building for {arch}", "STEP")
        log("=" * 60, "HEADER")

        # Frida's ./configure refuses to re-run when build/ already exists
        # ("Already configured. Wipe ./build to reconfigure."), so multi-arch
        # builds must clear the per-arch build dir before each configure.
        # Artifacts for the previous arch were already saved to output/ by
        # collect_artifacts, so wiping here is safe.
        build_dir = frida_dir / "build"
        if build_dir.exists():
            log(f"Removing stale {build_dir} before reconfigure", "INFO")
            shutil.rmtree(build_dir, ignore_errors=True)

        # apply_post_build_patches' frida_agent_main rename is persisted to
        # source (e.g. lib/agent/meson.build's `-Wl,-exported_symbol,_*` line).
        # Vala regenerates the agent.c each fresh build with the original
        # `frida_agent_main` symbol (Vala source defines namespace Frida.Agent
        # which we don't rename). With meson.build pinning the renamed symbol
        # but Vala emitting the original name, the next arch's first link
        # fails: `Undefined symbols ... -Wl,-exported_symbol,_<name>_agent_main`.
        # Revert to the original symbol name in source before each arch — the
        # post_build phase will re-apply the rename for this arch's binaries.
        if any(p.is_file() for p in frida_dir.rglob("meson.build")):
            reverted = replace_in_tree(
                frida_dir, f"{custom_name}_agent_main", "frida_agent_main",
                include_build=False,
            )
            if reverted:
                log(f"Reverted {custom_name}_agent_main -> frida_agent_main in source ({reverted})", "INFO")

        # Configure
        configure_arch(frida_dir, arch, ndk_path)

        # First build
        log("First build...", "STEP")
        build_frida(frida_dir, arch, ndk_path)

        # Post-build patches (frida_agent_main appears only after first build)
        apply_post_build_patches(frida_dir, custom_name)

        # Second build (incremental — only recompiles files with patched symbol)
        log("Second build (incremental)...", "STEP")
        build_frida(frida_dir, arch, ndk_path)

        # Collect and binary-patch artifacts
        collect_artifacts(frida_dir, arch, custom_name, version, output_dir, args.extended)

    # Step 5.5: iOS universal (fat) lipo merge — single dylib/server that loads
    # on both A11- (arm64) and A12+ (arm64e). Only meaningful when both archs
    # were built; sysctl arch detection on the device picks the right slice.
    ios_built = [a for a in archs if is_ios_arch(a)]
    if len(ios_built) >= 2 and sys.platform == "darwin":
        log("=" * 60, "HEADER")
        log("Building iOS universal (lipo) artifacts", "STEP")
        log("=" * 60, "HEADER")
        merge_ios_universal(output_dir, ios_built, custom_name, version)

    # Step 6: Verification
    if args.verify:
        log("=" * 60, "HEADER")
        log("Verification: scanning for residual 'frida' strings...", "STEP")
        for f in sorted(output_dir.iterdir()):
            if f.is_file() and not f.name.endswith(".gz"):
                verify_binary(f)

    # Done
    log("=" * 60, "HEADER")
    log("BUILD COMPLETE", "OK")
    log(f"Artifacts in: {output_dir}", "OK")
    for f in sorted(output_dir.iterdir()):
        size_mb = f.stat().st_size / (1024 * 1024)
        log(f"  {f.name} ({size_mb:.1f} MB)", "OK")

    # Usage hint
    log("", "INFO")
    log("To deploy:", "STEP")
    first_arch = archs[0]
    if is_ios_arch(first_arch):
        arch_short = first_arch.replace("ios-", "")
        server_name = f"{custom_name}-server-{version}-ios-{arch_short}"
        gadget_name = f"{custom_name}-gadget-{version}-ios-{arch_short}.dylib"
        log(f"  scp output/{server_name} root@<device>:/var/jb/usr/sbin/{custom_name}-server", "INFO")
        log(f"  scp output/{gadget_name} root@<device>:/var/jb/usr/lib/lib{custom_name}-gadget.dylib", "INFO")
        log(f"  ssh root@<device> 'chmod +x /var/jb/usr/sbin/{custom_name}-server && /var/jb/usr/sbin/{custom_name}-server &'", "INFO")
    else:
        arch_short = first_arch.replace("android-", "")
        server_name = f"{custom_name}-server-{version}-android-{arch_short}"
        log(f"  adb push output/{server_name} /data/local/tmp/{custom_name}-server", "INFO")
        log(f"  adb shell chmod 755 /data/local/tmp/{custom_name}-server", "INFO")
        log(f"  adb shell /data/local/tmp/{custom_name}-server &", "INFO")

    if args.port:
        log(f"  frida -H 127.0.0.1:{args.port} -f <package>", "INFO")
    elif is_ios_arch(first_arch):
        log("  frida -H <device-ip>:27042 -f <bundle-id>", "INFO")
    else:
        log(f"  frida -U -f <package>", "INFO")


if __name__ == "__main__":
    main()

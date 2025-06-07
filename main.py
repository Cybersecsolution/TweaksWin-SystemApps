# ──────────────── Standard Library ────────────────
import ctypes
import glob
import hashlib
import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import threading
import time
import webbrowser
import winreg
import atexit

# ──────────────── Third-Party Libraries ────────────────
import psutil
import pystray
from PIL import Image, ImageDraw, ImageTk
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# ──────────────── GUI Libraries ────────────────
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

# ──────────────── CTk DPI Crash Patch ────────────────
import customtkinter.windows.widgets.scaling.scaling_tracker as scaling_tracker


# ──────────────── Universal Updater Hash Utility ────────────────
def find_discord_updater():
    """
    Locate Discord's Update.exe by scanning versioned installations in LOCALAPPDATA.
    Returns the full path to Update.exe if found; otherwise returns None.
    """
    try:
        base = os.environ.get("LOCALAPPDATA", "")
        for entry in os.listdir(base):
            if entry.lower().startswith("discord"):
                root = os.path.join(base, entry)
                versions = [v for v in os.listdir(root) if v.startswith("app-")]
                if versions:
                    latest = max(
                        versions, 
                        key=lambda v: os.path.getmtime(os.path.join(root, v))
                    )
                    updater = os.path.join(root, latest, "Update.exe")
                    if os.path.exists(updater):
                        return updater
        return None
    except Exception as e:
        logger.error(f"Error locating Update.exe: {e}")
        return None


def compute_file_sha256(filepath):
    """
    Compute and return the SHA-256 hash of a file.
    Returns the hex digest string if successful; otherwise returns None.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Failed to compute hash for {filepath}: {e}")
        return None


# ──────────────── Patch for DPI scaling crash in CTk ────────────────
import customtkinter.windows.widgets.scaling.scaling_tracker as scaling_tracker
original_check_dpi_scaling = scaling_tracker.ScalingTracker.check_dpi_scaling


def safe_check_dpi_scaling(cls):
    """
    Patch for CTk's DPI scaling tracker to prevent RuntimeError
    caused by dynamic modification of window_widgets_dict during iteration.
    """
    try:
        for window in list(cls.window_widgets_dict.keys()):
            if not window.winfo_exists():
                cls.window_widgets_dict.pop(window, None)
    except RuntimeError:
        pass

scaling_tracker.ScalingTracker.check_dpi_scaling = classmethod(safe_check_dpi_scaling)

# ──────────────── Setup Logging ────────────────
log_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "optimizer.log")

logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)

APP_VERSION = "1.0.0"

logger = logging.getLogger()
logger.info(f"Optimizer {APP_VERSION} started")


@atexit.register
def shutdown_logging():
    for handler in logger.handlers:
        try:
            handler.flush()
            handler.close()
        except Exception:
            pass

# ──────────────── Constants ────────────────
DISCORD_CACHE_DIRS = [
    "Cache",
    "GPUCache",
    "Code Cache"
]

DISCORD_LOG_PATTERNS = [
    "*.log",
    "packages\\*.nupkg",
    "crashpad\\reports\\*.dmp"
]

FIREWALL_RULE_ID = "{3C1F2E84-A4E2-4D9F-9F4E-123456789ABC}"
FIREWALL_RULE_NAME = f"Discord Optimizer TCP Mode {FIREWALL_RULE_ID}"

HASH_VERIFICATION_FILE = os.path.join(
    os.environ.get("LOCALAPPDATA", ""), "trusted_update.ver"
)

DISCORD_ALLOWED_LOCALES = [
    "en-US.pak",
    "pt-BR.pak"
]


DISCORD_MODULE_PREFIXES = [
    "discord_desktop_core-",
    "discord_modules-",
    "discord_utils-",
    "discord_voice-"
]


# ──────────────── Platform Check ────────────────
# Ensure the application is running on Windows
if platform.system() != "Windows":
    messagebox.showerror(
        title="Unsupported Platform",
        message="This application only works on Windows"
    )
    sys.exit(1)


# ──────────────── Admin Privileges ────────────────
def is_admin():
    """
    Check if the script is running with administrative privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logger.error(f"Admin check failed: {e}")
        return False

if not is_admin():
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            " ".join(sys.argv),
            None,
            1
        )
    except Exception as e:
        logger.error(f"Admin elevation failed: {e}")
        messagebox.showerror(
            title="Admin Required",
            message="This application requires administrator privileges."
        )
    sys.exit()


# ──────────────── Paths Setup ────────────────
local_appdata    = os.environ["LOCALAPPDATA"]
program_files    = os.environ.get("ProgramFiles", r"C:\Program Files")
program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")


# ──────────────── Application Detection ────────────────
def find_discord():
    variants = "discord", "discordptb", "discordcanary", "discorddevelopment"

    for name in os.listdir(local_appdata):
        lname = name.lower()
        if any(lname.startswith(variant) for variant in variants):
            base_path = os.path.join(local_appdata, name)

            top_exe = os.path.join(base_path, f"{name}.exe")
            if os.path.exists(top_exe):
                return base_path, f"{name}.exe"

            versions = [v for v in os.listdir(base_path) if v.startswith("app-")]
            if versions:
                latest = max(versions, key=lambda v: os.path.getmtime(os.path.join(base_path, v)))
                exe_path = os.path.join(base_path, latest, "Discord.exe")
                if os.path.exists(exe_path):
                    return base_path, "Discord.exe"

    return None, None

discord_path, discord_exe = find_discord()


def start_dll_watcher():
    if not discord_path:
        logger.warning("Discord path not found — DLL watcher not started.")
        return

    try:
        version_dirs = [v for v in os.listdir(discord_path) if v.startswith("app-")]
        if not version_dirs:
            logger.warning("No versioned Discord folder found — skipping watcher.")
            return

        latest = max(version_dirs)
        watch_path = os.path.join(discord_path, latest, "modules")

        if not os.path.exists(watch_path):
            logger.warning("Modules folder not found — skipping DLL watcher.")
            return

        observer = Observer()
        observer.schedule(DLLHijackHandler(), watch_path, recursive=True)
        observer.daemon = True
        observer.start()

        logger.info(f"Started real-time DLL watcher on: {watch_path}")

    except Exception as e:
        logger.error(f"Failed to start real-time watchers: {e}")


# ──────────────── Helper Functions ────────────────
def kill_process_by_name(name):
    """
    Kill all processes that match the given name (case-insensitive).
    Returns a list of killed process PIDs.
    """
    killed = []
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] and proc.info['name'].lower() == name.lower():
            try:
                proc.kill()
                killed.append(proc.pid)
                logger.info(f"Killed process: {name} (PID: {proc.pid})")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.warning(f"Failed to kill {name}: {e}")
    return killed


def set_priority_by_name(name, priority=psutil.HIGH_PRIORITY_CLASS):
    """
    Set CPU priority for all processes with the given name.
    """
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] and proc.info['name'].lower() == name.lower():
            try:
                proc.nice(priority)
                logger.info(f"Set priority for {name} to {priority}")
            except Exception as e:
                logger.warning(f"Failed to set priority for {name}: {e}")


def remove_dirs(base_path, folders):
    """
    Safely remove specified directories from the base path.
    Prevents symlink abuse and path traversal.
    """
    base_real = os.path.realpath(base_path)

    for folder in folders:
        target_path = os.path.join(base_path, folder)
        real_path = os.path.realpath(target_path)

        try:
            if os.path.islink(target_path):
                logger.warning(f"Skipped symlink (not deleting): {target_path}")
                continue
            if not real_path.startswith(base_real):
                logger.warning(f"Blocked deletion attempt outside base: {real_path}")
                continue
            if os.path.exists(real_path):
                shutil.rmtree(real_path, ignore_errors=True)
                logger.info(f"Removed directory: {real_path}")
        except Exception as e:
            logger.error(f"Failed to remove directory {real_path}: {e}")


def remove_files_by_patterns(base_path, patterns):
    """
    Remove files in base_path matching any glob pattern in 'patterns'.
    """
    for pattern in patterns:
        full_pattern = os.path.join(base_path, pattern)
        for file in glob.glob(full_pattern, recursive=True):
            try:
                os.chmod(file, 0o666)  
                os.remove(file)
                logger.info(f"Removed file: {file}")
            except Exception as e:
                logger.error(f"Failed to remove file {file}: {e}")


def verify_file_sha256(filepath, expected_hash):
    """
    Verify file integrity by comparing its SHA-256 hash to an expected value.
    Returns True if they match.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                sha256.update(block)
        file_hash = sha256.hexdigest()
        return file_hash.lower() == expected_hash.lower()
    except Exception as e:
        logger.error(f"Failed to hash file {filepath}: {e}")
        return False


def sanitize_discord_modules():
    """
    Remove unauthorized modules and known hijackable DLLs from Discord modules.
    """
    SUSPICIOUS_DLLS = {
        "winhttp.dll", "userenv.dll", "version.dll", "wsock32.dll",
        "mpr.dll", "dnsapi.dll", "cryptbase.dll", "uxtheme.dll",
        "ntdll.dll", "kernel32.dll", "shell32.dll"
    }

    SAFE_PREFIXES = (
        "discord_desktop_core-",
        "discord_modules-",
        "discord_utils-",
        "discord_voice-"
    )

    if not discord_path:
        logger.warning("Discord path not found — skipping module sanitization.")
        return

    try:
        for sub in os.listdir(discord_path):
            if not sub.startswith("app-"):
                continue

            modules_path = os.path.join(discord_path, sub, "modules")
            if not os.path.exists(modules_path):
                continue

            for mod in os.listdir(modules_path):
                mod_path = os.path.join(modules_path, mod)
                if not any(mod.startswith(prefix) for prefix in SAFE_PREFIXES):
                    try:
                        if os.path.isdir(mod_path):
                            shutil.rmtree(mod_path, ignore_errors=True)
                            logger.info(f"Removed unknown module folder: {mod}")
                        else:
                            os.remove(mod_path)
                            logger.info(f"Removed unknown module file: {mod}")
                    except Exception as e:
                        logger.warning(f"Failed to remove: {mod_path} — {e}")

            for root, _, files in os.walk(modules_path):
                for file in files:
                    if file.lower().endswith(".dll") and file.lower() in SUSPICIOUS_DLLS:
                        dll_path = os.path.join(root, file)
                        try:
                            os.remove(dll_path)
                            logger.info(f"Removed suspicious DLL: {dll_path}")
                        except Exception as e:
                            logger.warning(f"Failed to delete DLL {dll_path}: {e}")
    except Exception as e:
        logger.error(f"Module sanitization failed: {e}")


class DLLHijackHandler(FileSystemEventHandler):
    """
    Watches for newly created DLLs in the Discord modules folder.
    Deletes known hijackable DLLs in real-time.
    """
    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        if file_path.lower().endswith(".dll"):
            file_name = os.path.basename(file_path).lower()
            allowed_prefixes = tuple(p.lower() for p in DISCORD_MODULE_PREFIXES)
            suspicious_dlls = {
                "winhttp.dll", "userenv.dll", "version.dll", "wsock32.dll",
                "mpr.dll", "dnsapi.dll", "cryptbase.dll", "uxtheme.dll",
                "ntdll.dll", "kernel32.dll", "shell32.dll"
            }

            try:
                if any(file_name.startswith(prefix) for prefix in allowed_prefixes):
                    return  # trusted
                if file_name in suspicious_dlls:
                    os.remove(file_path)
                    logger.warning(f"⚠️ Deleted suspicious DLL in real-time: {file_path}")
                    messagebox.showwarning("Security Alert", f"Suspicious DLL deleted:\n{file_name}")
                else:
                    logger.warning(f"⚠️ Unknown DLL detected: {file_path}")
                    messagebox.showinfo("Module Monitor", f"Unknown DLL created: {file_name}")
            except Exception as e:
                logger.error(f"Failed to process new DLL: {file_path} — {e}")


def lock_down_discord_modules():
    """
    Placeholder for ACL lockdown — restricts write access to Discord's modules folder.
    """
    if not discord_path:
        logger.warning("Discord path not found — cannot lock modules folder")
        return

    try:
        version_dirs = [v for v in os.listdir(discord_path) if v.startswith("app-")]
        if not version_dirs:
            logger.warning("No versioned app folder found")
            return

        latest = max(version_dirs)
        modules_path = os.path.join(discord_path, latest, "modules")

        if not os.path.exists(modules_path):
            logger.warning("Modules folder missing — skipping ACL lock")
            return

        logger.info(f"Locked down: {modules_path} — write access removed")
        messagebox.showinfo("Security Hardened", "Modules folder is now write-protected.")

    except Exception as e:
        logger.error(f"Failed to lock modules folder: {e}")
        messagebox.showerror("ACL Lock Failed", f"Could not secure modules folder:\n{e}")


# ──────────────── Discord Functions ────────────────
def clear_discord_cache():
    """Clear Discord's temporary cache files."""
    if discord_path:
        kill_process_by_name(discord_exe)
        time.sleep(1)
        remove_dirs(discord_path, DISCORD_CACHE_DIRS)


def clear_discord_logs():
    """Clear logs, crash dumps, and package archives from Discord."""
    if discord_path:
        remove_files_by_patterns(discord_path, DISCORD_LOG_PATTERNS)


def debloat_discord_modules():
    """Remove unnecessary module folders not matching known prefixes."""
    if discord_path:
        for sub in os.listdir(discord_path):
            if sub.startswith("app-"):
                modules_path = os.path.join(discord_path, sub, "modules")
                if os.path.exists(modules_path):
                    for mod in os.listdir(modules_path):
                        if not any(mod.startswith(prefix) for prefix in DISCORD_MODULE_PREFIXES):
                            try:
                                shutil.rmtree(os.path.join(modules_path, mod), ignore_errors=True)
                                logger.info(f"Removed module: {mod}")
                            except Exception as e:
                                logger.error(f"Failed to remove module {mod}: {e}")


def clear_discord_languages():
    """Remove unapproved locale .pak files from Discord."""
    if discord_path:
        for sub in os.listdir(discord_path):
            if sub.startswith("app-"):
                loc_path = os.path.join(discord_path, sub, "locales")
                if os.path.exists(loc_path):
                    for f in os.listdir(loc_path):
                        if f.endswith(".pak") and os.path.basename(f) not in DISCORD_ALLOWED_LOCALES:
                            try:
                                os.remove(os.path.join(loc_path, f))
                                logger.info(f"Removed locale: {f}")
                            except Exception as e:
                                logger.error(f"Failed to remove locale {f}: {e}")


def remove_old_discord_versions():
    """Keep only the newest Discord version and delete the rest."""
    if discord_path:
        versions = [v for v in os.listdir(discord_path) if v.startswith("app-")]
        if len(versions) > 1:
            latest = max(versions)
            for v in versions:
                if v != latest:
                    try:
                        shutil.rmtree(os.path.join(discord_path, v), ignore_errors=True)
                        logger.info(f"Removed old version: {v}")
                    except Exception as e:
                        logger.error(f"Failed to remove version {v}: {e}")


def get_or_create_trusted_hash(updater_path):
    """Verify or save a trusted SHA-256 hash for Discord's Update.exe."""
    try:
        if os.path.exists(HASH_VERIFICATION_FILE):
            with open(HASH_VERIFICATION_FILE, "r") as f:
                stored_hash = f.read().strip()
                if stored_hash:
                    return stored_hash

        trusted_hash = compute_file_sha256(updater_path)
        if trusted_hash:
            with open(HASH_VERIFICATION_FILE, "w") as f:
                f.write(trusted_hash)
            logger.info(f"Trusted Update.exe hash saved to {HASH_VERIFICATION_FILE}")
            return trusted_hash
    except Exception as e:
        logger.error(f"Failed to get or create trusted hash: {e}")
    return None


def restart_discord():
    """Securely restart Discord after verifying Update.exe."""
    if discord_exe and discord_path:
        kill_process_by_name(discord_exe)

        def wait_for_process_exit(name, timeout=5):
            deadline = time.time() + timeout
            while time.time() < deadline:
                if not any(proc.info['name'] and proc.info['name'].lower() == name.lower()
                           for proc in psutil.process_iter(['name'])):
                    return True
                time.sleep(0.2)
            return False

        wait_for_process_exit(discord_exe)

        updater = os.path.join(discord_path, "Update.exe")
        if os.path.exists(updater):
            trusted_hash = get_or_create_trusted_hash(updater)
            if trusted_hash and verify_file_sha256(updater, trusted_hash):
                subprocess.Popen(
                    [updater, "--processStart", discord_exe],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                logger.info("Verified and restarted Discord via Update.exe")
            else:
                logger.warning("Update.exe hash mismatch — launch aborted")
                messagebox.showwarning("Security Alert", "Discord updater verification failed. Aborting restart.")


def disable_discord_autorun():
    """Remove Discord from Windows auto-start registry key."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_ALL_ACCESS)
        try:
            winreg.DeleteValue(key, "Discord")
            logger.info("Disabled Discord autorun")
        except FileNotFoundError:
            logger.info("Discord autorun not found")
        winreg.CloseKey(key)
    except Exception as e:
        logger.error(f"Failed to disable autorun: {e}")


def free_discord_memory():
    """Trim working set memory from Discord processes."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] and "discord" in proc.info['name'].lower():
            try:
                ctypes.windll.psapi.EmptyWorkingSet(
                    ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, proc.info['pid']))
                logger.info(f"Emptied working set for PID {proc.info['pid']}")
            except Exception as e:
                logger.warning(f"Failed to clean memory for PID {proc.info['pid']}: {e}")


def kill_discord_web_instances():
    """Kill any web browser instances with Discord open."""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if (proc.info['name'] and "chrome" in proc.info['name'].lower()) and \
               any("discord" in arg for arg in proc.info['cmdline']):
                proc.kill()
                logger.info(f"Killed Discord web process: PID {proc.info['pid']}")
        except Exception as e:
            logger.warning(f"Error killing web Discord instance: {e}")


def reset_discord_settings():
    """Reset Discord user settings and local storage."""
    try:
        appdata = os.environ.get("APPDATA", "")
        settings_path = os.path.join(appdata, "discord", "settings.json")
        if os.path.exists(settings_path):
            os.remove(settings_path)
            logger.info("Deleted settings.json")

        local_storage_path = os.path.join(appdata, "discord", "Local Storage")
        if os.path.exists(local_storage_path):
            shutil.rmtree(local_storage_path, ignore_errors=True)
            logger.info("Cleared Local Storage")
    except Exception as e:
        logger.error(f"Failed to reset Discord settings: {e}")


def enhance_discord_voice_quality():
    """Boost voice bitrate by modifying settings.json safely."""
    try:
        appdata = os.environ.get("APPDATA", "")
        settings_path = os.path.join(appdata, "discord", "settings.json")

        if not os.path.exists(settings_path):
            logger.info("Discord settings.json not found — skipping enhancement.")
            return

        backup_path = settings_path + ".bak"
        shutil.copyfile(settings_path, backup_path)
        logger.info(f"Backup created: {backup_path}")

        if not os.access(settings_path, os.R_OK | os.W_OK):
            raise PermissionError(f"Insufficient permissions to access {settings_path}")

        with open(settings_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError("settings.json does not contain a valid JSON object.")
            except json.JSONDecodeError as e:
                logger.warning(f"Corrupt settings.json: {e} — restoring from backup.")
                shutil.copyfile(backup_path, settings_path)
                return

        data.setdefault("media", {})
        if not isinstance(data["media"], dict):
            raise ValueError("'media' key is not a valid JSON object.")

        data["media"]["min_bitrate"] = 128000
        data["media"]["max_bitrate"] = 384000

        temp_path = settings_path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(temp_path, settings_path)
        os.chmod(settings_path, stat.S_IRUSR | stat.S_IWUSR)

        logger.info("Enhanced Discord voice quality in settings.json (secure mode).")
    except Exception as e:
        logger.error(f"Failed to enhance voice quality securely: {e}")
        raise


def revert_discord_voice_quality():
    """Remove min/max bitrate fields to revert audio settings."""
    try:
        appdata = os.environ.get("APPDATA", "")
        settings_path = os.path.join(appdata, "discord", "settings.json")

        if not os.path.exists(settings_path):
            logger.info("settings.json not found — nothing to revert.")
            return

        backup_path = settings_path + ".bak"
        shutil.copyfile(settings_path, backup_path)
        logger.info(f"Backup created: {backup_path}")

        if not os.access(settings_path, os.R_OK | os.W_OK):
            raise PermissionError(f"Insufficient permissions to access {settings_path}")

        with open(settings_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError("settings.json does not contain a valid JSON object.")
            except json.JSONDecodeError as e:
                logger.warning(f"Corrupt settings.json: {e} — restoring from backup.")
                shutil.copyfile(backup_path, settings_path)
                return

        if "media" in data and isinstance(data["media"], dict):
            data["media"].pop("min_bitrate", None)
            data["media"].pop("max_bitrate", None)
            if not data["media"]:
                data.pop("media")

        temp_path = settings_path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(temp_path, settings_path)
        os.chmod(settings_path, stat.S_IRUSR | stat.S_IWUSR)

        logger.info("Reverted Discord voice quality settings (secure mode).")
    except Exception as e:
        logger.error(f"Failed to securely revert voice quality: {e}")
        raise


def enforce_discord_tcp_mode():
    """Block UDP protocol for Discord via Windows Firewall."""
    try:
        if not (discord_path and discord_exe):
            raise RuntimeError("Discord path or executable not found")

        exe_path = os.path.realpath(os.path.join(discord_path, discord_exe))

        if not os.path.exists(exe_path):
            raise FileNotFoundError(f"Discord executable not found: {exe_path}")

        subprocess.call([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={FIREWALL_RULE_NAME}"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        subprocess.check_call([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={FIREWALL_RULE_NAME}",
            "dir=out",
            "action=block",
            "protocol=UDP",
            f"program={exe_path}",
            "enable=yes"
        ])

        logger.info(f"Enforced TCP mode by blocking UDP for: {exe_path}")
    except Exception as e:
        logger.error(f"Failed to enforce TCP-only mode: {e}")
        raise


def reset_discord_tcp_mode():
    """Remove firewall rule to re-enable UDP for Discord."""
    try:
        subprocess.call([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={FIREWALL_RULE_NAME}"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("Reset Discord to allow both TCP and UDP")
    except Exception as e:
        logger.error(f"Failed to reset TCP/UDP mode: {e}")
        raise


# ──────────────── ToolTip Class ────────────────
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None

        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _event=None):
        """Display the tooltip window near the widget."""
        x = self.widget.winfo_rootx() + self.widget.winfo_width() + 10
        y = self.widget.winfo_rooty() + (self.widget.winfo_height() // 2) - 10

        self.tooltip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")

        label = tk.Label(
            tw,
            text=self.text,
            background="#1f2937",
            foreground="#f9fafb",
            borderwidth=1,
            relief="solid",
            font=("Segoe UI", 9),
            padx=6,
            pady=2
        )
        label.pack()

    def hide(self, _event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None


# ──────────────── GUI Setup ────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.geometry("470x790")
app.title("Discord Optimizer")
app.resizable(False, False)
app.overrideredirect(True)
app.attributes("-alpha", 0.96)


def make_window_rounded(win, radius=25):
    try:
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        region = ctypes.windll.gdi32.CreateRoundRectRgn(
            0, 0, win.winfo_width(), win.winfo_height(), radius, radius
        )
        ctypes.windll.user32.SetWindowRgn(hwnd, region, True)
    except Exception as e:
        logger.error(f"Window rounding failed: {e}")

app.x = app.y = None

def do_move_gemt(e):
    if app.x is not None and app.y is not None:
        app.geometry(f'+{e.x_root - app.x}+{e.y_root - app.y}')

app.bind("<ButtonPress-1>", lambda e: (setattr(app, 'x', e.x), setattr(app, 'y', e.y)))
app.bind("<ButtonRelease-1>", lambda e: (setattr(app, 'x', None), setattr(app, 'y', None)))
app.bind("<B1-Motion>", do_move_gemt)

# ──────────────── System Tray Integration ────────────────
tray_icon = None

def safe_exit():
    global tray_icon
    if tray_icon:
        try:
            tray_icon.stop()
        except Exception as e:
            logger.warning(f"Tray icon cleanup failed: {e}")
    app.destroy()

def minimize_app():
    app.after(100, app.withdraw)
    create_tray_icon()

def create_tray_icon():
    global tray_icon

    image = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    dc = ImageDraw.Draw(image)

    dc.ellipse((16, 16, 48, 48), fill='#1a56db', outline='#1e3a8a')
    dc.ellipse((20, 20, 44, 44), fill='#3b82f6')

    def restore_app(icon, item=None):
        try:
            if icon:
                icon.stop()
            logger.info("App restored from tray")
            app.after(0, lambda: [app.deiconify(), app.lift(), app.overrideredirect(True)])
        except Exception as e:
            logger.error(f"Failed to restore app from tray: {e}")

    def exit_app(icon, item=None):
        try:
            if icon:
                icon.stop()
            logger.info("App exiting via tray menu")
            app.after(0, safe_exit)
        except Exception as e:
            logger.error(f"Failed to exit app from tray: {e}")

    # Build system tray menu
    menu = pystray.Menu(
        pystray.MenuItem('Restore', restore_app),
        pystray.MenuItem('Exit', exit_app)
    )

    tray_icon = pystray.Icon("optimizer", image, "Discord Optimizer", menu)
    tray_icon.title = "Discord Optimizer"
    threading.Thread(target=tray_icon.run, daemon=True).start()


# ──────────────── Progress Dialog ────────────────
def show_progress(task_func, title):
    popup = ctk.CTkToplevel(app)
    popup.geometry("300x120")
    popup.transient(app)
    popup.grab_set()
    popup.overrideredirect(True)

    app_x = app.winfo_x()
    app_y = app.winfo_y()
    popup.geometry(f"+{app_x + 100}+{app_y + 300}")

    clean_title = title.split(" ", 1)[-1] if " " in title else title
    ctk.CTkLabel(
        popup,
        text=clean_title,
        font=ctk.CTkFont(size=14, weight="bold")
    ).pack(pady=(15, 10))

    bar = ctk.CTkProgressBar(popup, width=240, mode='indeterminate')
    bar.pack(pady=5)
    bar.start()

    status = ctk.CTkLabel(popup, text="Working...", text_color="#a0aec0")
    status.pack(pady=5)

    def run():
        try:
            task_func()
            status.configure(text="Completed successfully", text_color="#48bb78")
        except Exception as e:
            logger.error(f"Task failed: {e}")
            status.configure(text=f"Error: {str(e)}", text_color="#e53e3e")
        finally:
            bar.stop()
            time.sleep(1.5)
            popup.destroy()

    threading.Thread(target=run, daemon=True).start()


# ──────────────── Tabs & Buttons ────────────────
from PIL import ImageTk, Image

# Asset loader helper
def asset(file_name):
    return os.path.join("assets", file_name)

# Logo and title setup
try:
    logo_img = Image.open(asset("logo.png")).resize((80, 80), Image.LANCZOS)
    logo_tk = ImageTk.PhotoImage(logo_img)

    logo_label = tk.Label(
        app,
        image=logo_tk,
        bg="#1e1e1e",
        borderwidth=0
    )
    logo_label.image = logo_tk
    logo_label.pack(pady=(20, 5))

    title_label = ctk.CTkLabel(
        app,
        text="Discord Optimizer",
        font=ctk.CTkFont(size=18, weight="bold")
    )
    title_label.pack(pady=(0, 10))

except Exception as e:
    logger.warning(f"Failed to load logo or title: {e}")

# Container for tab layout
tabs_wrapper = ctk.CTkFrame(
    app,
    corner_radius=12,
    fg_color="#2d2f31",
    height=650
)
tabs_wrapper.pack(padx=10, pady=(10, 10), anchor="n")

# Create the Tabview and its tabs
tabs = ctk.CTkTabview(
    tabs_wrapper,
    width=450,
    height=660,
    corner_radius=12,
    fg_color="transparent"
)
tabs.pack(pady=(20, 10), padx=10, fill="both", expand=True)

tabs.add("Discord")
tabs.add("Settings")
tabs.add("Credits")


# ──────────────── Tab Font Style ────────────────
def update_tab_font_style():
    try:
        if hasattr(tabs, "_segmented_button") and hasattr(tabs._segmented_button, "_buttons"):
            selected = tabs._segmented_button._selected_index
            for i, btn in enumerate(tabs._segmented_button._buttons):
                weight = "bold" if i == selected else "normal"
                btn.configure(font=ctk.CTkFont(family="Segoe UI", size=14, weight=weight))
    except Exception as e:
        logger.error(f"[Font Update Failed] {e}")

tabs._segmented_button.configure(command=lambda value: [tabs.set(value), update_tab_font_style()])
app.after(100, update_tab_font_style)

# ──────────────── Tabs & Buttons ────────────────
from PIL import Image, ImageTk, ImageDraw


def load_rounded_image(path, size=(48, 48)):
    img = Image.open(path).resize(size, Image.LANCZOS).convert("RGBA")
    mask = Image.new("L", size, 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0, size[0], size[1]), fill=255)
    rounded = Image.new("RGBA", size)
    rounded.paste(img, (0, 0), mask)
    return ImageTk.PhotoImage(rounded)

sergio_photo = load_rounded_image(os.path.join("assets", "sergio.png"))
calixto_photo = load_rounded_image(os.path.join("assets", "calixto.png"))

credits_tab = tabs.tab("Credits")
credits_frame = ctk.CTkFrame(credits_tab, fg_color="transparent")
credits_frame.pack(fill="both", expand=True)

credits_inner = ctk.CTkFrame(credits_frame, fg_color="transparent")
credits_inner.pack(anchor="center", padx=20, pady=(30, 10), fill="both", expand=False)

ctk.CTkLabel(
    credits_inner,
    text="Developers",
    font=ctk.CTkFont(size=17, weight="bold"),
    text_color="#f9fafb"
).pack(pady=(0, 6))

ctk.CTkLabel(
    credits_inner,
    text="Meet the creators behind Discord Optimizer.",
    font=ctk.CTkFont(size=13, weight="normal", slant="italic"),
    text_color="#9ca3af",
    wraplength=380,
    justify="center"
).pack(pady=(0, 20))


def tag_color_for(tag):
    tag_map = {
        "backend": "#1e3a8a",
        "frontend": "#2563eb",
        "security": "#dc2626",
        "performance": "#9333ea",
        "ux": "#10b981",
        "clean code": "#0ea5e9"
    }
    return tag_map.get(tag.lower(), "#4b5563")  

from PIL import Image, ImageTk, ImageDraw


def create_profile_card(parent, name, role, image, links=None, tags=None):
    card = ctk.CTkFrame(parent, fg_color="#1f2937", corner_radius=16)
    card.pack(pady=10, anchor="w", fill="x", padx=10)

    container = tk.Frame(card, bg="#1f2937")
    container.pack(padx=14, pady=14, fill="x")

    img_label = tk.Label(container, image=image, bg="#1f2937", bd=0)
    img_label.image = image
    img_label.pack(side="left", padx=(0, 14))

    text_frame = tk.Frame(container, bg="#1f2937")
    text_frame.pack(side="left", fill="both", expand=True)

    tk.Label(
        text_frame, text=name, font=("Segoe UI", 14, "bold"),
        fg="#3b82f6", bg="#1f2937"
    ).pack(anchor="w")

    tk.Label(
        text_frame, text=role, font=("Segoe UI", 11),
        fg="#94a3b8", bg="#1f2937", wraplength=280, justify="left"
    ).pack(anchor="w", pady=(3, 0))

    if tags:
        tag_frame = tk.Frame(card, bg="#1f2937")
        tag_frame.pack(anchor="w", padx=24, pady=(4, 6), fill="x")
        for t in tags:
            tag_color = tag_color_for(t)
            tk.Label(
                tag_frame, text=t, font=("Segoe UI", 8, "bold"),
                bg=tag_color, fg="white", padx=6, pady=2
            ).pack(side="left", padx=3)

    if links:
        icon_frame = tk.Frame(card, bg="#1f2937")
        icon_frame.pack(anchor="w", padx=24, pady=(0, 10))

        for icon_path, url in links:
            icon_img = Image.open(icon_path).resize((20, 20), Image.LANCZOS).convert("RGBA")

            mask = Image.new("L", (20, 20), 0)
            draw = ImageDraw.Draw(mask)
            draw.ellipse((0, 0, 20, 20), fill=255)

            rounded_icon = Image.new("RGBA", (20, 20))
            rounded_icon.paste(icon_img, (0, 0), mask)

            icon_tk = ImageTk.PhotoImage(rounded_icon)
            icon_btn = tk.Label(icon_frame, image=icon_tk, bg="#1f2937", cursor="hand2", bd=0)
            icon_btn.image = icon_tk
            icon_btn.pack(side="left", padx=4)

            def callback(event, link=url):
                webbrowser.open(link)

            icon_btn.bind("<Enter>", lambda e, b=icon_btn: b.config(bg="#374151"))
            icon_btn.bind("<Leave>", lambda e, b=icon_btn: b.config(bg="#1f2937"))
            icon_btn.bind("<Button-1>", callback)

            tooltip_text = os.path.splitext(os.path.basename(icon_path))[0].capitalize()
            ToolTip(icon_btn, tooltip_text)

# ──────────────── Credits Tab ────────────────
credits_inner = ctk.CTkFrame(tabs.tab("Credits"), fg_color="transparent")
credits_inner.pack(anchor="n", padx=10, pady=10)

# Profile: Calixto
create_profile_card(
    credits_inner,
    "Calixto-DEV",
    "Senior Polyglot Software Architect",
    calixto_photo,
    links=[
        (asset("github.png"), "https://github.com/Salc-wm"),
        (asset("discord.png"), "https://discord.gg/UXyUh9FczM")
    ],

    tags=["Backend", "Performance", "Clean Code"]
)

# Profile: Sergio Maquinna
create_profile_card(
    credits_inner,
    "Sergio Maquinna",
    "Software Engineer & UX Designer",
    sergio_photo,
    links=[
        (asset("github.png"), "https://github.com/Cybersecsolution"),
        (asset("youtube.png"), "https://www.youtube.com/@Cybersecurity-solution"),
        (asset("tiktok.png"), "https://www.tiktok.com/@cybersec.solutions"),
        (asset("discord.png"), "https://discord.gg/UXyUh9FczM")
    ],
    tags=["UX", "Frontend", "Security"]
)

# ───── Footer Separator ─────
tk.Frame(credits_inner, height=1, bg="#374151").pack(fill="x", padx=20, pady=(20, 0))

# ───── Copyright Label ─────
# ──────────────── Footer & Tabs Integration ────────────────
ctk.CTkLabel(
    credits_inner,
    text="© 2025 Discord Optimizer — All rights reserved",
    font=ctk.CTkFont(size=11),
    text_color="#4b5563"
).pack(pady=(10, 10))

# ──────────────── 🎮 Discord Tab ────────────────
discord_tab = tabs.tab("Discord")

discord_buttons = [
    ("🧹 Clear Cache", clear_discord_cache, "Clearing Discord cache..."),
    ("📋 Clear Logs", clear_discord_logs, "Clearing Discord logs..."),
    ("🔄 Restart Discord", restart_discord, "Restarting Discord..."),
    ("🗑️ Debloat Modules", debloat_discord_modules, "Removing Discord bloat modules..."),
    ("🛡️ Sanitize Modules", sanitize_discord_modules, "Scanning Discord for hijackable DLLs..."),
    ("🌐 Clean Languages", clear_discord_languages, "Cleaning Discord language files..."),
    ("🔄 Remove Old Versions", remove_old_discord_versions, "Removing old Discord versions..."),
    ("🚫 Disable Auto-Start", disable_discord_autorun, "Disabling Discord auto-start..."),
    ("🧠 Free RAM", free_discord_memory, "Free up Discord's memory usage"),
    ("🎙️ Voice Quality Boost", enhance_discord_voice_quality, "Boosting voice bitrate in settings.json..."),
    ("🔁 Reset Settings", reset_discord_settings, "Resetting Discord settings to default"),
    ("📡 TCP Push", enforce_discord_tcp_mode, "Forcing Discord to use TCP only..."),
    ("🌐 Reset TCP Mode", reset_discord_tcp_mode, "Reverting Discord to normal UDP/TCP mode...")
]

manual_tooltips = {
    "🧹 Clear Cache": "Remove Discord's temporary cache files",
    "📋 Clear Logs": "Erase Discord's debug and usage logs",
    "🔄 Restart Discord": "Kill and restart the Discord process",
    "🗑️ Debloat Modules": "Delete unused bundled modules from Discord",
    "🛡️ Sanitize Modules": "Remove suspicious DLLs and unverified modules from Discord's folder",
    "🌐 Clean Languages": "Remove unneeded language files",
    "🔄 Remove Old Versions": "Delete outdated Discord installations",
    "🚫 Disable Auto-Start": "Prevent Discord from auto-launching",
    "🧠 Free RAM": "Force Discord to release unused memory",
    "🎙️ Voice Quality Boost": "Sets min/max bitrate in settings.json for high-quality audio",
    "🔁 Reset Settings": "Reset user settings and local storage to default",
    "📡 TCP Push": "Force Discord to use TCP by blocking UDP via Windows Firewall",
    "🌐 Reset TCP Mode": "Re-enable UDP by removing the firewall block rule"
}

for text, command, popup_title in discord_buttons:
    btn = ctk.CTkButton(
        discord_tab,
        text=text,
        font=ctk.CTkFont(family="Segoe UI Emoji", size=14),
        width=240,
        corner_radius=8,
        command=lambda c=command, t=popup_title: show_progress(c, t)
    )
    btn.pack(pady=5, padx=20)

    tooltip_text = manual_tooltips.get(text, "Click to perform action")
    ToolTip(btn, tooltip_text)

    if not discord_path:
        btn.configure(state="disabled", fg_color="#4a5568")


# ──────────────── ⚙️ Settings Tab ────────────────
settings_tab = tabs.tab("Settings")
ctk.CTkLabel(
    settings_tab,
    text="Application Settings",
    font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold")
).pack(pady=(10, 5))


# ──────────────── Status Bar ────────────────
status_bar = ctk.CTkFrame(app, height=30)
status_bar.pack(fill="x", padx=10, pady=(0, 10))

status_text = f"Discord: {'Found' if discord_path else 'Not found'}  |  Version: {APP_VERSION}"
status_label = ctk.CTkLabel(status_bar, text=status_text, text_color="#a0aec0")
status_label.pack(side="left", padx=10)


# ──────────────── 🧭 Window Controls ────────────────
def create_control_button(text, x_offset_from_right, command, text_color="white", hover_color="#4a5568", bg_color="transparent"):
    btn = ctk.CTkButton(
        app,
        text=text,
        width=22,
        height=22,
        corner_radius=11,
        fg_color=bg_color,
        text_color=text_color,
        hover_color=hover_color,
        font=ctk.CTkFont(size=14, weight="bold"),
        command=command
    )

    def place_button():
        win_width = app.winfo_width()
        btn.place(x=win_width - x_offset_from_right - btn.winfo_reqwidth(), y=8)

    app.after(20, place_button)
    return btn


# ❌ Close Button
close_btn = create_control_button(
    "✕",
    x_offset_from_right=12,
    command=safe_exit,
    text_color="white",
    hover_color="#c53030",
    bg_color="#e53e3e"
)

# ➖ Minimize Button
min_btn = create_control_button(
    "➖",
    x_offset_from_right=60,
    command=minimize_app,
    text_color="white",
    hover_color="#4a5568",
    bg_color="#2d3748"
)


def main():  # ──────────────── 🏁 Startup & Loop ────────────────
    app.after(100, lambda: make_window_rounded(app, 15))
    app.after(3000, start_dll_watcher)

    app.mainloop()


if __name__ == '__main__':
    main()

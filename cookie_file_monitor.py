"""
cookie_file_monitor.py
Surveille les accès suspects aux fichiers de cookies/tokens des navigateurs sous Windows.
Utilise watchdog pour détecter les lectures/modifications en temps réel.

Installation : pip install watchdog requests
"""

import os
import time
import json
import hashlib
import logging
import requests
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── Configuration ──────────────────────────────────────────────────────────────
ALERT_WEBHOOK = "http://localhost:5000/alert"   # URL de l'interface web locale
LOG_FILE      = "cookie_monitor.log"
POLL_INTERVAL = 1  # secondes

# Chemins sensibles par navigateur (Windows)
SENSITIVE_PATHS = {
    "Chrome": [
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies"),
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies"),
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Storage"),
    ],
    "Firefox": [
        os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles"),  # dossier entier
    ],
    "Edge": [
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies"),
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network\Cookies"),
    ],
    "Discord": [
        os.path.expandvars(r"%APPDATA%\discord\Local Storage\leveldb"),
    ],
}

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ── Utilitaires ────────────────────────────────────────────────────────────────

def get_process_accessing_file(filepath: str) -> list[dict]:
    """
    Retourne les processus qui ont le fichier ouvert.
    Nécessite psutil : pip install psutil
    """
    try:
        import psutil
        result = []
        for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                for f in proc.open_files():
                    if filepath.lower() in f.path.lower():
                        result.append({
                            "pid":      proc.pid,
                            "name":     proc.name(),
                            "exe":      proc.exe(),
                            "username": proc.username(),
                        })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        return result
    except ImportError:
        return [{"error": "psutil non installé"}]


def send_alert(alert: dict):
    """Envoie une alerte JSON à l'interface web."""
    try:
        requests.post(ALERT_WEBHOOK, json=alert, timeout=2)
    except requests.RequestException as e:
        log.warning(f"Impossible d'envoyer l'alerte : {e}")


def is_browser_process(name: str) -> bool:
    """Retourne True si le processus est un navigateur légitime."""
    legit = {"chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe"}
    return name.lower() in legit


# ── Handler watchdog ───────────────────────────────────────────────────────────

class CookieFileHandler(FileSystemEventHandler):

    def __init__(self, browser: str):
        self.browser = browser

    def _handle(self, event_type: str, path: str):
        procs = get_process_accessing_file(path)
        suspicious_procs = [p for p in procs if not is_browser_process(p.get("name", ""))]

        severity = "HIGH" if suspicious_procs else "INFO"

        alert = {
            "timestamp":  datetime.now().isoformat(),
            "type":       "FILE_ACCESS",
            "severity":   severity,
            "browser":    self.browser,
            "event":      event_type,
            "file":       path,
            "processes":  procs,
            "suspicious": suspicious_procs,
            "message":    (
                f"[{severity}] Accès {event_type} sur les cookies {self.browser} "
                f"par {[p.get('name') for p in suspicious_procs] or 'processus légitimes'}"
            ),
        }

        if severity == "HIGH":
            log.warning(alert["message"])
        else:
            log.info(alert["message"])

        send_alert(alert)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle("MODIFIED", event.src_path)

    def on_accessed(self, event):
        if not event.is_directory:
            self._handle("READ", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._handle("CREATED", event.src_path)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    log.info("=== Cookie File Monitor démarré ===")
    observer = Observer()

    for browser, paths in SENSITIVE_PATHS.items():
        for path in paths:
            p = Path(path)
            # Surveille le dossier parent si c'est un fichier, le dossier lui-même sinon
            watch_dir = str(p.parent if p.suffix else p)
            if os.path.exists(watch_dir):
                handler = CookieFileHandler(browser)
                observer.schedule(handler, watch_dir, recursive=True)
                log.info(f"Surveillance active : [{browser}] {watch_dir}")
            else:
                log.warning(f"Chemin introuvable (navigateur non installé ?) : {watch_dir}")

    observer.start()
    try:
        while True:
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        log.info("Arrêt du moniteur.")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()

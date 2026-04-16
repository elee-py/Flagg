"""
client.py — Flagg Client v2.0
==============================
Nouveautés :
  - ThreatReceiver : mini serveur HTTP Flask sur port 5100
    écoute POST /av_threat depuis antivirus_monitor.py
  - ThreatDialog : popup Qt pour chaque menace
      • Détails de la menace (type, niveau, chemin)
      • Résultat VirusTotal (nb moteurs, verdict, lien rapport)
      • Boutons : Supprimer le fichier | Terminer le processus | Ignorer
  - Notifications inline dans les logs (couleurs par niveau)
  - Bouton "Effacer" les logs
"""

import os
import sys
import json
import threading
import webbrowser
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

import psutil
from PyQt6.QtCore import Qt, QProcess, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QPlainTextEdit, QLabel, QFrame,
    QDialog, QDialogButtonBox, QScrollArea, QSizePolicy,
    QMessageBox,
)
from qt_material import apply_stylesheet

BASE_DIR = Path(__file__).resolve().parent

# ──────────────────────────────────────────────
# MODULE RUNNER
# ──────────────────────────────────────────────

class ModuleRunner:
    def __init__(self, name: str, script: str, log_callback):
        self.name = name
        self.script = script
        self.log_callback = log_callback
        self.process = None

    def start(self):
        if self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning:
            self.log_callback(f"[{self.name}] déjà en cours.")
            return
        self.process = QProcess()
        self.process.setProgram(sys.executable)
        self.process.setArguments([str(BASE_DIR / self.script)])
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._finished)
        self.process.start()
        self.log_callback(f"[{self.name}] démarré.")

    def stop(self):
        if self.process is None:
            return
        if self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.terminate()
            self.log_callback(f"[{self.name}] arrêt demandé.")
        else:
            self.log_callback(f"[{self.name}] déjà stoppé.")

    def _read_stdout(self):
        data = self.process.readAllStandardOutput().data().decode(errors="ignore")
        for line in data.splitlines():
            self.log_callback(f"[{self.name}] {line}")

    def _read_stderr(self):
        data = self.process.readAllStandardError().data().decode(errors="ignore")
        for line in data.splitlines():
            self.log_callback(f"[{self.name}][ERR] {line}")

    def _finished(self, code, _):
        self.log_callback(f"[{self.name}] terminé (code={code}).")

# ──────────────────────────────────────────────
# COULEURS MODULES
# ──────────────────────────────────────────────

MODULE_COLORS = {
    "AlertServer":   "#4fd1ff",
    "CookieMonitor": "#a78bfa",
    "NetExfil":      "#34d399",
    "Antivirus":     "#f87171",
}

# ──────────────────────────────────────────────
# DIALOGUE MENACE
# ──────────────────────────────────────────────

LEVEL_COLORS = {"HIGH": "#f87171", "MEDIUM": "#fbbf24", "INFO": "#60a5fa"}

class ThreatDialog(QDialog):
    """
    Popup affiché pour chaque menace reçue depuis antivirus_monitor.
    Propose : Supprimer fichier / Terminer processus / Ignorer.
    """

    def __init__(self, payload: dict, parent=None):
        super().__init__(parent)
        self.payload = payload
        self.setWindowTitle("⚠ Flagg — Menace détectée")
        self.setMinimumWidth(560)
        self.setModal(False)            # non-bloquant : plusieurs popups possibles
        self._build_ui()
        self._apply_styles()

    def _build_ui(self):
        level   = self.payload.get("level", "?")
        type_   = self.payload.get("type", "?")
        message = self.payload.get("message", "")
        details = self.payload.get("details", {})
        ts      = self.payload.get("timestamp", "")
        vt      = details.get("virustotal", {})

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        # ── En-tête niveau ────────────────────
        color = LEVEL_COLORS.get(level, "#e5e7eb")
        header = QLabel(f"  {level}  —  {type_}")
        header.setStyleSheet(
            f"background-color: {color}22; color: {color}; "
            f"border: 1px solid {color}; border-radius: 6px; "
            f"font-weight: 700; font-size: 13px; padding: 6px 10px;"
        )
        layout.addWidget(header)

        # ── Message ───────────────────────────
        msg_lbl = QLabel(message)
        msg_lbl.setWordWrap(True)
        msg_lbl.setStyleSheet("color: #e5e7eb; font-size: 12px;")
        layout.addWidget(msg_lbl)

        # ── Détails scrollable ─────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFixedHeight(130)
        scroll.setStyleSheet("border: 1px solid #1f2933; border-radius: 6px;")

        detail_text = QPlainTextEdit()
        detail_text.setReadOnly(True)
        detail_text.setStyleSheet(
            "background: #020617; color: #9ca3af; "
            "font-family: Consolas, monospace; font-size: 11px; border: none;"
        )
        # Formater les détails sans VT (affiché séparément)
        filtered = {k: v for k, v in details.items() if k != "virustotal"}
        detail_text.setPlainText(
            json.dumps(filtered, indent=2, ensure_ascii=False, default=str)
        )
        scroll.setWidget(detail_text)
        layout.addWidget(scroll)

        # ── Bloc VirusTotal ───────────────────
        if vt:
            vt_frame = QFrame()
            vt_frame.setObjectName("vtFrame")
            vt_layout = QVBoxLayout(vt_frame)
            vt_layout.setContentsMargins(10, 8, 10, 8)
            vt_layout.setSpacing(4)

            vt_title = QLabel("🛡 VirusTotal")
            vt_title.setStyleSheet("color: #4fd1ff; font-weight: 700; font-size: 12px;")
            vt_layout.addWidget(vt_title)

            if vt.get("error") and not vt.get("found"):
                err_lbl = QLabel(f"⚠  {vt['error']}")
                err_lbl.setStyleSheet("color: #fbbf24; font-size: 11px;")
                vt_layout.addWidget(err_lbl)
            else:
                # Verdict
                verdict = vt.get("verdict", "unknown")
                v_color = {"clean": "#34d399", "suspicious": "#fbbf24",
                           "malicious": "#f87171"}.get(verdict, "#9ca3af")
                mal  = vt.get("malicious", 0)
                tot  = vt.get("total", 0)
                v_lbl = QLabel(
                    f"Verdict : <b style='color:{v_color}'>{verdict.upper()}</b>"
                    f"  —  {mal} / {tot} moteurs positifs"
                )
                v_lbl.setStyleSheet("color: #d1d5db; font-size: 12px;")
                v_lbl.setTextFormat(Qt.TextFormat.RichText)
                vt_layout.addWidget(v_lbl)

                # Noms de menaces
                names = vt.get("names", [])
                if names:
                    n_lbl = QLabel("Noms : " + " · ".join(names))
                    n_lbl.setStyleSheet("color: #f87171; font-size: 11px;")
                    n_lbl.setWordWrap(True)
                    vt_layout.addWidget(n_lbl)

                # Lien rapport
                report_url = vt.get("report_url", "")
                if report_url:
                    link = QPushButton("🔗 Voir rapport VirusTotal")
                    link.setFixedHeight(28)
                    link.setCursor(Qt.CursorShape.PointingHandCursor)
                    link.setStyleSheet(
                        "QPushButton { background: transparent; color: #4fd1ff; "
                        "border: 1px solid #4fd1ff44; border-radius: 4px; "
                        "font-size: 11px; padding: 2px 8px; } "
                        "QPushButton:hover { background: #4fd1ff11; }"
                    )
                    link.clicked.connect(lambda: webbrowser.open(report_url))
                    vt_layout.addWidget(link)

            layout.addWidget(vt_frame)

        # ── Horodatage ────────────────────────
        ts_lbl = QLabel(f"🕐 {ts[:19].replace('T', ' ')}")
        ts_lbl.setStyleSheet("color: #4b5563; font-size: 10px;")
        layout.addWidget(ts_lbl)

        # ── Boutons d'action ──────────────────
        btn_layout = QHBoxLayout()

        self.btn_delete  = QPushButton("🗑 Supprimer le fichier")
        self.btn_kill    = QPushButton("💀 Tuer le processus")
        self.btn_ignore  = QPushButton("✓ Ignorer")

        for btn, color in [
            (self.btn_delete, "#f87171"),
            (self.btn_kill,   "#fb923c"),
            (self.btn_ignore, "#34d399"),
        ]:
            btn.setStyleSheet(
                f"QPushButton {{ background: #111827; color: {color}; "
                f"border: 1px solid {color}; border-radius: 6px; "
                f"padding: 7px 14px; font-size: 12px; font-weight: 600; }} "
                f"QPushButton:hover {{ background: #1f2937; }} "
                f"QPushButton:pressed {{ background: #0f172a; }}"
            )
            btn_layout.addWidget(btn)

        # Activer les boutons selon ce qui est disponible
        has_path = bool(details.get("path"))
        has_pid  = bool(details.get("pid"))
        self.btn_delete.setEnabled(has_path)
        self.btn_kill.setEnabled(has_pid)

        self.btn_delete.clicked.connect(self._on_delete)
        self.btn_kill.clicked.connect(self._on_kill)
        self.btn_ignore.clicked.connect(self.accept)

        layout.addLayout(btn_layout)

    def _apply_styles(self):
        self.setStyleSheet("""
        QDialog {
            background-color: #0b0f1a;
        }
        #vtFrame {
            background-color: #0f1729;
            border: 1px solid #1f4068;
            border-radius: 8px;
        }
        QScrollArea { background: transparent; }
        """)

    def _on_delete(self):
        path_str = self.payload.get("details", {}).get("path", "")
        if not path_str:
            return
        path = Path(path_str)

        confirm = QMessageBox(self)
        confirm.setWindowTitle("Confirmer la suppression")
        confirm.setText(
            f"Voulez-vous vraiment supprimer :\n\n{path_str}\n\n"
            "Cette action est irréversible."
        )
        confirm.setIcon(QMessageBox.Icon.Warning)
        confirm.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        confirm.setDefaultButton(QMessageBox.StandardButton.No)
        confirm.setStyleSheet("""
        QMessageBox { background: #0b0f1a; color: #e5e7eb; }
        QLabel { color: #e5e7eb; }
        QPushButton {
            background: #111827; color: #f87171;
            border: 1px solid #f87171; border-radius: 5px; padding: 5px 14px;
        }
        QPushButton:hover { background: #1f2937; }
        """)

        if confirm.exec() == QMessageBox.StandardButton.Yes:
            try:
                path.unlink(missing_ok=True)
                QMessageBox.information(
                    self, "Supprimé",
                    f"Fichier supprimé avec succès :\n{path_str}",
                )
                self.accept()
            except PermissionError:
                QMessageBox.critical(
                    self, "Erreur",
                    f"Impossible de supprimer le fichier (permissions) :\n{path_str}\n\n"
                    "Essayez en tant qu'administrateur.",
                )
            except Exception as e:
                QMessageBox.critical(self, "Erreur", str(e))

    def _on_kill(self):
        pid = self.payload.get("details", {}).get("pid")
        if pid is None:
            return
        confirm = QMessageBox(self)
        confirm.setWindowTitle("Confirmer la terminaison")
        confirm.setText(f"Tuer le processus PID {pid} ?")
        confirm.setIcon(QMessageBox.Icon.Warning)
        confirm.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        confirm.setStyleSheet("""
        QMessageBox { background: #0b0f1a; color: #e5e7eb; }
        QLabel { color: #e5e7eb; }
        QPushButton {
            background: #111827; color: #fb923c;
            border: 1px solid #fb923c; border-radius: 5px; padding: 5px 14px;
        }
        QPushButton:hover { background: #1f2937; }
        """)
        if confirm.exec() == QMessageBox.StandardButton.Yes:
            try:
                psutil.Process(pid).terminate()
                QMessageBox.information(self, "Terminé", f"Processus {pid} tué.")
                self.accept()
            except psutil.NoSuchProcess:
                QMessageBox.information(self, "Info", "Processus déjà terminé.")
                self.accept()
            except psutil.AccessDenied:
                QMessageBox.critical(self, "Erreur",
                                     "Permission refusée. Lancez Flagg en administrateur.")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", str(e))

# ──────────────────────────────────────────────
# THREAT RECEIVER (HTTP server thread-safe)
# ──────────────────────────────────────────────

class ThreatSignal(QObject):
    """Objet Qt pour émettre un signal depuis le thread HTTP vers le thread principal."""
    threat_received = pyqtSignal(dict)


_threat_signal = ThreatSignal()


def _make_handler(signal: ThreatSignal):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/av_threat":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                payload = json.loads(body.decode())
                signal.threat_received.emit(payload)
            except Exception:
                pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, fmt, *args):
            pass  # silencieux

    return Handler


def start_threat_receiver(signal: ThreatSignal, port: int = 5100):
    """Lance le mini serveur HTTP dans un thread daemon."""
    handler  = _make_handler(signal)
    server   = HTTPServer(("127.0.0.1", port), handler)
    thread   = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

# ──────────────────────────────────────────────
# MODULE ROW
# ──────────────────────────────────────────────

class ModuleRow(QWidget):
    def __init__(self, key: str, module: ModuleRunner, accent: str, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(8)

        dot = QLabel("●")
        dot.setStyleSheet(f"color: {accent}; font-size: 10px;")
        dot.setFixedWidth(14)

        lbl = QLabel(key)
        lbl.setStyleSheet("color: #d1d5db; font-size: 12px;")

        btn_start = QPushButton("Start")
        btn_stop  = QPushButton("Stop")
        btn_start.setFixedWidth(54)
        btn_stop.setFixedWidth(54)
        btn_start.setStyleSheet(self._btn_style(accent))
        btn_stop.setStyleSheet(self._btn_stop_style())

        btn_start.clicked.connect(module.start)
        btn_stop.clicked.connect(module.stop)

        layout.addWidget(dot)
        layout.addWidget(lbl)
        layout.addStretch()
        layout.addWidget(btn_start)
        layout.addWidget(btn_stop)

    @staticmethod
    def _btn_style(accent: str) -> str:
        return (
            f"QPushButton {{ background: #111827; color: {accent}; "
            f"border-radius: 5px; padding: 4px 8px; border: 1px solid {accent}; "
            f"font-size: 11px; }}"
            f"QPushButton:hover {{ background: #1f2937; }}"
            f"QPushButton:pressed {{ background: #0f172a; }}"
        )

    @staticmethod
    def _btn_stop_style() -> str:
        return (
            "QPushButton { background: #111827; color: #9ca3af; border-radius: 5px; "
            "padding: 4px 8px; border: 1px solid #374151; font-size: 11px; }"
            "QPushButton:hover { background: #1f2937; border-color: #f87171; color: #f87171; }"
            "QPushButton:pressed { background: #0f172a; }"
        )

# ──────────────────────────────────────────────
# MAIN WINDOW
# ──────────────────────────────────────────────

class FlaggClient(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Flagg — Client Mod")
        self.resize(1150, 700)

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Sidebar ───────────────────────────
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(275)
        sl = QVBoxLayout(sidebar)
        sl.setContentsMargins(16, 20, 16, 16)

        title = QLabel("FLAGG")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setObjectName("titleLabel")

        subtitle = QLabel("Monitoring client")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setObjectName("subtitleLabel")

        sl.addWidget(title)
        sl.addWidget(subtitle)
        sl.addSpacing(24)

        sep1 = QLabel("MODULES")
        sep1.setStyleSheet("color: #4b5563; font-size: 10px; letter-spacing: 2px;")
        sl.addWidget(sep1)
        sl.addSpacing(6)

        self.modules = {
            "AlertServer":   ModuleRunner("AlertServer",   "alert_server.py",         self.append_log),
            "CookieMonitor": ModuleRunner("CookieMonitor", "cookie_file_monitor.py",   self.append_log),
            "NetExfil":      ModuleRunner("NetExfil",      "network_exfil_monitor.py", self.append_log),
            "Antivirus":     ModuleRunner("Antivirus",     "antivirus_monitor.py",     self.append_log),
        }
        for key, mod in self.modules.items():
            sl.addWidget(ModuleRow(key, mod, MODULE_COLORS[key]))

        sl.addSpacing(24)
        sep2 = QLabel("CONTRÔLES GLOBAUX")
        sep2.setStyleSheet("color: #4b5563; font-size: 10px; letter-spacing: 2px;")
        sl.addWidget(sep2)
        sl.addSpacing(6)

        self.btn_start_all = QPushButton("▶  Start ALL")
        self.btn_stop_all  = QPushButton("■  Stop ALL")
        self.btn_start_all.clicked.connect(self.start_all)
        self.btn_stop_all.clicked.connect(self.stop_all)
        self.btn_start_all.setStyleSheet(self._global_btn_style("#4fd1ff"))
        self.btn_stop_all.setStyleSheet(self._global_btn_style("#f87171"))
        sl.addWidget(self.btn_start_all)
        sl.addSpacing(6)
        sl.addWidget(self.btn_stop_all)
        sl.addStretch()

        ver = QLabel("v2.0 — Flagg")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver.setStyleSheet("color: #374151; font-size: 10px;")
        sl.addWidget(ver)

        # ── Zone logs ─────────────────────────
        center = QFrame()
        center.setObjectName("centerFrame")
        cl = QVBoxLayout(center)
        cl.setContentsMargins(16, 16, 16, 16)

        log_header = QHBoxLayout()
        log_title = QLabel("Logs / Alerts")
        log_title.setObjectName("logTitle")
        self.btn_clear = QPushButton("Effacer")
        self.btn_clear.setFixedWidth(80)
        self.btn_clear.clicked.connect(self.log_box_clear)
        self.btn_clear.setStyleSheet(
            "QPushButton { background: #111827; color: #6b7280; border-radius: 5px; "
            "padding: 4px 8px; border: 1px solid #374151; font-size: 11px; } "
            "QPushButton:hover { border-color: #9ca3af; color: #d1d5db; }"
        )
        log_header.addWidget(log_title)
        log_header.addStr
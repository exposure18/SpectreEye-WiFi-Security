# main.py
import sys
import os
import json
from datetime import datetime
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QPixmap, QColor
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFrame, QStackedWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QListWidget, QFileDialog, QMessageBox,
    QComboBox
)
import qtawesome as qa

# Import your existing modules (scanner.py & analysis.py)
# Make sure those files are in the same folder
try:
    from scanner import scan_networks  # expects function returning {"error":..., "networks":[...]}
except Exception:
    # graceful fallback if import fails during editing demo
    def scan_networks():
        return {"error": "scanner.py not found or failed to import", "networks": []}

try:
    from analysis import analyze_network  # expects function(network) -> (severity, suggestion)
except Exception:
    def analyze_network(n):
        return ("Low", "No analysis available - analysis.py missing.")

# ---------- Styling ----------
APP_NAME = "SpectreEye Wi-Fi Security"
ACCENT = "#00bfa6"
BG = "#121314"
SIDEBAR_BG = "#161718"
CARD_BG = "#1d1f20"
TEXT = "#E9EEF1"
MUTED = "#9aa3a8"

STYLE = f"""
QMainWindow {{ background: {BG}; color: {TEXT}; }}
QWidget {{ color: {TEXT}; font-family: "Segoe UI", Roboto, Arial; }}
#sidebar {{ background: {SIDEBAR_BG}; border-right: 1px solid #222; }}
QPushButton#navbtn {{
    color: {TEXT};
    background: transparent;
    border: none;
    text-align: left;
    padding: 10px 18px;
    font-size: 14px;
}}
QPushButton#navbtn:hover {{ background: rgba(255,255,255,0.02); }}
QPushButton#navbtn[active="true"] {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {ACCENT}33, stop:1 {ACCENT}11);
    border-left: 4px solid {ACCENT};
}}
#titleLabel {{ font-size: 18px; font-weight: 700; color: white; }}
#card {{ background: {CARD_BG}; border-radius: 8px; padding: 12px; }}
QTableWidget {{
    background: transparent;
    gridline-color: #2a2c2d;
    color: {TEXT};
}}
QHeaderView::section {{ background: #232425; padding: 6px; border: none; color: {TEXT}; }}
QTableWidget::item:selected {{ background: {ACCENT}22; }}
QTextEdit {{ background: #151617; color: {TEXT}; border-radius: 6px; padding: 8px; }}
QListWidget {{ background: #151617; color: {TEXT}; border-radius: 6px; padding: 8px; }}
QComboBox {{ background: #151617; color: {TEXT}; padding: 6px; border-radius: 4px; }}
"""

# ---------- HTML Report Template ----------
HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Spectre Wi-Fi Report - {{ ts }}</title>
  <style>
    body {{ font-family: Arial, sans-serif; padding: 24px; background: #f6f8fa; color: #222; }}
    h1 {{ color: #006e60; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f1f3f4; }}
    .high {{ background: #ffe6e6; }}
    .medium {{ background: #fff7e0; }}
    .low {{ background: #e8fff0; }}
  </style>
</head>
<body>
  <h1>Spectre — Wi-Fi Security Audit</h1>
  <p>Generated: {{ ts }}</p>
  <table>
    <thead><tr><th>SSID</th><th>BSSID</th><th>Auth</th><th>Encryption</th><th>Signal</th><th>Severity</th><th>Suggestion</th></tr></thead>
    <tbody>
      {% for r in results %}
      <tr class="{{ r.Severity|lower }}">
        <td>{{ r.SSID }}</td><td>{{ r.BSSID }}</td><td>{{ r.Auth }}</td><td>{{ r.Encryption }}</td><td>{{ r.Signal }}</td><td>{{ r.Severity }}</td><td>{{ r.Suggestion }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</body>
</html>
"""

# ---------- App ----------
class SpectreMain(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1150, 720)
        self.setStyleSheet(STYLE)

        # central widget & main layout
        central = QWidget()
        main_layout = QHBoxLayout()
        central.setLayout(main_layout)
        self.setCentralWidget(central)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(285)
        side_layout = QVBoxLayout()
        side_layout.setContentsMargins(12, 12, 12, 12)
        side_layout.setSpacing(8)
        sidebar.setLayout(side_layout)

        # Logo + title area
        logo_path = self._find_logo()
        logo_area = QWidget()
        la = QHBoxLayout()
        la.setContentsMargins(0, 0, 0, 0)
        logo_area.setLayout(la)
        if logo_path:
            pix = QPixmap(logo_path).scaled(36, 36, Qt.AspectRatioMode.KeepAspectRatio,
                                            Qt.TransformationMode.SmoothTransformation)
            logo_lbl = QLabel()
            logo_lbl.setPixmap(pix)
            la.addWidget(logo_lbl, alignment=Qt.AlignmentFlag.AlignLeft)
        title = QLabel("SpectreEye Wi-Fi Security")
        title.setObjectName("titleLabel")
        la.addWidget(title)
        side_layout.addWidget(logo_area)

        # nav buttons
        self.btn_dashboard = QPushButton("  Dashboard")
        self.btn_dashboard.setObjectName("navbtn")
        self.btn_dashboard.clicked.connect(lambda: self.switch_page(0))
        self.btn_scanner = QPushButton("  Scanner")
        self.btn_scanner.setObjectName("navbtn")
        self.btn_scanner.clicked.connect(lambda: self.switch_page(1))

        # Add nav and stretch
        for b in (self.btn_dashboard, self.btn_scanner):
            b.setCheckable(True)
            side_layout.addWidget(b)

        side_layout.addStretch()
        # small footer
        footer = QLabel("Spectre • Passive Auditor")
        footer.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        side_layout.addWidget(footer, alignment=Qt.AlignmentFlag.AlignLeft)

        # Right area (stack)
        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background: transparent;")
        # pages
        self.page_dashboard = self._build_dashboard()
        self.page_scanner = self._build_scanner()

        for p in (self.page_dashboard, self.page_scanner):
            self.stack.addWidget(p)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.stack, stretch=1)

        # set initial active nav
        self._set_active(self.btn_dashboard)

        # internal state
        self.scan_history = []  # list of results
        self._refresh_dashboard()

    def _find_logo(self):
        # Look for resources/logo.{png,jpg}
        base = os.path.join(os.path.dirname(__file__), "resources")
        for name in ("logo.png", "logo.jpg", "logo.jpeg"):
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return p
        return None

    def _set_active(self, btn):
        # mark nav active/others not
        for b in (self.btn_dashboard, self.btn_scanner):
            b.setProperty("active", "true" if b is btn else "false")
            b.style().unpolish(b)
            b.style().polish(b)

    def switch_page(self, idx):
        # animate the page change: fade out then in
        old_idx = self.stack.currentIndex()
        if old_idx == idx:
            return
        self._set_active([self.btn_dashboard, self.btn_scanner][idx])
        # simple slide animation
        w_old = self.stack.widget(old_idx)
        w_new = self.stack.widget(idx)
        # set and animate a geometry-based slide
        direction = 1 if idx > old_idx else -1
        rect = self.stack.geometry()
        anim_old = QPropertyAnimation(w_old, b"geometry")
        anim_old.setDuration(240)
        anim_old.setEasingCurve(QEasingCurve.Type.InOutCubic)
        anim_old.setStartValue(rect)
        anim_old.setEndValue(rect.translated(-direction * rect.width(), 0))

        anim_new = QPropertyAnimation(w_new, b"geometry")
        anim_new.setDuration(240)
        anim_new.setEasingCurve(QEasingCurve.Type.InOutCubic)
        anim_new.setStartValue(rect.translated(direction * rect.width(), 0))
        anim_new.setEndValue(rect)

        # ensure new widget visible
        self.stack.setCurrentIndex(idx)
        anim_old.start()
        anim_new.start()

        # FIX: Refresh dashboard content when navigating back to it
        if idx == 0:
            self._refresh_dashboard()

    # ---------- Pages ----------
    def _build_dashboard(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        page.setLayout(layout)

        header = QLabel("Overview")
        header.setStyleSheet("font-size: 20px; font-weight: 700;")
        layout.addWidget(header)

        cards = QHBoxLayout()
        # stat cards
        self.card_total = self._make_card("Total networks", "0")
        self.card_vuln = self._make_card("Vulnerable (High/Medium)", "0")
        self.card_last = self._make_card("Last scan", "—")
        cards.addWidget(self.card_total)
        cards.addWidget(self.card_vuln)
        cards.addWidget(self.card_last)
        layout.addLayout(cards)

        # small graph placeholder (we'll put a table summary)
        layout.addSpacing(12)
        summary_title = QLabel("Recent Scan Summary")
        summary_title.setStyleSheet("font-weight: 600;")
        layout.addWidget(summary_title)

        self.summary_list = QListWidget()
        self.summary_list.setFixedHeight(320)
        layout.addWidget(self.summary_list)

        layout.addStretch()
        return page

    def _make_card(self, title, value):
        w = QFrame()
        w.setObjectName("card")
        w.setMinimumHeight(90)
        l = QVBoxLayout()
        l.setContentsMargins(10, 10, 10, 10)
        t = QLabel(title)
        t.setStyleSheet("color: " + MUTED + "; font-size: 12px;")
        v = QLabel(value)
        v.setStyleSheet("font-size: 20px; font-weight: 700; color: white;")
        l.addWidget(t)
        l.addWidget(v)
        w.setLayout(l)
        # store value label reference
        w.value_label = v
        return w

    def _build_scanner(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        page.setLayout(layout)

        title_area = QHBoxLayout()
        title = QLabel("Scanner")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        title_area.addWidget(title)
        title_area.addStretch()
        self.btn_scan = QPushButton("Scan Networks")
        self.btn_scan.setIcon(qa.icon("fa5s.wifi"))
        self.btn_scan.clicked.connect(self.do_scan)
        self.btn_export = QPushButton("Export HTML Report")
        self.btn_export.setIcon(qa.icon("fa5s.file-export"))
        self.btn_export.clicked.connect(self.export_report)
        title_area.addWidget(self.btn_scan)
        title_area.addWidget(self.btn_export)
        layout.addLayout(title_area)

        # table
        self.tbl = QTableWidget(0, 6)
        self.tbl.setHorizontalHeaderLabels(["SSID", "BSSID", "Auth", "Encryption", "Signal", "Severity"])
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setSelectionBehavior(self.tbl.SelectionBehavior.SelectRows)
        self.tbl.setEditTriggers(self.tbl.EditTrigger.NoEditTriggers)
        self.tbl.cellClicked.connect(self._on_table_click)
        layout.addWidget(self.tbl, stretch=1)

        # detail pane
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setFixedHeight(170)
        layout.addWidget(self.detail)

        return page

    # ---------- Actions ----------
    def do_scan(self):
        # Indicate scan is in progress
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("Scanning...")
        self.btn_scan.setIcon(qa.icon("fa5s.sync", animation=qa.Spin(self.btn_scan)))
        self.detail.clear()
        self.tbl.setRowCount(0)
        self.detail.append("Scanning networks... (this uses Windows netsh under the hood)")

        QtCore.QCoreApplication.processEvents()
        data = scan_networks()

        # Reset button and UI
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("Scan Networks")
        self.btn_scan.setIcon(qa.icon("fa5s.wifi"))

        if data.get("error"):
            QMessageBox.critical(self, "Scan Error", f"Scan failed:\n{data['error']}")
            return

        networks = data.get("networks", [])
        if not networks:
            QMessageBox.information(self, "No Networks", "No Wi-Fi networks detected.")
            return

        results = []
        for n in networks:
            sev, sug = analyze_network(n)
            row = {
                "SSID": n.get("SSID", ""),
                "BSSID": n.get("BSSID", ""),
                "Auth": n.get("Auth", ""),
                "Encryption": n.get("Encryption", ""),
                "Signal": n.get("Signal", ""),
                "Channel": n.get("Channel", ""),
                "Severity": sev,
                "Suggestion": sug,
                "first_seen": n.get("first_seen", datetime.now().isoformat())
            }
            results.append(row)
        # update table
        self._populate_table(results)
        # update details & dashboard
        ts = datetime.now().isoformat(sep=' ', timespec='seconds')
        summary = f"Scan completed: {ts}\nFound {len(results)} networks."
        self.detail.append(summary)
        # push to history (no longer persistent)
        self.scan_history.insert(0, {"ts": ts, "results": results})
        self._refresh_dashboard()

    def _populate_table(self, results):
        self.current_results = results
        self.tbl.setRowCount(len(results))
        for i, r in enumerate(results):
            self.tbl.setItem(i, 0, QTableWidgetItem(r["SSID"]))
            self.tbl.setItem(i, 1, QTableWidgetItem(r["BSSID"]))
            self.tbl.setItem(i, 2, QTableWidgetItem(r["Auth"]))
            self.tbl.setItem(i, 3, QTableWidgetItem(r["Encryption"]))
            self.tbl.setItem(i, 4, QTableWidgetItem(str(r["Signal"])))
            it = QTableWidgetItem(r["Severity"])
            it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.tbl.setItem(i, 5, it)

    def _on_table_click(self, row, col):
        if not hasattr(self, "current_results"):
            return
        r = self.current_results[row]
        self.detail.clear()
        self.detail.append(
            f"SSID: {r['SSID']}\nBSSID: {r['BSSID']}\nAuth: {r['Auth']}\nEncryption: {r['Encryption']}\nSignal: {r['Signal']}\nChannel: {r.get('Channel', '')}\n\nSeverity: {r['Severity']}\n\nMitigation Suggestion:\n{r['Suggestion']}")

    def export_report(self):
        if not hasattr(self, "current_results") or not self.current_results:
            QMessageBox.information(self, "No Data", "Run a scan first.")
            return
        # render template
        try:
            from jinja2 import Template
        except Exception:
            QMessageBox.critical(self, "Missing Dependency", "Please install jinja2: pip install jinja2")
            return
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tmpl = Template(HTML_TEMPLATE)
        html = tmpl.render(ts=ts, results=self.current_results)
        path, _ = QFileDialog.getSaveFileName(self, "Save report", os.path.expanduser("~"), "HTML Files (*.html)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            QMessageBox.information(self, "Exported", f"Report saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Could not save report:\n{e}")

    # ---------- Dashboard refresh ----------
    def _refresh_dashboard(self):
        total = sum(len(e.get("results", [])) for e in self.scan_history)
        vuln = 0
        last_ts = "—"
        if self.scan_history:
            for e in self.scan_history:
                for r in e.get("results", []):
                    if r.get("Severity") in ("High", "Medium"):
                        vuln += 1
            last_ts = self.scan_history[0].get("ts", "—")
        self.card_total.value_label.setText(str(total))
        self.card_vuln.value_label.setText(str(vuln))
        self.card_last.value_label.setText(last_ts)
        # populate summary list (recent few)
        self.summary_list.clear()
        for e in self.scan_history[:8]:
            ts = e.get("ts", "")
            count = len(e.get("results", []))
            self.summary_list.addItem(f"{ts} — {count} networks")

def main():
    app = QApplication(sys.argv)
    window = SpectreMain()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
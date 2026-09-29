"""
╔══════════════════════════════════════════════════════════════╗
║          DASHBOARD VIEW                                      ║
║  Live clock · 3D Cesium globe · Manipulation gauge · stats   ║
╚══════════════════════════════════════════════════════════════╝
"""
from pathlib import Path

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QFrame,
    QScrollArea
)

try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtWebEngineCore import QWebEngineSettings
    WEB_OK = True
except ImportError:
    WEB_OK = False

from config.settings import (
    T, CESIUM_ION_TOKEN, MAPTILER_KEY, RESOURCE_DIR, FONT_MONO, FONT_MONO_ALT,
    APP_CODENAME
)
from .widgets import LiveClock, ScoreGauge, StatCard, MiniBar, SeverityPill


class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("DashboardView")
        self._build()
        self._last_result = None

    # ─── UI ────────────────────────────────────────────────────────────
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(12)

        # Header: codename + clock
        header = QFrame()
        header.setObjectName("Panel")
        header.setMinimumHeight(84)
        header_l = QHBoxLayout(header)
        header_l.setContentsMargins(14, 6, 14, 6)
        header_l.setSpacing(18)

        left_col = QVBoxLayout()
        left_col.setSpacing(0)
        l1 = QLabel("OPERATION DESIGNATION")
        l1.setObjectName("CardTitle")
        l2 = QLabel(f"▶ {APP_CODENAME}  ·  FILE-FORENSIC INTELLIGENCE SUITE")
        l2.setStyleSheet(
            f"color:{T['accent']}; font-size:13pt; font-weight:bold; letter-spacing:2px;"
            f"font-family:'{FONT_MONO}','{FONT_MONO_ALT}',monospace;"
        )
        l3 = QLabel("TIER-1 · CLEAR-EYES · OPERATOR-GRADE FORENSIC TELEMETRY")
        l3.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt; letter-spacing:2px;")
        left_col.addWidget(l1)
        left_col.addWidget(l2)
        left_col.addWidget(l3)
        header_l.addLayout(left_col, stretch=2)

        self.clock = LiveClock(self)
        header_l.addWidget(self.clock, stretch=1)

        root.addWidget(header)

        # Main grid
        grid_wrap = QHBoxLayout()
        grid_wrap.setSpacing(12)

        # LEFT — score gauge + findings panel
        left_panel = QFrame()
        left_panel.setObjectName("Panel")
        left_panel.setMinimumWidth(320)
        left_panel.setMaximumWidth(360)
        lp_lay = QVBoxLayout(left_panel)
        lp_lay.setContentsMargins(10, 10, 10, 10)
        lp_lay.setSpacing(8)

        hdr = QLabel("▸  MANIPULATION ASSESSMENT")
        hdr.setObjectName("SectionHeader")
        lp_lay.addWidget(hdr)

        self.gauge = ScoreGauge(size=240)
        lp_lay.addWidget(self.gauge, alignment=Qt.AlignmentFlag.AlignCenter)

        # Verdict strip
        self.lbl_verdict = QLabel("—  AWAITING FILE INPUT  —")
        self.lbl_verdict.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_verdict.setStyleSheet(
            f"color:{T['text_dim']}; font-size:9pt; letter-spacing:3px; "
            f"padding:6px; border-top:1px solid {T['border']};"
            f"border-bottom:1px solid {T['border']}; font-weight:bold;"
        )
        lp_lay.addWidget(self.lbl_verdict)

        # Top signals list
        sig_hdr = QLabel("▸  TOP SIGNALS")
        sig_hdr.setObjectName("SectionHeader")
        lp_lay.addWidget(sig_hdr)

        self.findings_frame = QFrame()
        self.findings_frame.setObjectName("Card")
        self.findings_layout = QVBoxLayout(self.findings_frame)
        self.findings_layout.setContentsMargins(8, 8, 8, 8)
        self.findings_layout.setSpacing(5)
        self._empty_findings_label()

        scroll = QScrollArea()
        scroll.setWidget(self.findings_frame)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(f"background:{T['panel']};")
        lp_lay.addWidget(scroll, stretch=1)

        grid_wrap.addWidget(left_panel)

        # CENTER — globe
        center_panel = QFrame()
        center_panel.setObjectName("Panel")
        cp_lay = QVBoxLayout(center_panel)
        cp_lay.setContentsMargins(10, 10, 10, 10)
        cp_lay.setSpacing(6)

        globe_hdr = QLabel("▸  SENTINEL GEO-TRACK  ·  LIVE GLOBE")
        globe_hdr.setObjectName("SectionHeader")
        cp_lay.addWidget(globe_hdr)

        if WEB_OK:
            self.web = QWebEngineView()
            s = self.web.settings()
            s.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
            s.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
            s.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, True)
            s.setAttribute(QWebEngineSettings.WebAttribute.AllowRunningInsecureContent, True)
            s.setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, True)
            s.setAttribute(QWebEngineSettings.WebAttribute.Accelerated2dCanvasEnabled, True)
            s.setAttribute(QWebEngineSettings.WebAttribute.ErrorPageEnabled, False)
            self._load_globe()
            self.web.setMinimumHeight(380)
            cp_lay.addWidget(self.web, stretch=1)
        else:
            warn = QLabel(
                "⚠  PyQt6-WebEngine not installed.\n"
                "    Install with:  pip install PyQt6-WebEngine\n"
                "    3D globe will be available after restart."
            )
            warn.setStyleSheet(
                f"color:{T['warn']}; padding:40px; background:{T['card']};"
                f"border:1px solid {T['warn']}; letter-spacing:1px; font-size:10pt;"
            )
            warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cp_lay.addWidget(warn, stretch=1)

        grid_wrap.addWidget(center_panel, stretch=2)
        root.addLayout(grid_wrap, stretch=1)

        # Bottom stat grid
        stat_grid = QGridLayout()
        stat_grid.setSpacing(10)

        self.card_file     = StatCard("FILE",        "—",  "no file loaded")
        self.card_size     = StatCard("SIZE",        "—",  "bytes / human-readable")
        self.card_type     = StatCard("TYPE",        "—",  "detected category · magic")
        self.card_hash     = StatCard("SHA-256",     "—",  "cryptographic digest",
                                      color=T['cyan'])
        self.card_signals  = StatCard("SIGNALS",     "0",  "heuristic findings",
                                      color=T['accent'])
        self.card_ai       = StatCard("OLLAMA",      "…",  "probing local AI",
                                      color=T['text_dim'])

        stats = [
            self.card_file, self.card_size, self.card_type,
            self.card_hash, self.card_signals, self.card_ai,
        ]
        for i, card in enumerate(stats):
            stat_grid.addWidget(card, 0, i)

        root.addLayout(stat_grid)

    # ─── Findings list helpers ────────────────────────────────────────
    def _clear_findings_layout(self):
        while self.findings_layout.count():
            item = self.findings_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _empty_findings_label(self):
        self._clear_findings_layout()
        lbl = QLabel("  No signals — run an analysis to populate this panel.")
        lbl.setStyleSheet(
            f"color:{T['text_mute']}; font-size:9pt; padding:10px 4px;"
        )
        lbl.setWordWrap(True)
        self.findings_layout.addWidget(lbl)
        self.findings_layout.addStretch(1)

    # ─── Cesium globe loader ──────────────────────────────────────────
    def _load_globe(self):
        """
        Render the Cesium HTML template with tokens substituted, then write
        to a cached file and load via file:// URL. Loading via load() rather
        than setHtml() gives WebEngine a real origin, which is required for
        remote tile services (MapTiler, OSM, Cesium Ion) to work.
        """
        from config.settings import CACHE_DIR
        src = Path(RESOURCE_DIR) / "cesium_globe.html"
        out = Path(CACHE_DIR) / "cesium_globe.rendered.html"
        try:
            html = src.read_text(encoding="utf-8")
            html = html.replace("__CESIUM_TOKEN__", CESIUM_ION_TOKEN)
            html = html.replace("__MAPTILER_KEY__", MAPTILER_KEY)
            out.write_text(html, encoding="utf-8")
            self.web.load(QUrl.fromLocalFile(str(out.resolve())))
        except Exception as e:
            self.web.setHtml(
                f"<html><body style='background:#05070a;color:#ff4d6d;"
                f"font-family:monospace;padding:40px;'>Globe load failed: {e}</body></html>"
            )

    # ─── Public API ───────────────────────────────────────────────────
    def set_ollama_status(self, ok, info):
        color = T['ok'] if ok else T['err']
        label = "ONLINE" if ok else "OFFLINE"
        self.card_ai.set_value(label, info, color=color)

    def load_result(self, result):
        """result = dict from engines.run_forensic()"""
        self._last_result = result

        fi = result.get("file") or {}
        self.card_file.set_value(
            (fi.get("name") or "—")[:24],
            (fi.get("path") or "")[-40:],
        )
        self.card_size.set_value(
            fi.get("size_h", "—"),
            f"{fi.get('size', 0):,} bytes" if fi.get("size") else "—",
        )

        magic = result.get("magic") or ("—", "—", "")
        self.card_type.set_value(
            result.get("kind", "—").upper(),
            f"{magic[0]}/{magic[1]}  ·  {magic[2][:24]}",
        )

        hashes = result.get("hashes") or {}
        sha = hashes.get("sha256", "—")
        self.card_hash.set_value(sha[:14] + "…", f"MD5 {hashes.get('md5','—')[:16]}…")

        score = result.get("score") or {}
        if score:
            self.gauge.set_score(score.get("score", 0),
                                 score.get("level", "—"),
                                 score.get("color", T['text_mute']))
            self.card_signals.set_value(
                str(score.get("total_signals", 0)),
                f"Top weight {score.get('top', [{}])[0].get('weight', 0) if score.get('top') else 0}",
                color=score.get("color", T['accent'])
            )
            verdict = score.get("level", "—")
            vcolor  = score.get("color", T['text_dim'])
            th = result.get("threat") or {}
            self.lbl_verdict.setText(f"  VERDICT  ·  {verdict}  ")
            # Bereiche + Kernaussage als Tooltip: das Label ist schmal
            if th.get("families"):
                self.lbl_verdict.setToolTip(" · ".join(th["families"]) + "\n" + th.get("headline", ""))
            self.lbl_verdict.setStyleSheet(
                f"color:{vcolor}; font-size:9pt; letter-spacing:3px; "
                f"padding:6px; border-top:1px solid {vcolor};"
                f"border-bottom:1px solid {vcolor}; font-weight:bold;"
            )
            self._populate_findings(score)
        else:
            self.gauge.reset()
            self.card_signals.set_value("0", "—")
            self.lbl_verdict.setText("—  ANALYSIS FAILED  —")
            self._empty_findings_label()

    def reset(self):
        self._last_result = None
        self.gauge.reset()
        for card, title, sub in [
            (self.card_file,    "—", "no file loaded"),
            (self.card_size,    "—", "bytes / human-readable"),
            (self.card_type,    "—", "detected category · magic"),
            (self.card_hash,    "—", "cryptographic digest"),
            (self.card_signals, "0", "heuristic findings"),
        ]:
            card.set_value(title, sub)
        self.lbl_verdict.setText("—  AWAITING FILE INPUT  —")
        self.lbl_verdict.setStyleSheet(
            f"color:{T['text_dim']}; font-size:9pt; letter-spacing:3px; "
            f"padding:6px; border-top:1px solid {T['border']};"
            f"border-bottom:1px solid {T['border']}; font-weight:bold;"
        )
        self._empty_findings_label()

    # ─── Populate findings list ───────────────────────────────────────
    def _populate_findings(self, score):
        self._clear_findings_layout()
        findings = score.get("findings") or []
        if not findings:
            self._empty_findings_label()
            return

        # Sort by weight desc
        findings = sorted(findings, key=lambda f: f.get("weight", 0), reverse=True)
        max_w = max(f.get("weight", 1) for f in findings) or 1

        for f in findings[:30]:
            row = QFrame()
            row.setStyleSheet(
                f"background:{T['bg']}; border:1px solid {T['border']}; padding:2px;"
            )
            rl = QVBoxLayout(row)
            rl.setContentsMargins(8, 6, 8, 6)
            rl.setSpacing(3)

            top_row = QHBoxLayout()
            top_row.setSpacing(6)

            pill = SeverityPill(f.get("severity", "INFO"))
            top_row.addWidget(pill)

            code = QLabel(f.get("code", "?").upper())
            code.setStyleSheet(
                f"color:{T['cyan']}; font-size:8pt; font-weight:bold; letter-spacing:1.5px;"
            )
            top_row.addWidget(code)
            top_row.addStretch(1)

            w = QLabel(f"+{f.get('weight', 0):.1f}")
            w.setStyleSheet(
                f"color:{T['accent']}; font-size:8pt; font-weight:bold;"
            )
            top_row.addWidget(w)

            rl.addLayout(top_row)

            desc = QLabel(f.get("desc", ""))
            desc.setWordWrap(True)
            desc.setStyleSheet(
                f"color:{T['text']}; font-size:8pt;"
            )
            rl.addWidget(desc)

            bar = MiniBar(
                f.get("weight", 0), max_w,
                color={
                    "CRIT": T['err'], "WARN": T['warn'],
                    "INFO": T['info'], "OK": T['ok'],
                }.get(f.get("severity", "INFO"), T['info'])
            )
            rl.addWidget(bar)

            self.findings_layout.addWidget(row)

        self.findings_layout.addStretch(1)

    def pin_file_location(self, lon, lat, label):
        """If a file has GPS EXIF, pin it on the globe."""
        if WEB_OK and hasattr(self, "web"):
            import json
            # Werte als JSON übergeben – der Dateiname stammt aus der untersuchten Datei (JS-Injection)
            js = (f"pinLocation({float(lon)}, {float(lat)}, {json.dumps(str(label))}); "
                  f"flyTo({float(lon)}, {float(lat)}, 2500000);")
            self.web.page().runJavaScript(js)

    def show_route(self, route):
        """Bewegungsprofil (core.geo.build_route) auf dem Globus zeichnen."""
        if not (WEB_OK and hasattr(self, "web")):
            return False
        import json
        flags = {leg["to_id"]: leg["flag"] for leg in route.get("legs", [])}
        pts = [{"lon": float(p["lon"]), "lat": float(p["lat"]), "label": str(p["name"]),
                "flag": flags.get(p["id"])} for p in route.get("points", [])]
        self.web.page().runJavaScript(f"window.drawRoute && drawRoute({json.dumps(pts)});")
        return True

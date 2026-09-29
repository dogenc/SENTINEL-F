"""
╔══════════════════════════════════════════════════════════════╗
║        SHARED QT STYLESHEETS — CIA / PALANTIR AESTHETIC      ║
╚══════════════════════════════════════════════════════════════╝
"""
from config.settings import T, FONT_MONO, FONT_MONO_ALT


def qss_main():
    """Global stylesheet applied to the QApplication."""
    return f"""
    * {{
        font-family: "{FONT_MONO}", "{FONT_MONO_ALT}", "Courier New", monospace;
        color: {T['text']};
        outline: 0;
    }}

    QMainWindow, QWidget#RootFrame {{
        background: {T['bg']};
    }}

    /* ── Custom title bar ──────────────────────────────────────────── */
    QWidget#TitleBar {{
        background: {T['bg_alt']};
        border-bottom: 1px solid {T['border']};
    }}
    QLabel#TitleText {{
        color: {T['accent']};
        font-weight: bold;
        letter-spacing: 2px;
        padding-left: 10px;
    }}
    QLabel#TitleVersion {{
        color: {T['text_mute']};
        font-size: 9pt;
        padding-left: 6px;
    }}
    QPushButton#WinBtn {{
        background: transparent;
        color: {T['text_dim']};
        border: none;
        min-width: 38px;
        min-height: 28px;
        font-size: 14pt;
    }}
    QPushButton#WinBtn:hover {{ background: {T['card_hover']}; color: {T['text_hot']}; }}
    QPushButton#WinBtnClose:hover {{ background: {T['err']}; color: #fff; }}

    /* ── Panels & Cards ────────────────────────────────────────────── */
    QFrame#Panel {{
        background: {T['panel']};
        border: 1px solid {T['border']};
        border-radius: 2px;
    }}
    QFrame#Card {{
        background: {T['card']};
        border: 1px solid {T['border']};
        border-radius: 2px;
    }}
    QFrame#CardHot {{
        background: {T['card']};
        border: 1px solid {T['accent_dim']};
        border-radius: 2px;
    }}
    QLabel#CardTitle {{
        color: {T['cyan']};
        font-size: 8pt;
        letter-spacing: 2px;
        font-weight: bold;
        padding: 4px 2px 2px 2px;
    }}
    QLabel#CardValue {{
        color: {T['accent']};
        font-size: 20pt;
        font-weight: bold;
    }}
    QLabel#CardSub {{
        color: {T['text_dim']};
        font-size: 8pt;
    }}

    /* ── Sidebar ───────────────────────────────────────────────────── */
    QWidget#Sidebar {{
        background: {T['bg_alt']};
        border-right: 1px solid {T['border']};
    }}
    QPushButton#NavBtn {{
        background: transparent;
        color: {T['text_dim']};
        border: none;
        border-left: 3px solid transparent;
        padding: 10px 18px;
        text-align: left;
        font-size: 9pt;
        letter-spacing: 2px;
        font-weight: bold;
    }}
    QPushButton#NavBtn:hover {{
        background: {T['card']};
        color: {T['text']};
    }}
    QPushButton#NavBtn:checked {{
        background: {T['card']};
        color: {T['accent']};
        border-left: 3px solid {T['accent']};
    }}
    QLabel#SidebarSection {{
        color: {T['text_mute']};
        font-size: 8pt;
        letter-spacing: 2px;
        padding: 14px 18px 4px 18px;
    }}

    /* ── Buttons ───────────────────────────────────────────────────── */
    QPushButton {{
        background: {T['card']};
        color: {T['text']};
        border: 1px solid {T['border']};
        padding: 7px 14px;
        font-size: 9pt;
        letter-spacing: 1px;
    }}
    QPushButton:hover {{
        background: {T['card_hover']};
        border-color: {T['accent_dim']};
        color: {T['accent']};
    }}
    QPushButton:pressed {{ background: {T['bg_alt']}; }}
    QPushButton:disabled {{ color: {T['text_mute']}; border-color: {T['border']}; }}
    QPushButton#PrimaryBtn {{
        background: {T['accent_dim']};
        color: #000;
        border: 1px solid {T['accent']};
        font-weight: bold;
    }}
    QPushButton#PrimaryBtn:hover {{
        background: {T['accent']};
        color: #000;
    }}
    QPushButton#DangerBtn {{
        background: transparent;
        color: {T['err']};
        border: 1px solid {T['err']};
    }}
    QPushButton#DangerBtn:hover {{ background: {T['err']}; color: #fff; }}

    /* ── Text inputs ───────────────────────────────────────────────── */
    QLineEdit, QPlainTextEdit, QTextEdit {{
        background: {T['bg']};
        color: {T['text']};
        border: 1px solid {T['border']};
        selection-background-color: {T['accent_dim']};
        padding: 4px;
    }}
    QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{
        border-color: {T['accent_dim']};
    }}

    /* ── Lists & trees ─────────────────────────────────────────────── */
    QListWidget, QTreeWidget, QTableWidget {{
        background: {T['bg']};
        color: {T['text']};
        border: 1px solid {T['border']};
        alternate-background-color: {T['bg_alt']};
    }}
    QListWidget::item, QTreeWidget::item {{ padding: 4px; }}
    QListWidget::item:selected, QTreeWidget::item:selected {{
        background: {T['card_hover']};
        color: {T['accent']};
    }}
    QHeaderView::section {{
        background: {T['bg_alt']};
        color: {T['cyan']};
        border: 0;
        border-right: 1px solid {T['border']};
        border-bottom: 1px solid {T['border']};
        padding: 5px;
        font-weight: bold;
        letter-spacing: 1px;
    }}

    /* ── Tabs ──────────────────────────────────────────────────────── */
    QTabWidget::pane {{ border: 1px solid {T['border']}; background: {T['panel']}; }}
    QTabBar::tab {{
        background: {T['bg_alt']};
        color: {T['text_dim']};
        padding: 7px 16px;
        border: 1px solid {T['border']};
        border-bottom: none;
        font-size: 9pt;
        letter-spacing: 1.5px;
    }}
    QTabBar::tab:selected {{
        background: {T['panel']};
        color: {T['accent']};
        border-bottom: 2px solid {T['accent']};
    }}
    QTabBar::tab:hover {{ color: {T['text']}; }}
    QTabWidget#AnalysisTabs QTabBar::tab {{ padding: 7px 9px; letter-spacing: 0.5px; }}

    /* ── Progress ──────────────────────────────────────────────────── */
    QProgressBar {{
        background: {T['bg']};
        border: 1px solid {T['border']};
        text-align: center;
        color: {T['text']};
        height: 14px;
    }}
    QProgressBar::chunk {{
        background: {T['accent_dim']};
    }}

    /* ── Scrollbars ────────────────────────────────────────────────── */
    QScrollBar:vertical, QScrollBar:horizontal {{
        background: {T['bg']}; border: none; width: 8px; height: 8px;
    }}
    QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
        background: {T['border_hot']}; border-radius: 2px;
    }}
    QScrollBar::handle:hover {{ background: {T['accent_dim']}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ background: none; border: none; }}

    /* ── Labels ────────────────────────────────────────────────────── */
    QLabel#Mono {{ font-family: "{FONT_MONO}", monospace; color: {T['text']}; }}
    QLabel#Dim  {{ color: {T['text_dim']}; }}
    QLabel#Cyan {{ color: {T['cyan']}; }}
    QLabel#Accent {{ color: {T['accent']}; }}
    QLabel#SectionHeader {{
        color: {T['cyan']};
        font-size: 8pt;
        font-weight: bold;
        letter-spacing: 2px;
        padding: 8px 4px 4px 4px;
        border-bottom: 1px solid {T['border']};
    }}

    /* ── Combo ─────────────────────────────────────────────────────── */
    QComboBox {{
        background: {T['card']}; color: {T['text']};
        border: 1px solid {T['border']}; padding: 4px 8px;
    }}
    QComboBox:hover {{ border-color: {T['accent_dim']}; }}
    QComboBox QAbstractItemView {{
        background: {T['panel']}; color: {T['text']};
        border: 1px solid {T['accent_dim']};
        selection-background-color: {T['card_hover']};
    }}

    /* ── Status bar ────────────────────────────────────────────────── */
    QWidget#StatusBar {{
        background: {T['bg_alt']};
        border-top: 1px solid {T['border']};
    }}
    QLabel#StatusText {{ color: {T['text_dim']}; font-size: 8pt; letter-spacing: 1px; }}
    QLabel#StatusOK   {{ color: {T['ok']};   font-size: 8pt; font-weight: bold; }}
    QLabel#StatusERR  {{ color: {T['err']};  font-size: 8pt; font-weight: bold; }}
    """

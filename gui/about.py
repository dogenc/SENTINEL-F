"""„Über SENTINEL-F“: Urheber, Lizenz, Entstehung (GPL-3.0 §5(d) + Zusatzbedingung Namensnennung, siehe NOTICE)."""
from PyQt6.QtWidgets import QMessageBox

from config.settings import APP_CODENAME, APP_VERSION

REPO_URL = "https://github.com/dogenc/SENTINEL-F"


def about_html():
    return (
        f"<h3>{APP_CODENAME} v{APP_VERSION}</h3>"
        "<p><b>© 2026 DGKN@Labs</b> · File-forensic intelligence suite</p>"
        "<p>Free software under the <b>GNU General Public License v3.0 or later</b> with an "
        "attribution term (section 7). It comes with <b>absolutely no warranty</b>. "
        "See <code>LICENSE</code> and <code>NOTICE</code> in the program folder, or "
        f"<a href='{REPO_URL}'>{REPO_URL}</a>.</p>"
        "<p>Developed by DGKN@Labs with the help of AI coding assistants (incl. Claude Code). "
        "Idea, architecture, testing and parts of the code: DGKN@Labs.</p>"
        "<p>Built for security testers, forensic analysts and incident responders. Use it only on "
        "files and systems you are authorised to examine.</p>"
    )


def show_about(parent=None):
    QMessageBox.about(parent, f"About {APP_CODENAME}", about_html())

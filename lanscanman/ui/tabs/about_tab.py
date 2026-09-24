from pathlib import Path

from PyQt6.QtWidgets import QTextBrowser, QVBoxLayout, QWidget

# The page itself is plain HTML so it can be edited without touching Python.
_HTML_PATH = Path(__file__).resolve().parent.parent / "resources" / "about.html"


# ─────────────────────────────────────────────────────────────────────────────
# AboutTab widget
# ─────────────────────────────────────────────────────────────────────────────

class AboutTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        browser = QTextBrowser()
        browser.setHtml(_HTML_PATH.read_text(encoding="utf-8"))
        browser.setOpenExternalLinks(True)
        browser.setReadOnly(True)

        # Match the app's panel background so there's no white flash
        browser.setStyleSheet("""
            QTextBrowser {
                background-color: #121417;
                border: none;
                padding: 0px;
            }
            QScrollBar:vertical {
                background: #1B1F24;
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background: #3A4452;
                border-radius: 5px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background: #3498db;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)

        root.addWidget(browser)

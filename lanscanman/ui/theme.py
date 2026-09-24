"""Application-wide dark theme: the colour palette and the Qt stylesheet built from it."""

# =========================
# LanScanMan Theme Config
# =========================

THEME = {
    "bg": "#121417",
    "panel": "#1B1F24",
    "panel_alt": "#20262E",
    "text": "#E6E6E6",
    "muted": "#9AA4AF",
    "accent": "#3498db",
    "good": "#27ae60",
    "warn": "#f39c12",
    "bad": "#c0392b",
    "radius": 8,
    "border": "1px solid #2A313B",
}


def apply_theme(app):
    app.setStyleSheet(f"""
/* ========================= CORE BACKGROUND ========================= */
QMainWindow {{
    background-color: {THEME['bg']};
    color: {THEME['text']};
}}

/* ========================= LABELS ========================= */
QLabel {{ color: {THEME['text']}; }}
QLabel[role="muted"] {{ color: {THEME['muted']}; }}

/* ========================= INPUT FIELDS ========================= */
QLineEdit {{
    background-color: {THEME['panel_alt']};
    border: {THEME['border']};
    padding: 6px;
    border-radius: {THEME['radius']}px;
    color: {THEME['text']};
}}
QLineEdit:focus {{ border: 1px solid {THEME['accent']}; }}

/* ========================= CHECKBOXES ========================= */
QCheckBox {{ color: {THEME['text']}; spacing: 8px; }}
QCheckBox::indicator {{
    width: 15px; height: 15px;
    border-radius: 3px;
    border: 1px solid #3A4452;
    background-color: {THEME['panel_alt']};
}}
QCheckBox::indicator:checked {{
    background-color: #2ecc71;
    border: 1px solid #27ae60;
}}
QCheckBox::indicator:hover {{ border: 1px solid {THEME['accent']}; }}

/* ========================= BUTTONS ========================= */
QPushButton {{
    background-color: {THEME['panel_alt']};
    border: {THEME['border']};
    padding: 6px 10px;
    border-radius: {THEME['radius']}px;
    color: {THEME['text']};
}}
QPushButton:hover {{ border: 1px solid {THEME['accent']}; }}
QPushButton:pressed {{ background-color: #151A20; }}

/* ========================= TABLES ========================= */
QTableWidget {{
    background-color: {THEME['panel']};
    border: {THEME['border']};
    gridline-color: transparent;
    color: #D6D6D6;
    alternate-background-color: #171B21;
}}
QTableWidget::item {{
    border-bottom: 1px solid #1A1F26;
    padding: 6px;
}}
QHeaderView::section {{
    background-color: {THEME['panel_alt']};
    color: {THEME['text']};
    padding: 6px;
    border: none;
    border-bottom: 1px solid {THEME['accent']};
}}

/* ========================= COMBOBOXES ========================= */
QComboBox {{
    background-color: {THEME['panel_alt']};
    border: {THEME['border']};
    padding: 6px;
    border-radius: {THEME['radius']}px;
    color: {THEME['text']};
}}
QComboBox:hover {{ border: 1px solid {THEME['accent']}; }}
QComboBox QAbstractItemView {{
    background-color: {THEME['panel']};
    selection-background-color: {THEME['accent']};
    color: {THEME['text']};
    border: {THEME['border']};
}}

/* ========================= TABS ========================= */
QTabWidget::pane {{
    border: {THEME['border']};
    border-radius: {THEME['radius']}px;
    background-color: {THEME['panel']};
}}
QTabBar::tab {{
    background-color: {THEME['panel_alt']};
    color: {THEME['text']};
    padding: 8px 14px;
    margin-right: 4px;
    border-top-left-radius: {THEME['radius']}px;
    border-top-right-radius: {THEME['radius']}px;
    border: {THEME['border']};
}}
QTabBar::tab:selected {{
    background-color: {THEME['panel']};
    border-bottom: 2px solid {THEME['accent']};
}}
QTabBar::tab:hover {{ border: 1px solid {THEME['accent']}; }}

/* ========================= GROUP BOXES ========================= */
QGroupBox {{
    border: {THEME['border']};
    margin-top: 10px;
    padding: 10px;
    border-radius: {THEME['radius']}px;
}}

/* ========================= DIALOGS / POPUPS ========================= */
QDialog {{ background-color: {THEME['bg']}; color: {THEME['text']}; }}
QMessageBox {{ background-color: {THEME['bg']}; color: {THEME['text']}; }}
QMessageBox QLabel {{ color: {THEME['text']}; }}
QDialogButtonBox QPushButton {{ min-width: 80px; }}

/* ========================= TOOLTIPS ========================= */
QToolTip {{
    background-color: {THEME['panel']};
    color: {THEME['text']};
    border: {THEME['border']};
    padding: 4px;
    border-radius: 6px;
}}
""")

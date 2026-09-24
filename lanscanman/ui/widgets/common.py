"""Small styled widgets shared by the monitor and disk-health views."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QGroupBox, QLabel, QProgressBar

from lanscanman.core.formatting import usage_color


def make_bar(pct, label: str = "") -> QProgressBar:
    """Return a styled QProgressBar for a 0-100 percentage."""
    bar = QProgressBar()
    bar.setRange(0, 100)
    bar.setValue(int(pct) if pct is not None else 0)
    bar.setTextVisible(True)
    bar.setFormat(label if label else f"{pct:.1f}%" if pct is not None else "N/A")
    color = usage_color(pct)
    bar.setStyleSheet(f"""
        QProgressBar {{
            border: 1px solid #2A313B;
            border-radius: 5px;
            background-color: #15181C;
            color: #E6E6E6;
            text-align: center;
            height: 18px;
        }}
        QProgressBar::chunk {{
            background-color: {color};
            border-radius: 4px;
        }}
    """)
    return bar


def section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        "color: #3498db; font-weight: bold; font-size: 11px; "
        "letter-spacing: 1px; text-transform: uppercase;"
    )
    return lbl


def value_label(text: str, muted: bool = False) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color: {'#9AA4AF' if muted else '#E6E6E6'}; font-size: 12px;")
    lbl.setWordWrap(True)
    return lbl


def make_badge() -> QLabel:
    """Return a blank badge label — text and style applied later via apply_brand."""
    lbl = QLabel("")
    lbl.setFixedHeight(20)
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    return lbl


def apply_brand(group: "QGroupBox", badge: QLabel, name_lbl: QLabel, brand: dict):
    """Paint a hardware section with its brand colour: top border, badge pill, name tint."""
    c  = brand["color"]
    bg = brand["bg"]
    bd = brand["border"]

    # Coloured top-border on the group box
    group.setStyleSheet(f"""
        QGroupBox {{
            border: 1px solid #2A313B;
            border-top: 2px solid {c};
            border-radius: 6px;
            padding: 10px;
            margin-top: 1px;
        }}
    """)

    # Pill badge
    badge.setText(brand["label"])
    badge.setStyleSheet(f"""
        QLabel {{
            color: {c};
            background-color: {bg};
            border: 1px solid {bd};
            border-radius: 4px;
            padding: 1px 7px;
            font-size: 9px;
            font-weight: bold;
            letter-spacing: 1.5px;
        }}
    """)

    # Name label tinted to brand colour
    name_lbl.setStyleSheet(f"color: {c}; font-size: 12px;")

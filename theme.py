"""
Project Obsidian Pro: Enterprise Industrial Design System
Premium, High-Contrast Industrial Aesthetic focusing on Clarity and Sophistication.
"""

OBSIDIAN_PRO_COLORS = {
    "bg_void": "#0a0a0b",      # Obsidian Black
    "bg_main": "#0e0e11",      # Deep Graphite
    "bg_panel": "rgba(23, 23, 26, 0.8)", # Graphite Glass
    "bg_sidebar": "#080809",   # Sidebar Absolute

    "accent_primary": "#6366f1",  # Indigo Pro
    "accent_success": "#10b981",  # Emerald Success
    "accent_warning": "#f59e0b",  # Amber Caution
    "accent_error": "#f43f5e",    # Rose Critical
    "accent_info": "#0ea5e9",     # Sky Info
    "accent_blue": "#3b82f6",     # Pro Blue (Blue-500)
    "accent_gold": "#eab308",     # Gold (Yellow-500)
    "accent_cyan": "#06b6d4",     # Cyan-500
    "accent_green": "#22c55e",    # Green-500
    "accent_pink": "#ec4899",     # Pink-500
    "accent_violet": "#8b5cf6",   # Violet-500

    # Severity aliases
    "critical": "#ef4444",        # Red-500
    "high": "#f97316",            # Orange-500
    "medium": "#eab308",          # Yellow-500
    "low": "#22c55e",             # Green-500
    "info": "#0ea5e9",            # Sky-500

    # Tool category accents
    "cat_recon": "#06b6d4",       # Cyan — Reconnaissance
    "cat_web": "#f59e0b",         # Amber — Web Application
    "cat_exploit": "#ef4444",     # Red — Exploitation
    "cat_social": "#a855f7",      # Purple — Social Engineering
    "cat_wireless": "#22d3ee",    # Cyan-400 — Wireless

    "text_prime": "#ffffff",      # High Contrast White
    "text_sec": "#cbd5e1",        # Bright Silver (Slate-300)
    "text_dim": "#94a3b8",        # Visible Graphite (Slate-400)

    "border_subtle": "rgba(255, 255, 255, 0.06)",
    "border_active": "rgba(99, 102, 241, 0.4)",
}

# Compatibility alias for main app refactor
AETHER_COLORS = OBSIDIAN_PRO_COLORS
CYBER_COLORS = OBSIDIAN_PRO_COLORS

def get_qss():
    return f"""
    QMainWindow {{
        background-color: {OBSIDIAN_PRO_COLORS["bg_void"]};
    }}

    QWidget {{
        font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
        font-size: 13px;
        color: {OBSIDIAN_PRO_COLORS["text_prime"]};
        background-color: transparent;
    }}
    
    QMainWindow, QDialog {{
        background-color: {OBSIDIAN_PRO_COLORS["bg_void"]};
    }}

    QFrame#Sidebar {{
        background-color: {OBSIDIAN_PRO_COLORS["bg_sidebar"]};
        border-right: 1px solid {OBSIDIAN_PRO_COLORS["border_subtle"]};
    }}

    QFrame#Card {{
        background-color: {OBSIDIAN_PRO_COLORS["bg_panel"]};
        border: 1px solid {OBSIDIAN_PRO_COLORS["border_subtle"]};
        border-radius: 10px;
    }}

    QLabel#Title {{
        font-weight: 700;
        font-size: 22px;
        color: #ffffff;
        letter-spacing: -0.5px;
    }}

    QLabel#StatValue {{
        font-family: 'Inter', sans-serif;
        font-size: 28px;
        font-weight: 800;
        color: #ffffff;
    }}

    QLabel#StatLabel {{
        color: {OBSIDIAN_PRO_COLORS["text_sec"]};
        font-size: 12px;
        font-weight: 600;
    }}

    QPushButton#MenuBtn {{
        background: transparent;
        color: {OBSIDIAN_PRO_COLORS["text_sec"]};
        border: none;
        padding: 12px 20px;
        text-align: left;
        font-weight: 500;
        border-radius: 6px;
        margin: 2px 8px;
    }}

    QPushButton#MenuBtn:hover {{
        color: #ffffff;
        background-color: rgba(255, 255, 255, 0.05);
    }}

    QPushButton#MenuBtn[active="true"] {{
        color: #ffffff;
        background-color: {OBSIDIAN_PRO_COLORS["accent_primary"]};
        font-weight: 600;
    }}

    QPushButton#ProBtn {{
        background-color: {OBSIDIAN_PRO_COLORS["accent_primary"]};
        color: #ffffff;
        border: none;
        padding: 10px 24px;
        font-weight: 600;
        border-radius: 6px;
    }}

    QPushButton#ProBtn:hover {{
        background-color: #4f46e5;
    }}

    QPushButton#ToolBtn {{
        background-color: rgba(255, 255, 255, 0.02);
        border: 1px solid {OBSIDIAN_PRO_COLORS["border_subtle"]};
        color: #ffffff;
        padding: 16px;
        border-radius: 10px;
        text-align: left;
        font-weight: 600;
        font-size: 13px;
        letter-spacing: 0.5px;
    }}

    QPushButton#ToolBtn:hover {{
        border: 1px solid {OBSIDIAN_PRO_COLORS["accent_primary"]};
        background-color: rgba(99, 102, 241, 0.06);
    }}

    QPushButton#ToolBtn:pressed {{
        background-color: rgba(99, 102, 241, 0.12);
    }}

    QPushButton#ToolBtnRecon {{
        background-color: rgba(6, 182, 212, 0.04);
        border: 1px solid rgba(6, 182, 212, 0.15);
        color: #ffffff;
        padding: 16px;
        border-radius: 10px;
        text-align: left;
        font-weight: 600;
        font-size: 13px;
        letter-spacing: 0.5px;
    }}
    QPushButton#ToolBtnRecon:hover {{
        border: 1px solid {OBSIDIAN_PRO_COLORS["cat_recon"]};
        background-color: rgba(6, 182, 212, 0.10);
    }}

    QPushButton#ToolBtnWeb {{
        background-color: rgba(245, 158, 11, 0.04);
        border: 1px solid rgba(245, 158, 11, 0.15);
        color: #ffffff;
        padding: 16px;
        border-radius: 10px;
        text-align: left;
        font-weight: 600;
        font-size: 13px;
        letter-spacing: 0.5px;
    }}
    QPushButton#ToolBtnWeb:hover {{
        border: 1px solid {OBSIDIAN_PRO_COLORS["cat_web"]};
        background-color: rgba(245, 158, 11, 0.10);
    }}

    QPushButton#ToolBtnExploit {{
        background-color: rgba(239, 68, 68, 0.04);
        border: 1px solid rgba(239, 68, 68, 0.15);
        color: #ffffff;
        padding: 16px;
        border-radius: 10px;
        text-align: left;
        font-weight: 600;
        font-size: 13px;
        letter-spacing: 0.5px;
    }}
    QPushButton#ToolBtnExploit:hover {{
        border: 1px solid {OBSIDIAN_PRO_COLORS["cat_exploit"]};
        background-color: rgba(239, 68, 68, 0.10);
    }}

    QPushButton#ToolBtnSocial {{
        background-color: rgba(168, 85, 247, 0.04);
        border: 1px solid rgba(168, 85, 247, 0.15);
        color: #ffffff;
        padding: 16px;
        border-radius: 10px;
        text-align: left;
        font-weight: 600;
        font-size: 13px;
        letter-spacing: 0.5px;
    }}
    QPushButton#ToolBtnSocial:hover {{
        border: 1px solid {OBSIDIAN_PRO_COLORS["cat_social"]};
        background-color: rgba(168, 85, 247, 0.10);
    }}

    QPushButton#ToolBtnWireless {{
        background-color: rgba(34, 211, 238, 0.04);
        border: 1px solid rgba(34, 211, 238, 0.15);
        color: #ffffff;
        padding: 16px;
        border-radius: 10px;
        text-align: left;
        font-weight: 600;
        font-size: 13px;
        letter-spacing: 0.5px;
    }}
    QPushButton#ToolBtnWireless:hover {{
        border: 1px solid {OBSIDIAN_PRO_COLORS["cat_wireless"]};
        background-color: rgba(34, 211, 238, 0.10);
    }}

    QTableWidget {{
        background-color: transparent;
        gridline-color: {OBSIDIAN_PRO_COLORS["border_subtle"]};
        border: 1px solid {OBSIDIAN_PRO_COLORS["border_subtle"]};
        border-radius: 10px;
        outline: none;
    }}

    QHeaderView::section {{
        background-color: {OBSIDIAN_PRO_COLORS["bg_void"]};
        color: {OBSIDIAN_PRO_COLORS["text_sec"]};
        padding: 12px;
        border: none;
        border-bottom: 1px solid {OBSIDIAN_PRO_COLORS["border_subtle"]};
        font-weight: 600;
        font-size: 12px;
    }}

    QLineEdit {{
        background-color: rgba(0, 0, 0, 0.2);
        border: 1px solid {OBSIDIAN_PRO_COLORS["border_subtle"]};
        color: #ffffff;
        padding: 10px 14px;
        border-radius: 6px;
    }}

    QLineEdit:focus {{
        border: 1px solid {OBSIDIAN_PRO_COLORS["accent_primary"]};
    }}

    QProgressBar {{
        border: none;
        background: rgba(255, 255, 255, 0.05);
        height: 6px;
        border-radius: 3px;
        text-align: center;
    }}

    QProgressBar::chunk {{
        background-color: {OBSIDIAN_PRO_COLORS["accent_primary"]};
        border-radius: 3px;
    }}

    QTextEdit {{
        background-color: #000000;
        border: 1px solid {OBSIDIAN_PRO_COLORS["border_subtle"]};
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        padding: 12px;
        border-radius: 8px;
    }}
    
    QTabBar::tab {{
        background: transparent;
        color: {OBSIDIAN_PRO_COLORS["text_sec"]};
        padding: 10px 24px;
        border-bottom: 2px solid transparent;
        margin-right: 4px;
        font-weight: 500;
    }}
    
    QTabBar::tab:selected {{
        color: {OBSIDIAN_PRO_COLORS["accent_primary"]};
        border-bottom: 2px solid {OBSIDIAN_PRO_COLORS["accent_primary"]};
    }}
    
    QScrollBar:vertical {{
        background: transparent;
        width: 6px;
    }}
    
    QScrollBar::handle:vertical {{
        background: rgba(255, 255, 255, 0.1);
        border-radius: 3px;
    }}
    """

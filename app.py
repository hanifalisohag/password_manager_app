# app.py
import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon
from pathlib import Path

from ui.main_window import MainWindow

class PasswordApp:
    def __init__(self):
        self.qt_app = QApplication(sys.argv)
        self.main_win = MainWindow()

        # Get absolute path for icon
        if getattr(sys, 'frozen', False):
            # Running in PyInstaller bundle
            base_path = Path(sys._MEIPASS)
        else:
            # Running in normal Python environment
            base_path = Path(__file__).parent

        icon_path = base_path / 'resources' / 'icons' / 'main_logo.png'
        self.main_win.setWindowIcon(QIcon(str(icon_path)))

    def run(self):
        self.main_win.show()
        sys.exit(self.qt_app.exec())

from PyQt6.QtWidgets import QDialog, QLineEdit, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QTextEdit

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Unlock Vault')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        btn_unlock = QPushButton('Unlock')
        btn_unlock.clicked.connect(self.accept)
        layout = QVBoxLayout()
        layout.addWidget(QLabel('Master password'))
        layout.addWidget(self.password_input)
        layout.addWidget(btn_unlock)
        self.setLayout(layout)

    def get_password(self):
        return self.password_input.text()


class CreateVaultDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Vault - Enter Master Password")

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)

        btn_create = QPushButton("Create")
        btn_create.clicked.connect(self.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Master Password (min 8 characters)"))
        layout.addWidget(self.password_input)
        layout.addWidget(QLabel("Confirm Password"))
        layout.addWidget(self.confirm_input)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(btn_create)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def get_passwords(self):
        return self.password_input.text(), self.confirm_input.text()

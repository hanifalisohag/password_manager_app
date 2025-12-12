from PyQt6.QtWidgets import QDialog, QLineEdit, QLabel, QPushButton, QVBoxLayout,  QFileDialog,QDialogButtonBox

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

        self.vault_path_field = QLineEdit()
        self.vault_path_field.setPlaceholderText("Choose vault location...")
        self.btn_browse = QPushButton("Browse")
        self.btn_browse.clicked.connect(self.browse_location)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Master Password (min 8 characters)"))
        layout.addWidget(self.password_input)
        layout.addWidget(QLabel("Confirm Password"))
        layout.addWidget(self.confirm_input)
        layout.addWidget(QLabel("Vault File Location:"))
        layout.addWidget(self.vault_path_field)
        layout.addWidget(self.btn_browse)

        # OK / Cancel buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

    def browse_location(self):
        path, _ = QFileDialog.getSaveFileName(self, "Select Vault Location", "", "Database Files (*.db)")
        if path:
            if not path.endswith(".db"):
                path += ".db"
            self.vault_path_field.setText(path)

    def get_passwords(self):
        return self.password_input.text(), self.confirm_input.text()

    def get_vault_path(self):
        return self.vault_path_field.text()

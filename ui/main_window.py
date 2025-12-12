from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QMessageBox, QApplication, QToolTip, QTreeWidget, QTreeWidgetItem,
    QLineEdit, QCompleter, QMenu, QTextEdit,QFileDialog, QMessageBox
)
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtCore import Qt, QStringListModel
from ui.dialogs import LoginDialog, CreateVaultDialog
from core.vault import Vault
from database.db import DB_FILE
from pathlib import Path
import json



def is_first_run():
    return not DB_FILE.exists() or DB_FILE.stat().st_size == 0


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('HASPassVault - Password Manager')
        self.resize(1000, 600)

        self.vault = None
        self.current_entry_id = None
        self.current_password_masked = '********'
        self.password_visible = False


        # --- Top buttons ---
        self.btn_unlock = QPushButton('Unlock Vault')
        self.btn_unlock.clicked.connect(self.show_unlock)

        self.btn_create = QPushButton('Create New Vault')
        self.btn_create.clicked.connect(self.show_create)

        if is_first_run():
            self.btn_create.setEnabled(True)
            self.btn_unlock.setEnabled(False)
        else:
            self.btn_create.setEnabled(False)
            self.btn_unlock.setEnabled(True)

        top_widget = QWidget()
        top_layout = QHBoxLayout()
        top_layout.addWidget(self.btn_unlock)
        top_layout.addWidget(self.btn_create)
        top_widget.setLayout(top_layout)


        btn_import = QPushButton("Import")
        btn_import.clicked.connect(self.import_vault)
        top_layout.addWidget(btn_import)

        btn_export = QPushButton("Export")
        btn_export.clicked.connect(self.export_vault)
        top_layout.addWidget(btn_export)

        # --- Left: search + tree + buttons ---
        left_widget = QWidget()
        left_layout = QVBoxLayout()

        # Search bar
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search titles or usernames...")
        left_layout.addWidget(self.search_bar)

        # Tree widget
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Title / Username"])
        self.tree_widget.setAlternatingRowColors(True)
        self.tree_widget.setRootIsDecorated(True)
        self.tree_widget.setItemsExpandable(True)
        self.tree_widget.setIndentation(5)
        self.tree_widget.setFont(QFont("Arial", 10))
        self.tree_widget.itemClicked.connect(self.on_tree_item_click)
        self.tree_widget.itemDoubleClicked.connect(self.toggle_parent)
        left_layout.addWidget(self.tree_widget)

        # Left-side action buttons
        buttons_row = QHBoxLayout()
        btn_add = QPushButton("New Entry")  # Add new entry
        btn_add.setToolTip("Create a new entry")
        # btn_add.setFixedWidth(30)

        btn_add.clicked.connect(self.add_entry_inline)
        buttons_row.addWidget(btn_add)
        # buttons_row.addStretch()
        left_layout.addLayout(buttons_row)

        left_widget.setLayout(left_layout)

        # --- Completer for search bar ---
        self.completer = QCompleter()
        self.completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.completer.setModel(QStringListModel())
        self.search_bar.setCompleter(self.completer)
        self.search_bar.textChanged.connect(self.on_search_text_changed)
        self.completer.activated.connect(self.on_completer_activated)


  


        # --- Right: inline editable details ---
        self.right_widget = QWidget()
        right_layout = QVBoxLayout()

        self.details_container = QWidget()
        details_layout = QVBoxLayout()

        # Title
        self.title_field = QLineEdit()
        self.title_field.setReadOnly(True)
        details_layout.addWidget(QLabel("Title:"))
        details_layout.addWidget(self.title_field)

        # Username
        self.username_field = QLineEdit()
        self.username_field.setReadOnly(True)
        username_row = QHBoxLayout()
        username_row.addWidget(self.username_field)
        btn_copy_username = QPushButton("Copy")
        btn_copy_username.setFixedWidth(60)
        btn_copy_username.clicked.connect(self.copy_username)
        username_row.addWidget(btn_copy_username)
        details_layout.addWidget(QLabel("Username:"))
        details_layout.addLayout(username_row)

        # Password
        self.password_field = QLineEdit()
        self.password_field.setReadOnly(True)
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)
        password_row = QHBoxLayout()
        password_row.addWidget(self.password_field)
        self.btn_show_password = QPushButton("Show")
        self.btn_show_password.setFixedWidth(60)
        self.btn_show_password.clicked.connect(self.toggle_password)
        self.btn_copy_password = QPushButton("Copy")
        self.btn_copy_password.setFixedWidth(60)
        self.btn_copy_password.clicked.connect(self.copy_password)
        password_row.addWidget(self.btn_show_password)
        password_row.addWidget(self.btn_copy_password)
        details_layout.addWidget(QLabel("Password:"))
        details_layout.addLayout(password_row)


        # --- Right panel title autocomplete ---
        self.title_completer = QCompleter()
        self.title_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.title_completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.title_model = QStringListModel()
        self.title_completer.setModel(self.title_model)
        self.title_field.setCompleter(self.title_completer)

        # Notes
        self.notes_field = QTextEdit()
        self.notes_field.setReadOnly(True)
        details_layout.addWidget(QLabel("Notes:"))
        details_layout.addWidget(self.notes_field)

        # Edit/Save button
        self.edit_save_button = QPushButton("Edit")
        self.edit_save_button.setEnabled(False)
        self.edit_save_button.clicked.connect(self.enable_edit_mode)
        details_layout.addWidget(self.edit_save_button)

        # --- New Delete button ---
        self.delete_button = QPushButton("Delete")
        self.delete_button.setEnabled(False)  # Only enabled when an entry is selected
        self.delete_button.clicked.connect(self.delete_entry_inline)
        details_layout.addWidget(self.delete_button)

        self.details_container.setLayout(details_layout)
        self.details_container.setVisible(False)
        right_layout.addWidget(self.details_container)
        right_layout.addStretch()
        self.right_widget.setLayout(right_layout)

        # --- New Discard button ---
        self.discard_button = QPushButton("Discard")
        self.discard_button.setVisible(False)  # hidden by default
        # self.discard_button.setEnabled(False)
        self.discard_button.clicked.connect(self.discard_changes)
        details_layout.addWidget(self.discard_button)

        # --- Center layout ---
        center_widget = QWidget()
        center_layout = QHBoxLayout()
        center_layout.addWidget(left_widget, 3)
        center_layout.addWidget(self.right_widget, 5)
        center_widget.setLayout(center_layout)

        # --- Root layout ---
        root = QWidget()
        root_layout = QVBoxLayout()
        root_layout.addWidget(top_widget)
        root_layout.addWidget(center_widget)
        root.setLayout(root_layout)
        self.setCentralWidget(root)


        self.created_label = QLabel("Created At: N/A")
        self.updated_label = QLabel("Updated At: N/A")
        details_layout.addWidget(self.created_label)
        details_layout.addWidget(self.updated_label)

        self.view_style = """
            QLineEdit, QTextEdit {
                background-color: #000000;
                border: 1px solid #ccc;
                color: #fff;
            }
        """

        self.edit_style = """
            QLineEdit, QTextEdit {
                background-color: #ffffff;
                border: 1px solid #888;
                color: #000;
            }
        """

    def export_vault(self):
        if not self.vault:
            QMessageBox.warning(self, "Error", "Vault is not unlocked!")
            return

        # Ask user where to save
        path, _ = QFileDialog.getSaveFileName(self, "Export Vault", "", "JSON Files (*.json)")
        if not path:
            return

        try:
            items = self.vault.list_items()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(items, f, indent=4)
            QMessageBox.information(self, "Export", f"Vault exported successfully to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export vault:\n{str(e)}")
            

    def import_vault(self):
        if not self.vault:
            QMessageBox.warning(self, "Error", "Vault is not unlocked!")
            return

        path, _ = QFileDialog.getOpenFileName(self, "Import Vault", "", "JSON Files (*.json)")
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                items = json.load(f)

            for item in items:
                self.vault.import_item(
                    title=item.get("title", ""),
                    username=item.get("username", ""),
                    password=item.get("password", ""),
                    notes=item.get("notes", ""),
                    created_at=item.get("created_at"),
                    updated_at=item.get("updated_at")
                )

            self.reload_tree()
            self.update_completer()

            QMessageBox.information(self, "Import", f"Vault imported successfully from {path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import vault:\n{str(e)}")




    # --- Vault creation ---   
    def show_create(self):
        dlg = CreateVaultDialog(self)
        while True:
            if dlg.exec() != dlg.DialogCode.Accepted:
                return
            pw, pw_confirm = dlg.get_passwords()
            if len(pw) < 8:
                QMessageBox.warning(self, "Error", "Password must be at least 8 characters.")
                continue
            if pw != pw_confirm:
                QMessageBox.warning(self, "Error", "Passwords do not match.")
                continue

            # ---------------------------
            # FIX: Only initialize vault once
            # but DO NOT unlock it
            # ---------------------------
            Vault(pw)  # creates encrypted DB structure

            QMessageBox.information(self, "Vault", "Vault created successfully!")

            # Disable create → vault exists
            self.btn_create.setEnabled(False)

            # Enable unlock → user must unlock manually
            self.btn_unlock.setEnabled(True)

            # Vault is locked → ensure app knows it's locked
            self.vault = None
            self.tree_widget.clear()
            return
    
    def discard_changes(self):
        if self.current_entry_id:
            # Editing existing entry: revert fields to original
            self.display_entry(self.current_entry_id)
        else:
            # New entry: clear the form and hide details panel
            self.details_container.setVisible(False)
            self.edit_save_button.setEnabled(False)
            self.delete_button.setVisible(False)
        self.discard_button.setVisible(False)


    def update_title_completer(self):
        if not self.vault:
            self.title_model.setStringList([])
            return
        titles = sorted({item['title'] for item in self.vault.list_items()})
        self.title_model.setStringList(titles)

    def show_unlock(self):
        if not Path(DB_FILE).exists():
            QMessageBox.warning(self, 'Error', 'No vault exists. Create one first.')
            return

        dlg = LoginDialog(self)
        if dlg.exec() == dlg.DialogCode.Accepted:
            password = dlg.get_password()
            if not password:
                return

            self.vault = Vault(password)
            if not self.vault.verify_master_password():
                QMessageBox.warning(self, 'Error', 'Wrong master password!')
                self.vault = None
                return

            # ------------------------------
            # FIX: Disable unlock button now
            # ------------------------------
            self.btn_unlock.setEnabled(False)

            # Also disable "Create New Vault" because a vault already exists
            self.btn_create.setEnabled(False)

            self.reload_tree()
            self.update_completer()
            QMessageBox.information(self, 'Vault', 'Vault unlocked successfully!')
            self.update_title_completer()


    # --- Reload tree ---
    def reload_tree(self):
        self.tree_widget.clear()
        self.details_container.setVisible(False)
        self.current_entry_id = None
        self.edit_save_button.setEnabled(False)
        if not self.vault:
            return
        items = self.vault.list_items()
        title_dict = {}
        for it in items:
            title = it['title']
            if title not in title_dict:
                title_dict[title] = []
            title_dict[title].append(it)

        for title in sorted(title_dict.keys(), key=lambda x: x.lower()):
            top_item = QTreeWidgetItem([title])
            self.tree_widget.addTopLevelItem(top_item)
            sorted_entries = sorted(title_dict[title], key=lambda e: e['username'].lower())
            for e in sorted_entries:
                child_item = QTreeWidgetItem([e['username']])
                child_item.setData(0, 1, e['id'])
                top_item.addChild(child_item)
            top_item.setExpanded(True)

    # --- Tree item click ---
    def on_tree_item_click(self, item):
        entry_id = item.data(0, 1)
        if entry_id:  # child selected
            self.current_entry_id = entry_id
            self.display_entry(entry_id)
            self.edit_save_button.setEnabled(True)
            self.delete_button.setEnabled(True)
            self.delete_button.setVisible(True)
        else:
            self.current_entry_id = None
            self.details_container.setVisible(False)
            self.edit_save_button.setEnabled(False)
            self.delete_button.setEnabled(False)

    def toggle_parent(self, item, column):
        if item.childCount() > 0:
            item.setExpanded(not item.isExpanded())

    # --- Display entry in right panel ---
    # In display_entry
    def display_entry(self, entry_id):
        entry = self.vault.get_item(entry_id)
        if not entry:
            return

        self.title_field.setText(entry['title'])
        self.username_field.setText(entry['username'])
        self.current_password_real = entry['password']  # Store actual password
        self.password_field.setText(entry['password'])
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)  # Masked by default
        self.notes_field.setPlainText(entry['notes'])

        # Set timestamps
        self.created_label.setText(f"Created At: {entry.get('created_at','N/A')}")
        self.updated_label.setText(f"Updated At: {entry.get('updated_at','N/A')}")


        self.details_container.setVisible(True)
        self.set_readonly(True)
        self.apply_view_style()

        self.edit_save_button.setText("Edit")
        self.password_visible = False
        self.btn_show_password.setText("Show")
        self.discard_button.setVisible(False)
        self.delete_button.setVisible(True)


    def set_readonly(self, readonly: bool):
        self.title_field.setReadOnly(readonly)
        self.username_field.setReadOnly(readonly)
        self.password_field.setReadOnly(readonly)
        self.notes_field.setReadOnly(readonly)

    # --- Edit / Save ---
    def enable_edit_mode(self):
        if not self.current_entry_id:
            return
        self.set_readonly(False)
        self.apply_edit_style()
        self.edit_save_button.setText("Save")

        # self.discard_button.setEnabled(True)
        self.discard_button.setVisible(True)
        self.delete_button.setVisible(False)

        try:
            self.edit_save_button.clicked.disconnect()
        except TypeError:
            pass
        self.edit_save_button.clicked.connect(self.save_entry)

    def save_entry(self):
        if not self.vault or not self.current_entry_id:
            return
        self.vault.update_item(
            self.current_entry_id,
            self.title_field.text(),
            self.username_field.text(),
            self.password_field.text(),
            self.notes_field.toPlainText()
        )
        self.set_readonly(True)
        self.edit_save_button.setText("Edit")
        # self.discard_button.setEnabled(False)
        self.discard_button.setVisible(False)
        self.delete_button.setVisible(True)
        self.edit_save_button.clicked.disconnect()
        self.edit_save_button.clicked.connect(self.enable_edit_mode)
        self.reload_tree()
        self.update_completer()

    # --- Add entry inline ---
    def add_entry_inline(self):
        if not self.vault:
            QMessageBox.warning(self, 'Error', 'Unlock the vault first')
            return

        self.details_container.setVisible(True)
        self.current_entry_id = None

        # self.discard_button.setEnabled(True)
        self.discard_button.setVisible(True)

        # Clear all fields for new entry
        self.title_field.setText("")
        self.username_field.setText("")
        self.password_field.setText("")
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)  # Masked by default
        self.notes_field.setPlainText("")

        # Make fields editable and apply edit style
        self.set_readonly(False)
        self.apply_edit_style()

        # Enable Save button for new entry
        self.edit_save_button.setEnabled(True)
        self.edit_save_button.setText("Save")
        try:
            self.edit_save_button.clicked.disconnect()
        except TypeError:
            pass
        self.edit_save_button.clicked.connect(self.save_new_entry)

        # Hide delete button for new entry
        self.delete_button.setVisible(False)

        # Reset password toggle state
        self.password_visible = False
        self.btn_show_password.setText("Show")

        # Update title autocomplete
        self.update_title_completer()

    def save_new_entry(self):
        if not self.vault:
            return
        title = self.title_field.text().strip()
        username = self.username_field.text().strip()
        password = self.password_field.text().strip()
        notes = self.notes_field.toPlainText().strip()
        
       
        if not title or not username or not password:
            QMessageBox.warning(self, "Error", "Title, Username, and Password cannot be empty.")
            return

        self.vault.add_item(title, username, password, notes)
        self.set_readonly(True)
        self.edit_save_button.setText("Edit")
        self.edit_save_button.clicked.disconnect()
        self.edit_save_button.clicked.connect(self.enable_edit_mode)
        self.reload_tree()
        self.update_completer()
        self.update_title_completer()     # title field autocomplete

         # self.discard_button.setEnabled(False)
        self.discard_button.setVisible(False)
        self.delete_button.setVisible(True)

    # --- Delete inline ---
    def delete_entry_inline(self):
        if not self.vault or not self.current_entry_id:
            return
        confirm = QMessageBox.question(self, "Confirm", "Delete this entry?")
        if confirm == QMessageBox.StandardButton.Yes:
            self.vault.delete_item(self.current_entry_id)
            self.current_entry_id = None
            self.details_container.setVisible(False)
            self.edit_save_button.setEnabled(False)
            self.delete_button.setEnabled(False)
            self.reload_tree()
            self.update_completer()
            self.update_title_completer()


    # --- Copy / Toggle password ---
    def toggle_password(self):
        if self.password_visible:
            # Hide password
            self.password_field.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_show_password.setText("Show")
            self.password_visible = False
        else:
            # Show password
            self.password_field.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_show_password.setText("Hide")
            self.password_visible = True



    def copy_username(self):
        if not self.current_entry_id or not self.vault:
            return
        entry = self.vault.get_item(self.current_entry_id)
        if entry:
            QApplication.clipboard().setText(entry['username'])
            QToolTip.showText(self.username_field.mapToGlobal(self.username_field.rect().center()),
                              "Copied!", self.username_field, self.username_field.rect(), 1000)

    def copy_password(self):
        if not self.current_entry_id or not self.vault:
            return
        entry = self.vault.get_item(self.current_entry_id)
        if entry:
            QApplication.clipboard().setText(entry['password'])
            QToolTip.showText(self.password_field.mapToGlobal(self.password_field.rect().center()),
                              "Copied!", self.password_field, self.password_field.rect(), 1000)

    # --- Left-side settings menu (QMenu) ---
    def show_edit_delete_menu(self):
        if not self.current_entry_id:
            return
        menu = QMenu(self)
        edit_action = menu.addAction("Edit")
        delete_action = menu.addAction("Delete")
        action = menu.exec(self.btn_settings.mapToGlobal(self.btn_settings.rect().bottomLeft()))
        if action == edit_action:
            self.enable_edit_mode()
        elif action == delete_action:
            self.delete_entry_inline()

    # --- Search / autocomplete ---
    def on_search_text_changed(self, text):
        text = text.lower()
        for i in range(self.tree_widget.topLevelItemCount()):
            parent = self.tree_widget.topLevelItem(i)
            match_parent = text in parent.text(0).lower()
            has_visible_child = False
            for j in range(parent.childCount()):
                child = parent.child(j)
                match_child = text in child.text(0).lower()
                child.setHidden(not match_child)
                if match_child:
                    has_visible_child = True
            parent.setHidden(not (match_parent or has_visible_child))
            parent.setExpanded(has_visible_child)

    def on_completer_activated(self, text):
        for i in range(self.tree_widget.topLevelItemCount()):
            parent = self.tree_widget.topLevelItem(i)
            if text.lower() in parent.text(0).lower():
                self.tree_widget.setCurrentItem(parent)
                return
            for j in range(parent.childCount()):
                child = parent.child(j)
                if text.lower() in child.text(0).lower():
                    self.tree_widget.setCurrentItem(child)
                    return

    # --- Update main search completer ---
    def update_completer(self):
        if not self.vault:
            return
        items = self.vault.list_items()
        suggestions = set()
        for it in items:
            suggestions.add(it['title'])
            suggestions.add(it['username'])
        self.completer.model().setStringList(sorted(list(suggestions)))

    def set_readonly(self, readonly=True):
        self.title_field.setReadOnly(readonly)
        self.username_field.setReadOnly(readonly)
        self.password_field.setReadOnly(readonly)
        self.notes_field.setReadOnly(readonly)

    def apply_view_style(self):
        self.title_field.setStyleSheet(self.view_style)
        self.username_field.setStyleSheet(self.view_style)
        self.password_field.setStyleSheet(self.view_style)
        self.notes_field.setStyleSheet(self.view_style)

    def apply_edit_style(self):
        self.title_field.setStyleSheet(self.edit_style)
        self.username_field.setStyleSheet(self.edit_style)
        self.password_field.setStyleSheet(self.edit_style)
        self.notes_field.setStyleSheet(self.edit_style)

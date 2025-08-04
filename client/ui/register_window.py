# ui/register_window.py - Clean Registration Interface
# IT2504 Applied Cryptography Assignment 2

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QFrame, QCheckBox)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

class RegisterWindow(QDialog):
    """
    Clean and simple registration window for new user accounts.
    """
    
    registration_successful = pyqtSignal(str)  # Emits username when successful
    
    def __init__(self, network_client):
        super().__init__()
        self.network_client = network_client
        
        self.setWindowTitle("Create Account - Secure Messaging")
        self.setFixedSize(450, 400)
        self.setModal(True)
        self.center_window()
        
        self.setup_ui()
        
    def center_window(self):
        """Center the window on screen."""
        screen = self.frameGeometry()
        if self.parent():
            center_point = self.parent().frameGeometry().center()
        else:
            center_point = self.screen().availableGeometry().center()
        screen.moveCenter(center_point)
        self.move(screen.topLeft())
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(30, 25, 30, 25)
        
        # Title
        title_label = QLabel("Create New Account")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Arial", 16, QFont.Bold)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Join the secure messaging network")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_font = QFont("Arial", 10)
        subtitle_label.setFont(subtitle_font)
        main_layout.addWidget(subtitle_label)
        
        # Add spacing
        main_layout.addSpacing(20)
        
        # Username field
        username_label = QLabel("Username:")
        username_label.setFont(QFont("Arial", 11))
        main_layout.addWidget(username_label)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose a unique username")
        self.username_input.setFixedHeight(35)
        self.username_input.setFont(QFont("Arial", 11))
        self.username_input.textChanged.connect(self.validate_form)
        main_layout.addWidget(self.username_input)
        
        # Add small spacing
        main_layout.addSpacing(8)
        
        # Password field
        password_label = QLabel("Password:")
        password_label.setFont(QFont("Arial", 11))
        main_layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Choose a strong password")
        self.password_input.setFixedHeight(35)
        self.password_input.setFont(QFont("Arial", 11))
        self.password_input.textChanged.connect(self.validate_form)
        main_layout.addWidget(self.password_input)
        
        # Add small spacing
        main_layout.addSpacing(8)
        
        # Confirm password field
        confirm_label = QLabel("Confirm Password:")
        confirm_label.setFont(QFont("Arial", 11))
        main_layout.addWidget(confirm_label)
        
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setPlaceholderText("Re-enter your password")
        self.confirm_input.setFixedHeight(35)
        self.confirm_input.setFont(QFont("Arial", 11))
        self.confirm_input.textChanged.connect(self.validate_form)
        main_layout.addWidget(self.confirm_input)
        
        # Add spacing
        main_layout.addSpacing(15)
        
        # Security notice (simplified)
        security_label = QLabel("🔐 Security: Keys stored locally, messages encrypted end-to-end")
        security_label.setAlignment(Qt.AlignCenter)
        security_label.setFont(QFont("Arial", 9))
        security_label.setWordWrap(True)
        main_layout.addWidget(security_label)
        
        # Add spacing
        main_layout.addSpacing(10)
        
        # Agreement checkbox
        self.agreement_checkbox = QCheckBox("I understand that my private keys will be stored locally")
        self.agreement_checkbox.setFont(QFont("Arial", 10))
        self.agreement_checkbox.stateChanged.connect(self.validate_form)
        main_layout.addWidget(self.agreement_checkbox)
        
        # Add spacing
        main_layout.addSpacing(15)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        # Cancel button
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setFixedHeight(40)
        self.cancel_button.setFont(QFont("Arial", 11, QFont.Bold))
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        # Register button
        self.register_button = QPushButton("Create Account")
        self.register_button.setFixedHeight(40)
        self.register_button.setFont(QFont("Arial", 11, QFont.Bold))
        self.register_button.clicked.connect(self.handle_registration)
        self.register_button.setEnabled(False)
        button_layout.addWidget(self.register_button)
        
        main_layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setFont(QFont("Arial", 10))
        main_layout.addWidget(self.status_label)
        
    def validate_form(self):
        """Validate form input and enable/disable register button."""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        agreement = self.agreement_checkbox.isChecked()
        
        # Clear previous status
        self.status_label.setText("")
        
        # Check all fields
        if not username:
            self.register_button.setEnabled(False)
            return
        
        if len(username) < 3:
            self.show_status("Username must be at least 3 characters", True)
            self.register_button.setEnabled(False)
            return
        
        if not password:
            self.register_button.setEnabled(False)
            return
        
        if len(password) < 8:
            self.show_status("Password must be at least 8 characters", True)
            self.register_button.setEnabled(False)
            return
        
        if password != confirm:
            if confirm:  # Only show error if user has started typing confirm
                self.show_status("Passwords do not match", True)
            self.register_button.setEnabled(False)
            return
        
        if not agreement:
            self.register_button.setEnabled(False)
            return
        
        # All validation passed
        self.show_status("Ready to create account", False)
        self.register_button.setEnabled(True)
    
    def show_status(self, message: str, is_error: bool = False):
        """Show status message."""
        self.status_label.setText(message)
        if is_error:
            self.status_label.setStyleSheet("color: red;")
        else:
            self.status_label.setStyleSheet("color: green;")
    
    def handle_registration(self):
        """Handle user registration."""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        # Disable UI during registration
        self.set_ui_enabled(False)
        self.show_status("Creating account...")
        
        try:
            # Attempt registration
            success, message = self.network_client.register_user(username, password)
            
            if success:
                self.show_status("Account created successfully!", False)
                
                # Emit signal and close dialog
                self.registration_successful.emit(username)
                self.accept()
                
            else:
                self.show_status(f"Registration failed: {message}", True)
                self.set_ui_enabled(True)
                
        except Exception as e:
            self.show_status(f"Error: {str(e)}", True)
            self.set_ui_enabled(True)
    
    def set_ui_enabled(self, enabled: bool):
        """Enable or disable UI elements."""
        self.username_input.setEnabled(enabled)
        self.password_input.setEnabled(enabled)
        self.confirm_input.setEnabled(enabled)
        self.agreement_checkbox.setEnabled(enabled)
        self.register_button.setEnabled(enabled and self.validate_form)
        self.cancel_button.setEnabled(enabled)
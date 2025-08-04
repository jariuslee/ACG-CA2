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
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(40, 30, 40, 30)
        
        # Title
        title_label = QLabel("Create New Account")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Segoe UI", 16, QFont.Bold)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #0078d4; margin-bottom: 10px;")
        main_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Join the secure messaging network")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #666666; font-size: 12px; margin-bottom: 20px;")
        main_layout.addWidget(subtitle_label)
        
        # Registration form container
        form_frame = QFrame()
        form_frame.setStyleSheet("""
            QFrame {
                background-color: #fafafa;
                border: 1px solid #e1e1e1;
                border-radius: 8px;
                padding: 20px;
            }
        """)
        form_layout = QVBoxLayout(form_frame)
        form_layout.setSpacing(15)
        
        # Username field
        username_label = QLabel("Username:")
        username_label.setStyleSheet("font-weight: 500;")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose a unique username")
        self.username_input.textChanged.connect(self.validate_form)
        
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.username_input)
        
        # Password field
        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-weight: 500;")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Choose a strong password")
        self.password_input.textChanged.connect(self.validate_form)
        
        form_layout.addWidget(password_label)
        form_layout.addWidget(self.password_input)
        
        # Confirm password field
        confirm_label = QLabel("Confirm Password:")
        confirm_label.setStyleSheet("font-weight: 500;")
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setPlaceholderText("Re-enter your password")
        self.confirm_input.textChanged.connect(self.validate_form)
        
        form_layout.addWidget(confirm_label)
        form_layout.addWidget(self.confirm_input)
        
        main_layout.addWidget(form_frame)
        
        # Security notice
        security_frame = QFrame()
        security_frame.setStyleSheet("""
            QFrame {
                background-color: #e3f2fd;
                border: 1px solid #bbdefb;
                border-radius: 4px;
                padding: 12px;
            }
        """)
        security_layout = QVBoxLayout(security_frame)
        
        security_title = QLabel("🔐 Security Information")
        security_title.setStyleSheet("font-weight: bold; color: #0277bd;")
        security_layout.addWidget(security_title)
        
        security_text = QLabel(
            "• Your password is hashed and stored securely\n"
            "• Encryption keys will be generated after registration\n"
            "• Private keys are stored only on your device\n"
            "• All messages are end-to-end encrypted"
        )
        security_text.setStyleSheet("color: #01579b; font-size: 12px; margin-top: 5px;")
        security_layout.addWidget(security_text)
        
        main_layout.addWidget(security_frame)
        
        # Agreement checkbox
        self.agreement_checkbox = QCheckBox(
            "I understand that my private keys will be stored locally and "
            "I am responsible for keeping them secure."
        )
        self.agreement_checkbox.setStyleSheet("font-size: 12px;")
        self.agreement_checkbox.stateChanged.connect(self.validate_form)
        main_layout.addWidget(self.agreement_checkbox)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        # Cancel button
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        self.cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                font-weight: 600;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
        """)
        
        # Register button
        self.register_button = QPushButton("Create Account")
        self.register_button.clicked.connect(self.handle_registration)
        self.register_button.setEnabled(False)
        self.register_button.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                font-weight: 600;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.register_button)
        
        main_layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #666666; font-size: 12px;")
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
        color = "#dc3545" if is_error else "#28a745"
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color}; font-size: 12px;")
    
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
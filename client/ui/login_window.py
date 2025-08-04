# ui/login_window.py - Clean Login Interface
# IT2504 Applied Cryptography Assignment 2

from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QMessageBox, QFrame)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QPixmap

from .register_window import RegisterWindow
from .chat_window import ChatWindow
from key_manager import ClientKeyManager

class LoginWindow(QMainWindow):
    """
    Clean and simple login window for user authentication.
    """
    
    def __init__(self, network_client):
        super().__init__()
        self.network_client = network_client
        self.key_manager = ClientKeyManager()
        
        self.setWindowTitle("Secure Messaging - Login")
        self.setFixedSize(400, 300)
        self.center_window()
        
        self.setup_ui()
        
    def center_window(self):
        """Center the window on screen."""
        screen = self.frameGeometry()
        center_point = self.screen().availableGeometry().center()
        screen.moveCenter(center_point)
        self.move(screen.topLeft())
    
    def setup_ui(self):
        """Set up the user interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(40, 40, 40, 40)
        
        # Title
        title_label = QLabel("🔐 Secure Messaging")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Segoe UI", 18, QFont.Bold)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #0078d4; margin-bottom: 10px;")
        main_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("End-to-End Encrypted Communication")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #666666; font-size: 12px; margin-bottom: 20px;")
        main_layout.addWidget(subtitle_label)
        
        # Login form container
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
        self.username_input.setPlaceholderText("Enter your username")
        self.username_input.returnPressed.connect(self.handle_login)
        
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.username_input)
        
        # Password field
        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-weight: 500;")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.returnPressed.connect(self.handle_login)
        
        form_layout.addWidget(password_label)
        form_layout.addWidget(self.password_input)
        
        main_layout.addWidget(form_frame)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)
        self.login_button.setStyleSheet("""
            QPushButton {
                background-color: #0078d4;
                font-weight: 600;
                padding: 10px 20px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
        """)
        
        # Register button
        self.register_button = QPushButton("Create Account")
        self.register_button.clicked.connect(self.show_register_window)
        self.register_button.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                font-weight: 600;
                padding: 10px 20px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
        """)
        
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.register_button)
        
        main_layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #666666; font-size: 12px;")
        main_layout.addWidget(self.status_label)
        
        # Add some stretch at the bottom
        main_layout.addStretch()
        
    def show_status(self, message: str, is_error: bool = False):
        """Show status message."""
        color = "#dc3545" if is_error else "#28a745"
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color}; font-size: 12px;")
    
    def handle_login(self):
        """Handle user login."""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        # Validate input
        if not username or not password:
            self.show_status("Please enter both username and password", True)
            return
        
        # Disable UI during login
        self.set_ui_enabled(False)
        self.show_status("Logging in...")
        
        try:
            # Attempt login
            success, message = self.network_client.login_user(username, password)
            
            if success:
                self.show_status("Login successful!", False)
                
                # Check if user has cryptographic keys
                if not self.key_manager.user_has_keys(username):
                    self.show_key_generation_dialog(username)
                else:
                    self.open_chat_window(username)
            else:
                self.show_status(f"Login failed: {message}", True)
                self.set_ui_enabled(True)
                
        except Exception as e:
            self.show_status(f"Error: {str(e)}", True)
            self.set_ui_enabled(True)
    
    def show_key_generation_dialog(self, username: str):
        """Show key generation dialog for new users."""
        reply = QMessageBox.question(
            self,
            "Generate Encryption Keys",
            f"Welcome {username}!\n\n"
            "This appears to be your first login. We need to generate\n"
            "your encryption keys for secure messaging.\n\n"
            "This will create:\n"
            "• ED25519 keys for digital signatures\n"
            "• X25519 keys for key exchange\n\n"
            "Your private keys will be stored securely on this device only.\n"
            "Would you like to generate your keys now?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )
        
        if reply == QMessageBox.Yes:
            self.generate_user_keys(username)
        else:
            self.network_client.logout_user()
            self.show_status("Login cancelled - keys are required for messaging", True)
            self.set_ui_enabled(True)
    
    def generate_user_keys(self, username: str):
        """Generate and upload user's cryptographic keys."""
        try:
            self.show_status("Generating encryption keys...")
            
            # Generate keys locally
            public_keys = self.key_manager.generate_keys_for_user(username)
            
            self.show_status("Uploading public keys to server...")
            
            # Upload public keys to server
            success, message = self.network_client.upload_my_public_keys(
                public_keys['ed25519_public_key'],
                public_keys['x25519_public_key']
            )
            
            if success:
                self.show_status("Keys generated successfully!", False)
                QMessageBox.information(
                    self,
                    "Keys Generated",
                    "Your encryption keys have been generated and uploaded!\n\n"
                    "🔐 Your private keys are stored securely on this device\n"
                    "📤 Your public keys are available on the server\n\n"
                    "You can now send and receive encrypted messages!"
                )
                self.open_chat_window(username)
            else:
                QMessageBox.warning(
                    self,
                    "Key Upload Failed",
                    f"Failed to upload keys to server: {message}\n\n"
                    "Please try logging in again."
                )
                self.network_client.logout_user()
                self.set_ui_enabled(True)
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "Key Generation Error",
                f"Failed to generate encryption keys: {str(e)}\n\n"
                "Please try logging in again."
            )
            self.network_client.logout_user()
            self.set_ui_enabled(True)
    
    def open_chat_window(self, username: str):
        """Open the main chat window."""
        try:
            self.chat_window = ChatWindow(self.network_client, self.key_manager, username)
            self.chat_window.show()
            self.hide()  # Hide login window
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open chat window: {str(e)}"
            )
            self.set_ui_enabled(True)
    
    def show_register_window(self):
        """Show the registration window."""
        self.register_window = RegisterWindow(self.network_client)
        self.register_window.registration_successful.connect(self.on_registration_successful)
        self.register_window.show()
    
    def on_registration_successful(self, username: str):
        """Handle successful registration."""
        self.username_input.setText(username)
        self.password_input.clear()
        self.password_input.setFocus()
        self.show_status("Registration successful! Please log in.", False)
    
    def set_ui_enabled(self, enabled: bool):
        """Enable or disable UI elements."""
        self.username_input.setEnabled(enabled)
        self.password_input.setEnabled(enabled)
        self.login_button.setEnabled(enabled)
        self.register_button.setEnabled(enabled)
    
    def closeEvent(self, event):
        """Handle window close event."""
        if self.network_client.is_logged_in:
            self.network_client.logout_user()
        event.accept()
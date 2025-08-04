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
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title_label = QLabel("🔐 Secure Messaging")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Arial", 16, QFont.Bold)
        title_label.setFont(title_font)
        main_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("End-to-End Encrypted Communication")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_font = QFont("Arial", 10)
        subtitle_label.setFont(subtitle_font)
        main_layout.addWidget(subtitle_label)
        
        # Add spacing
        main_layout.addSpacing(25)
        
        # Username section
        username_label = QLabel("Username:")
        username_font = QFont("Arial", 11)
        username_label.setFont(username_font)
        main_layout.addWidget(username_label)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        self.username_input.setFixedHeight(35)
        self.username_input.setFont(QFont("Arial", 11))
        self.username_input.returnPressed.connect(self.handle_login)
        main_layout.addWidget(self.username_input)
        
        # Add small spacing
        main_layout.addSpacing(10)
        
        # Password section
        password_label = QLabel("Password:")
        password_label.setFont(username_font)
        main_layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setFixedHeight(35)
        self.password_input.setFont(QFont("Arial", 11))
        self.password_input.returnPressed.connect(self.handle_login)
        main_layout.addWidget(self.password_input)
        
        # Add spacing before buttons
        main_layout.addSpacing(20)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.setFixedHeight(40)
        self.login_button.setFont(QFont("Arial", 11, QFont.Bold))
        self.login_button.clicked.connect(self.handle_login)
        button_layout.addWidget(self.login_button)
        
        # Register button
        self.register_button = QPushButton("Create Account")
        self.register_button.setFixedHeight(40)
        self.register_button.setFont(QFont("Arial", 11, QFont.Bold))
        self.register_button.clicked.connect(self.show_register_window)
        button_layout.addWidget(self.register_button)
        
        main_layout.addLayout(button_layout)
        
        # Add spacing
        main_layout.addSpacing(15)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setFont(QFont("Arial", 10))
        main_layout.addWidget(self.status_label)
        
        # Add stretch at the bottom
        main_layout.addStretch()
        
    def show_status(self, message: str, is_error: bool = False):
        """Show status message."""
        self.status_label.setText(message)
        if is_error:
            self.status_label.setStyleSheet("color: red;")
        else:
            self.status_label.setStyleSheet("color: green;")
    
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
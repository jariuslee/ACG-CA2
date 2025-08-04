# ui/chat_window.py - Clean Main Chat Interface
# IT2504 Applied Cryptography Assignment 2

from PyQt5.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, 
                             QListWidget, QListWidgetItem, QTextEdit, QLineEdit, 
                             QPushButton, QLabel, QSplitter, QFrame, QMessageBox,
                             QGroupBox, QScrollArea)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QTextCursor

from crypto_utils import ClientCrypto
import datetime

class ChatWindow(QMainWindow):
    """
    Clean and intuitive main chat interface for secure messaging.
    """
    
    def __init__(self, network_client, key_manager, username):
        super().__init__()
        self.network_client = network_client
        self.key_manager = key_manager
        self.username = username
        self.crypto = ClientCrypto()
        
        self.current_chat_user = None
        self.users_list = []
        
        self.setWindowTitle(f"Secure Messaging - {username}")
        self.setMinimumSize(800, 600)
        self.resize(1000, 700)
        
        self.setup_ui()
        self.load_users()
        
        # Set up refresh timer for user list and messages
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
    
    def setup_ui(self):
        """Set up the main chat interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel - User list
        self.setup_user_panel(splitter)
        
        # Right panel - Chat area
        self.setup_chat_panel(splitter)
        
        # Set splitter proportions
        splitter.setSizes([250, 750])
        
    def setup_user_panel(self, parent):
        """Set up the user list panel."""
        user_frame = QFrame()
        user_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-right: 1px solid #dee2e6;
            }
        """)
        user_layout = QVBoxLayout(user_frame)
        user_layout.setContentsMargins(15, 15, 15, 15)
        
        # User panel header
        header_layout = QVBoxLayout()
        
        # Current user info
        user_info_label = QLabel(f"👤 {self.username}")
        user_info_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                font-size: 14px;
                color: #0078d4;
                padding: 8px;
                background-color: #e3f2fd;
                border-radius: 4px;
                margin-bottom: 10px;
            }
        """)
        header_layout.addWidget(user_info_label)
        
        # Online users label
        users_header = QLabel("💬 Online Users")
        users_header.setStyleSheet("font-weight: bold; color: #495057; margin-bottom: 5px;")
        header_layout.addWidget(users_header)
        
        user_layout.addLayout(header_layout)
        
        # Users list
        self.users_list_widget = QListWidget()
        self.users_list_widget.setStyleSheet("""
            QListWidget {
                border: 1px solid #dee2e6;
                border-radius: 4px;
                background-color: white;
                font-size: 13px;
            }
            QListWidget::item {
                padding: 12px 8px;
                border-bottom: 1px solid #f8f9fa;
            }
            QListWidget::item:hover {
                background-color: #f8f9fa;
            }
            QListWidget::item:selected {
                background-color: #e3f2fd;
                color: #0078d4;
                font-weight: 500;
            }
        """)
        self.users_list_widget.itemClicked.connect(self.select_user)
        user_layout.addWidget(self.users_list_widget)
        
        # Refresh button
        self.refresh_button = QPushButton("🔄 Refresh Users")
        self.refresh_button.clicked.connect(self.refresh_users)
        self.refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                margin-top: 10px;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
        """)
        user_layout.addWidget(self.refresh_button)
        
        # Logout button
        self.logout_button = QPushButton("🚪 Logout")
        self.logout_button.clicked.connect(self.handle_logout)
        self.logout_button.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                margin-top: 5px;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        user_layout.addWidget(self.logout_button)
        
        parent.addWidget(user_frame)
    
    def setup_chat_panel(self, parent):
        """Set up the chat panel."""
        chat_frame = QFrame()
        chat_layout = QVBoxLayout(chat_frame)
        chat_layout.setContentsMargins(15, 15, 15, 15)
        
        # Chat header
        self.chat_header = QLabel("Select a user to start chatting")
        self.chat_header.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #495057;
                padding: 15px;
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                margin-bottom: 10px;
            }
        """)
        chat_layout.addWidget(self.chat_header)
        
        # Messages display area
        self.messages_display = QTextEdit()
        self.messages_display.setReadOnly(True)
        self.messages_display.setStyleSheet("""
            QTextEdit {
                border: 1px solid #dee2e6;
                border-radius: 4px;
                background-color: white;
                font-size: 13px;
                line-height: 1.4;
            }
        """)
        chat_layout.addWidget(self.messages_display)
        
        # Message input area
        input_frame = QFrame()
        input_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
                margin-top: 10px;
            }
        """)
        input_layout = QVBoxLayout(input_frame)
        
        # Input field and send button layout
        message_layout = QHBoxLayout()
        
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        self.message_input.setEnabled(False)
        self.message_input.returnPressed.connect(self.send_message)
        self.message_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                font-size: 14px;
                border: 1px solid #ced4da;
            }
        """)
        
        self.send_button = QPushButton("🔒 Send Encrypted")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setEnabled(False)
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                font-weight: 600;
                padding: 10px 15px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        
        message_layout.addWidget(self.message_input)
        message_layout.addWidget(self.send_button)
        input_layout.addLayout(message_layout)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #6c757d; font-size: 12px; margin-top: 5px;")
        input_layout.addWidget(self.status_label)
        
        chat_layout.addWidget(input_frame)
        
        parent.addWidget(chat_frame)
    
    def load_users(self):
        """Load users from server."""
        self.show_status("Loading users...")
        try:
            users = self.network_client.get_all_users()
            self.users_list = users
            self.update_users_display()
            self.show_status(f"Loaded {len(users)} users")
        except Exception as e:
            self.show_status(f"Error loading users: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to load users: {str(e)}")
    
    def update_users_display(self):
        """Update the users list display."""
        self.users_list_widget.clear()
        
        if not self.users_list:
            item = QListWidgetItem("No other users online")
            item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            self.users_list_widget.addItem(item)
            return
        
        for user in self.users_list:
            username = user['username']
            user_id = user['user_id']
            
            # Create display text
            display_text = f"👤 {username}"
            
            item = QListWidgetItem(display_text)
            item.setData(Qt.UserRole, user)  # Store user data
            self.users_list_widget.addItem(item)
    
    def add_received_message(self, sender: str, message: str, timestamp: str):
        """Add received message to the chat display."""
        formatted_message = f"""
        <div style="margin: 8px 0; padding: 8px; background-color: #f0fff0; 
             border-left: 3px solid #28a745; border-radius: 4px;">
            <div style="font-weight: bold; color: #28a745; font-size: 12px;">
                📥 {sender} - {timestamp}
            </div>
            <div style="margin-top: 4px; color: #333; font-size: 13px;">
                {message}
            </div>
        </div>
        """
        
        # Add to display
        cursor = self.messages_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(formatted_message)
        self.messages_display.setTextCursor(cursor)
        self.messages_display.ensureCursorVisible()
    
    def refresh_users(self):
        """Refresh the users list."""
        self.load_users()
    
    def select_user(self, item):
        """Handle user selection."""
        user_data = item.data(Qt.UserRole)
        if not user_data:
            return
        
        self.current_chat_user = user_data
        username = user_data['username']
        
        # Update chat header
        self.chat_header.setText(f"🔒 Secure Chat with {username}")
        self.chat_header.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #0078d4;
                padding: 15px;
                background-color: #e3f2fd;
                border: 1px solid #bbdefb;
                border-radius: 4px;
                margin-bottom: 10px;
            }
        """)
        
        # Enable message input
        self.message_input.setEnabled(True)
        self.send_button.setEnabled(True)
        self.message_input.setFocus()
        
        # Clear messages and show encryption info
        self.messages_display.clear()
        self.add_system_message(f"🔐 End-to-end encrypted chat with {username}")
        self.add_system_message("Messages are encrypted with AES-256-GCM and signed with ED25519")
        
        # Load existing messages with this user
        self.load_messages_with_user(username)
        
        self.show_status(f"Ready to chat with {username}")
    
    def load_messages_with_user(self, username: str):
        """Load and decrypt messages with specific user."""
        try:
            # Get all my messages
            all_messages = self.network_client.get_my_messages()
            
            # Filter messages from this specific user
            user_messages = [msg for msg in all_messages if msg['sender_username'] == username]
            
            if not user_messages:
                self.add_system_message("No previous messages with this user")
                return
            
            self.add_system_message(f"Loading {len(user_messages)} previous messages...")
            
            # Get sender's public keys for decryption
            sender_keys = self.network_client.get_user_public_keys(username)
            if not sender_keys:
                self.add_system_message("⚠️ Cannot load messages - sender's keys not available")
                return
            
            # Get my private keys for decryption
            my_crypto_keys = self.key_manager.get_my_encryption_keys(self.username)
            if not my_crypto_keys:
                self.add_system_message("⚠️ Cannot decrypt messages - your keys not available")
                return
            
            # Decrypt and display each message
            for msg in reversed(user_messages):  # Show oldest first
                try:
                    # Decrypt the message
                    decrypted_message, signature_valid = self.crypto.process_message_from_server(
                        msg['encrypted_message'],
                        msg['nonce'],
                        msg['signature'],
                        sender_keys['x25519_public_key'],
                        my_crypto_keys['x25519_private'],
                        sender_keys['ed25519_public_key']
                    )
                    
                    # Add to display
                    timestamp = msg.get('timestamp', 'Unknown time')
                    if signature_valid:
                        self.add_received_message(username, decrypted_message, timestamp)
                    else:
                        self.add_system_message(f"⚠️ Message from {username} failed signature verification!")
                        
                except Exception as e:
                    self.add_system_message(f"❌ Failed to decrypt message from {username}: {str(e)}")
            
            self.add_system_message("📨 Message history loaded")
            
        except Exception as e:
            self.add_system_message(f"❌ Error loading messages: {str(e)}")
    
    def refresh_data(self):
        """Refresh both users and messages."""
        if self.current_chat_user:
            # Check for new messages from current chat user
            self.check_for_new_messages()
        
        # Refresh user list less frequently
        import time
        if not hasattr(self, 'last_user_refresh') or time.time() - self.last_user_refresh > 30:
            self.refresh_users()
            self.last_user_refresh = time.time()
    
    def check_for_new_messages(self):
        """Check for new messages from current chat user."""
        if not self.current_chat_user:
            return
        
        try:
            username = self.current_chat_user['username']
            
            # Get latest messages
            all_messages = self.network_client.get_my_messages()
            user_messages = [msg for msg in all_messages if msg['sender_username'] == username]
            
            # Check if we have new messages (this is a simple check - in production you'd track message IDs)
            if not hasattr(self, 'last_message_count'):
                self.last_message_count = {}
            
            current_count = len(user_messages)
            last_count = self.last_message_count.get(username, 0)
            
            if current_count > last_count:
                # We have new messages
                new_messages = user_messages[:current_count - last_count]
                
                # Get keys for decryption
                sender_keys = self.network_client.get_user_public_keys(username)
                my_crypto_keys = self.key_manager.get_my_encryption_keys(self.username)
                
                if sender_keys and my_crypto_keys:
                    for msg in reversed(new_messages):  # Process newest first, display in order
                        try:
                            decrypted_message, signature_valid = self.crypto.process_message_from_server(
                                msg['encrypted_message'],
                                msg['nonce'],
                                msg['signature'],
                                sender_keys['x25519_public_key'],
                                my_crypto_keys['x25519_private'],
                                sender_keys['ed25519_public_key']
                            )
                            
                            if signature_valid:
                                timestamp = msg.get('timestamp', 'Just now')
                                self.add_received_message(username, decrypted_message, timestamp)
                            else:
                                self.add_system_message(f"⚠️ New message failed signature verification!")
                                
                        except Exception as e:
                            self.add_system_message(f"❌ Failed to decrypt new message: {str(e)}")
                
                self.last_message_count[username] = current_count
            
        except Exception as e:
            # Don't spam errors for refresh issues
            pass
    
    def send_message(self):
        """Send encrypted message."""
        if not self.current_chat_user:
            return
        
        message_text = self.message_input.text().strip()
        if not message_text:
            return
        
        recipient_username = self.current_chat_user['username']
        recipient_id = self.current_chat_user['user_id']
        
        print(f"🔍 DEBUG: Sending to {recipient_username} (ID: {recipient_id})")
        
        try:
            self.show_status("Encrypting message...")
            self.send_button.setEnabled(False)
            
            # Get recipient's public keys from server
            recipient_keys = self.network_client.get_user_public_keys(recipient_username)
            if not recipient_keys:
                QMessageBox.warning(self, "Error", f"Cannot get public keys for {recipient_username}")
                self.send_button.setEnabled(True)
                return
            
            print(f"🔍 DEBUG: Got recipient keys: {list(recipient_keys.keys())}")
            
            # Get my private keys
            my_crypto_keys = self.key_manager.get_my_encryption_keys(self.username)
            if not my_crypto_keys:
                QMessageBox.critical(self, "Error", "Cannot access your private keys")
                self.send_button.setEnabled(True)
                return
            
            print(f"🔍 DEBUG: Got my keys: {list(my_crypto_keys.keys())}")
            
            # Encrypt and sign the message
            print("🔍 DEBUG: Encrypting message...")
            encrypted_package = self.crypto.prepare_message_for_server(
                message_text,
                recipient_keys['x25519_public_key'],
                my_crypto_keys['x25519_private'],
                my_crypto_keys['ed25519_private']
            )
            
            print(f"🔍 DEBUG: Encryption complete, package keys: {list(encrypted_package.keys())}")
            
            self.show_status("Sending encrypted message...")
            
            # Send to server
            print(f"🔍 DEBUG: Sending to server...")
            success, response = self.network_client.send_encrypted_message(
                recipient_username,
                encrypted_package['encrypted_message'],
                encrypted_package['signature'],
                encrypted_package['nonce']
            )
            
            print(f"🔍 DEBUG: Server response - Success: {success}, Response: {response}")
            
            if success:
                # Add to display
                self.add_message_to_display("You", message_text, True)
                self.message_input.clear()
                self.show_status("Message sent successfully")
            else:
                QMessageBox.warning(self, "Send Failed", f"Failed to send message: {response}")
                self.show_status("Failed to send message")
            
        except Exception as e:
            print(f"🔍 DEBUG: Exception during send: {e}")
            QMessageBox.critical(self, "Encryption Error", f"Failed to encrypt message: {str(e)}")
            self.show_status("Encryption failed")
        
        finally:
            self.send_button.setEnabled(True)
    
    def add_message_to_display(self, sender: str, message: str, is_sent: bool):
        """Add message to the chat display."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        if is_sent:
            color = "#0078d4"
            prefix = "📤"
        else:
            color = "#28a745"
            prefix = "📥"
        
        # Format message
        formatted_message = f"""
        <div style="margin: 8px 0; padding: 8px; background-color: {'#f0f8ff' if is_sent else '#f0fff0'}; 
             border-left: 3px solid {color}; border-radius: 4px;">
            <div style="font-weight: bold; color: {color}; font-size: 12px;">
                {prefix} {sender} - {timestamp}
            </div>
            <div style="margin-top: 4px; color: #333; font-size: 13px;">
                {message}
            </div>
        </div>
        """
        
        # Add to display
        cursor = self.messages_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(formatted_message)
        self.messages_display.setTextCursor(cursor)
        self.messages_display.ensureCursorVisible()
    
    def add_system_message(self, message: str):
        """Add system message to display."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        formatted_message = f"""
        <div style="margin: 4px 0; padding: 6px; background-color: #fff3cd; 
             border-left: 3px solid #ffc107; border-radius: 4px;">
            <div style="color: #856404; font-size: 12px; font-style: italic;">
                ℹ️ {message} - {timestamp}
            </div>
        </div>
        """
        
        cursor = self.messages_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(formatted_message)
        self.messages_display.setTextCursor(cursor)
        self.messages_display.ensureCursorVisible()
    
    def show_status(self, message: str):
        """Update status label."""
        self.status_label.setText(message)
    
    def handle_logout(self):
        """Handle logout."""
        reply = QMessageBox.question(
            self,
            "Logout",
            "Are you sure you want to logout?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.network_client.logout_user()
            self.close()
    
    def closeEvent(self, event):
        """Handle window close."""
        if hasattr(self, 'refresh_timer'):
            self.refresh_timer.stop()
        
        if self.network_client.is_logged_in:
            self.network_client.logout_user()
        
        event.accept()
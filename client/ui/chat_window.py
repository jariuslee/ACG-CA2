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
        
        # Initialize tracking sets
        self.displayed_message_ids = set()
        self.sent_message_tracker = set()
        
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
    
    def refresh_users_only(self):
        """Refresh only the users list, not message history."""
        try:
            users = self.network_client.get_all_users()
            self.users_list = users
            self.update_users_display()
        except Exception as e:
            print(f"Error refreshing users: {e}")
    
    def refresh_users(self):
        """Refresh the users list (called by button)."""
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
        
        # Clear displayed message IDs for fresh loading
        if hasattr(self, 'displayed_message_ids'):
            self.displayed_message_ids.clear()
        
        # Clear sent message tracker for fresh tracking
        if hasattr(self, 'sent_message_tracker'):
            self.sent_message_tracker.clear()
        
        self.add_system_message(f"🔐 End-to-end encrypted chat with {username}")
        self.add_system_message("Messages are encrypted with AES-256-GCM and signed with ED25519")
        
        # Load existing messages with this user
        self.load_messages_with_user(username)
        
        self.show_status(f"Ready to chat with {username}")
    
    def load_messages_with_user(self, username: str):
        """Load and decrypt messages with specific user (both sent and received)."""
        try:
            # Get all my messages
            all_messages = self.network_client.get_my_messages()
            
            # Filter messages to/from this specific user
            user_messages = []
            for msg in all_messages:
                # Check if message is between me and this user
                if (msg['sender_username'] == username and msg['recipient_username'] == self.username) or \
                   (msg['sender_username'] == self.username and msg['recipient_username'] == username):
                    user_messages.append(msg)
            
            if not user_messages:
                self.add_system_message("No previous messages with this user")
                return
            
            self.add_system_message(f"Loading {len(user_messages)} previous messages...")
            
            # Get keys for both users
            sender_keys = self.network_client.get_user_public_keys(username)
            my_crypto_keys = self.key_manager.get_my_encryption_keys(self.username)
            
            if not sender_keys or not my_crypto_keys:
                self.add_system_message("⚠️ Cannot load messages - keys not available")
                return
            
            # Sort messages by timestamp (oldest first)
            user_messages.sort(key=lambda x: x.get('timestamp', 0))
            
            # Decrypt and display each message
            for msg in user_messages:
                try:
                    # Determine if this message was sent by me or received
                    is_sent = msg['sender_username'] == self.username
                    sender_name = "You" if is_sent else msg['sender_username']
                    
                    # Create unique message ID to prevent duplicates
                    message_id = f"{msg['message_id']}_{msg['sender_username']}_{msg['timestamp']}"
                    if message_id in self.displayed_message_ids:
                        continue
                    
                    if is_sent:
                        # For sent messages, we need to decrypt using recipient's public key
                        # But we need to get the recipient's keys
                        recipient_keys = self.network_client.get_user_public_keys(msg['recipient_username'])
                        if not recipient_keys:
                            self.add_system_message(f"⚠️ Cannot decrypt sent message - recipient keys not available")
                            continue
                        
                        # Get my own public keys for signature verification
                        my_public_keys = self.key_manager.get_my_public_keys(self.username)
                        if not my_public_keys:
                            self.add_system_message(f"⚠️ Cannot verify sent message - your public keys not available")
                            continue
                        
                        # Decrypt using recipient's public key and my private key
                        decrypted_message, signature_valid = self.crypto.process_message_from_server(
                            msg['encrypted_message'],
                            msg['nonce'],
                            msg['signature'],
                            recipient_keys['x25519_public_key'],
                            my_crypto_keys['x25519_private'],
                            my_public_keys['ed25519_public']  # My public key for signature verification
                        )
                    else:
                        # For received messages, decrypt using sender's public key
                        decrypted_message, signature_valid = self.crypto.process_message_from_server(
                            msg['encrypted_message'],
                            msg['nonce'],
                            msg['signature'],
                            sender_keys['x25519_public_key'],
                            my_crypto_keys['x25519_private'],
                            sender_keys['ed25519_public_key']
                        )
                    
                    if decrypted_message:
                        # Add to display with correct styling
                        self.add_message_to_display(sender_name, decrypted_message, is_sent)
                        self.displayed_message_ids.add(message_id)
                        
                        if not is_sent and not signature_valid:
                            self.add_system_message(f"⚠️ Message from {sender_name} failed signature verification!")
                    else:
                        self.add_system_message(f"❌ Failed to decrypt message from {sender_name}")
                        
                except Exception as e:
                    self.add_system_message(f"❌ Error processing message: {str(e)}")
            
            self.add_system_message("📨 Message history loaded")
            
        except Exception as e:
            self.add_system_message(f"❌ Error loading messages: {str(e)}")
        
        # Initialize the message count for this user to prevent re-displaying loaded messages
        if not hasattr(self, 'last_message_count'):
            self.last_message_count = {}
        self.last_message_count[username] = len(user_messages)
    
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
            
            # Filter messages between me and this user
            user_messages = []
            for msg in all_messages:
                if (msg['sender_username'] == username and msg['recipient_username'] == self.username) or \
                   (msg['sender_username'] == self.username and msg['recipient_username'] == username):
                    user_messages.append(msg)
            
            # Check if we have new messages
            if not hasattr(self, 'last_message_count'):
                self.last_message_count = {}
            
            current_count = len(user_messages)
            last_count = self.last_message_count.get(username, 0)
            
            if current_count > last_count:
                # We have new messages
                new_messages = user_messages[last_count:]  # Get only the new ones
                
                # Get keys for decryption
                sender_keys = self.network_client.get_user_public_keys(username)
                my_crypto_keys = self.key_manager.get_my_encryption_keys(self.username)
                my_public_keys = self.key_manager.get_my_public_keys(self.username)
                
                if sender_keys and my_crypto_keys and my_public_keys:
                    for msg in new_messages:
                        try:
                            # Determine if this is a sent or received message
                            is_sent = msg['sender_username'] == self.username
                            sender_name = "You" if is_sent else msg['sender_username']
                            
                            # Create unique message ID
                            message_id = f"{msg['message_id']}_{msg['sender_username']}_{msg['timestamp']}"
                            
                            # Skip if we've already displayed this message
                            if message_id in self.displayed_message_ids:
                                continue
                            
                            # For sent messages, check if we've already tracked this as sent
                            if is_sent:
                                # Try to decrypt the message to get its content for tracking
                                try:
                                    recipient_keys = self.network_client.get_user_public_keys(msg['recipient_username'])
                                    my_crypto_keys = self.key_manager.get_my_encryption_keys(self.username)
                                    my_public_keys = self.key_manager.get_my_public_keys(self.username)
                                    
                                    if recipient_keys and my_crypto_keys and my_public_keys:
                                        decrypted_content, _ = self.crypto.process_message_from_server(
                                            msg['encrypted_message'],
                                            msg['nonce'],
                                            msg['signature'],
                                            recipient_keys['x25519_public_key'],
                                            my_crypto_keys['x25519_private'],
                                            my_public_keys['ed25519_public']
                                        )
                                        
                                        if decrypted_content:
                                            # Create the same key format used when sending
                                            sent_message_key = f"{msg['sender_username']}_{msg['recipient_username']}_{decrypted_content}"
                                            if sent_message_key in self.sent_message_tracker:
                                                continue  # Skip this message as we already displayed it when sending
                                except:
                                    pass  # If decryption fails, continue with normal processing
                            
                            if is_sent:
                                # For sent messages, decrypt using recipient's public key
                                recipient_keys = self.network_client.get_user_public_keys(msg['recipient_username'])
                                if not recipient_keys:
                                    continue
                                
                                decrypted_message, signature_valid = self.crypto.process_message_from_server(
                                    msg['encrypted_message'],
                                    msg['nonce'],
                                    msg['signature'],
                                    recipient_keys['x25519_public_key'],
                                    my_crypto_keys['x25519_private'],
                                    my_public_keys['ed25519_public']
                                )
                            else:
                                # For received messages, decrypt using sender's public key
                                decrypted_message, signature_valid = self.crypto.process_message_from_server(
                                    msg['encrypted_message'],
                                    msg['nonce'],
                                    msg['signature'],
                                    sender_keys['x25519_public_key'],
                                    my_crypto_keys['x25519_private'],
                                    sender_keys['ed25519_public_key']
                                )
                            
                            if decrypted_message:
                                self.add_message_to_display(sender_name, decrypted_message, is_sent)
                                self.displayed_message_ids.add(message_id)
                                
                                if not is_sent and not signature_valid:
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
                # Create a unique identifier for this sent message
                sent_message_key = f"{self.username}_{recipient_username}_{message_text}"
                
                # Add to display immediately
                self.add_message_to_display("You", message_text, True)
                
                # Track this sent message to prevent it from being displayed again by refresh
                self.sent_message_tracker.add(sent_message_key)
                
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
        """Add message to the chat display with proper line breaks and spacing."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        if is_sent:
            color = "#0078d4"
            prefix = "📤"
            bg_color = "#f0f8ff"
        else:
            color = "#28a745"
            prefix = "📥"
            bg_color = "#f0fff0"
        
        # FIXED: Format message with proper HTML structure and explicit spacing
        formatted_message = f'''<div style="margin: 12px 0; padding: 12px; background-color: {bg_color}; border-left: 4px solid {color}; border-radius: 8px; font-family: 'Segoe UI', Arial, sans-serif; display: block;">
<div style="font-weight: bold; color: {color}; font-size: 12px; margin-bottom: 8px; display: block;">
{prefix} {sender} - {timestamp}
</div>
<div style="color: #333; font-size: 14px; line-height: 1.6; word-wrap: break-word; display: block;">
{message}
</div>
</div>
<div style="height: 8px; display: block;"></div>'''
        
        # Add to display with proper cursor handling
        cursor = self.messages_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(formatted_message)
        self.messages_display.setTextCursor(cursor)
        self.messages_display.ensureCursorVisible()
        
        # Force the display to update
        self.messages_display.repaint()
    
    def add_system_message(self, message: str):
        """Add system message to display with proper line breaks and spacing."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        # FIXED: Format system message with proper HTML structure and explicit spacing
        formatted_message = f'''<div style="margin: 8px 0; padding: 10px; background-color: #fff3cd; border-left: 3px solid #ffc107; border-radius: 6px; font-family: 'Segoe UI', Arial, sans-serif; display: block;">
<div style="color: #856404; font-size: 12px; font-style: italic; display: block;">
ℹ️ {message} - {timestamp}
</div>
</div>
<div style="height: 6px; display: block;"></div>'''
        
        cursor = self.messages_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(formatted_message)
        self.messages_display.setTextCursor(cursor)
        self.messages_display.ensureCursorVisible()
        
        # Force the display to update
        self.messages_display.repaint()
    
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
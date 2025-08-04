# main.py - Main PyQt5 Application Entry Point
# IT2504 Applied Cryptography Assignment 2

import sys
import os
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

# Import our UI windows
from ui.login_window import LoginWindow
from network_client import NetworkClient

class SecureMessagingApp:
    """
    Main application controller for the secure messaging system.
    Coordinates between UI, cryptography, and network communication.
    """
    
    def __init__(self):
        """Initialize the main application."""
        self.app = QApplication(sys.argv)
        self.network_client = NetworkClient()
        
        # Set application properties
        self.app.setApplicationName("Secure Messaging System")
        self.app.setApplicationVersion("1.0")
        self.app.setOrganizationName("IT2504 Applied Cryptography")
        
        # Set global font for clean appearance
        font = QFont("Segoe UI", 10)
        self.app.setFont(font)
        
        # Apply clean stylesheet
        self.apply_global_stylesheet()
        
        print("🚀 Secure Messaging Application Starting...")
        
    def apply_global_stylesheet(self):
        """Apply clean, consistent stylesheet."""
        stylesheet = """
        QMainWindow {
            background-color: #f0f0f0;
        }
        
        QWidget {
            background-color: white;
        }
        
        QLineEdit {
            border: 2px solid #d0d0d0;
            border-radius: 4px;
            padding: 8px 12px;
            font-size: 12px;
            background-color: white;
            color: #333333;
        }
        
        QLineEdit:focus {
            border-color: #0078d4;
            outline: none;
        }
        
        QPushButton {
            background-color: #0078d4;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 10px 20px;
            font-size: 12px;
            font-weight: bold;
        }
        
        QPushButton:hover {
            background-color: #106ebe;
        }
        
        QPushButton:pressed {
            background-color: #005a9e;
        }
        
        QPushButton:disabled {
            background-color: #cccccc;
            color: #666666;
        }
        
        QLabel {
            color: #333333;
            background-color: transparent;
        }
        """
        
        self.app.setStyleSheet(stylesheet)
    
    def show_error_message(self, title: str, message: str):
        """Show error message dialog."""
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Critical)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.exec_()
    
    def show_info_message(self, title: str, message: str):
        """Show information message dialog."""
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.exec_()
    
    def check_server_connection(self):
        """Check if the Flask server is running."""
        print("🔍 Checking server connection...")
        if not self.network_client.test_server_connection():
            self.show_error_message(
                "Server Connection Error",
                "Cannot connect to the server!\n\n"
                "Please make sure the Flask server is running:\n"
                "1. Open terminal in the 'server' directory\n"
                "2. Run: python app.py\n"
                "3. Restart this application"
            )
            return False
        
        print("✅ Server connection successful!")
        return True
    
    def run(self):
        """Start the application."""
        # Check server connection first
        if not self.check_server_connection():
            return 1
        
        # Show login window
        self.login_window = LoginWindow(self.network_client)
        self.login_window.show()
        
        # Start the application event loop
        return self.app.exec_()

def main():
    """Main entry point of the application."""
    try:
        # Create and run the application
        app = SecureMessagingApp()
        exit_code = app.run()
        
        print(f"🏁 Application exited with code: {exit_code}")
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n⚠️ Application interrupted by user")
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
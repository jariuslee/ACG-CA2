# Secure Messaging Service (Web Version)

This project is a simple, secure messaging service using Python, Flask, and cryptography. It allows multiple clients (e.g., Alice and Bob) to send and receive messages via a web interface, with the server running on a host machine.

## Features
- Web-based messaging API (Flask)
- Endpoints for sending and retrieving messages
- (Coming soon) End-to-end encryption and digital signatures for message security

## Requirements
- Python 3.8+
- pip

## Installation
1. Clone the repository or download the files.
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Running the Server
Start the web server (on your host PC):
```sh
python web_server.py
```
The server will listen on all interfaces at port 5000.

## API Endpoints

### Send a Message
- **POST** `/send_message`
- **Body (JSON):**
  ```json
  {
    "sender": "Alice",
    "message": "Hello, Bob!"
  }
  ```
- **Response:** `{ "status": "ok" }`

### Get All Messages
- **GET** `/get_messages`
- **Response:**
  ```json
  [
    { "sender": "Alice", "message": "Hello, Bob!" },
    { "sender": "Bob", "message": "Hi, Alice!" }
  ]
  ```

## Testing the API
You can use [Postman](https://www.postman.com/), [curl](https://curl.se/), or a browser extension to test the endpoints.

Example using curl:
```sh
curl -X POST http://localhost:5000/send_message -H "Content-Type: application/json" -d "{\"sender\":\"Alice\",\"message\":\"Hello!\"}"
curl http://localhost:5000/get_messages
```

## Next Steps
- Add cryptography and digital signature verification for secure messaging.
- Build a web frontend for easy browser-based messaging.

---

For any questions, see the code comments in `web_server.py` or contact the project maintainer.

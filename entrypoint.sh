#!/bin/bash
set -e  # Exit on error

# 1️⃣ Ensure the parent directory exists
mkdir -p "$(dirname "$PRIVATE_KEY_PATH")"
mkdir -p "$(dirname "$PUBLIC_KEY_PATH")"

# 2️⃣ Decode Base64 environment variables and create .pem files
echo "$PRIVATE_KEY_BASE64" | base64 --decode > "$PRIVATE_KEY_PATH"
echo "$PUBLIC_KEY_BASE64" | base64 --decode > "$PUBLIC_KEY_PATH"

# 3️⃣ Set correct file permissions
chmod 600 "$PRIVATE_KEY_PATH"  # Secure private key
chmod 644 "$PUBLIC_KEY_PATH"   # Public key readable

# 4️⃣ Start the application
exec java -jar target/application.jar
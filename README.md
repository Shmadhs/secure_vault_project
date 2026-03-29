Secure Password Vault (AES-256 Project)
Network Security - Implementation Project

This is a local password manager I built to practice implementing modern cryptographic standards in Python. The goal was to create a "Zero-Knowledge" storage system where the master password is never saved and the data is protected against both tampering and brute-force attempts.

Security Implementation Details
Key Derivation (Argon2id)
Instead of using standard PBKDF2 or SHA-256 (which are vulnerable to GPU cracking), I used Argon2id.

Why: It’s the current industry winner for password hashing.

Settings: I configured it with a 64MB memory cost. This makes it much harder for an attacker to use specialized hardware (ASICs) or GPUs to try millions of passwords a second.

Encryption (AES-256-GCM)
For the actual data storage, I used AES-256 in GCM (Galois/Counter Mode).

Encryption + Integrity: Most basic tutorials use CBC mode, but I chose GCM because it provides an "Authentication Tag."

Protection: If anyone tries to modify the database file (bit-flipping attacks), the decryption will fail because the tag won't match. It ensures the data hasn't been tampered with.

Database & Forensics
Zero-Knowledge: The master password is used to derive the encryption key but is never stored on disk. I used a "canary" (an encrypted known value) to check if the password is correct during login.

Salt & Pepper: I used a unique 32-byte salt for every vault to prevent rainbow table attacks.

SQLite Security: The app uses the VACUUM command. This is a forensic precaution to ensure that when a password is deleted, the data is physically cleared from the database file rather than just marked as "free space."

Technical Stack
Language: Python 3.x

Libraries: cryptography.io (Hazmat layer for AES-GCM), sqlite3 for local storage, pyperclip for secure clipboard handling.

Randomness: Used secrets module (CSPRNG) for all salt and password generation.

How to Run
Install dependencies: pip install cryptography pyperclip

Run the main script: python password.py

On the first run, you will be prompted to create a Master Password.
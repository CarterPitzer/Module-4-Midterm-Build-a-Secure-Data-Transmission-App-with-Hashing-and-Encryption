Crypto Application

Overview
This project is a Python application demonstrating hashing, symmetric encryption, substitution ciphers, digital signatures, and role-based access control.

Features
User login and role-based access control
SHA-256 hashing
AES encryption and decryption
Caesar cipher
RSA digital signatures

CIA Triad
Confidentiality
AES encryption and role-based access control

Integrity
SHA-256 hashing and digital signature verification

Availability
Login system and controlled access based on user roles

Entropy and Key Generation
AES keys, IVs, and RSA key pairs are generated using secure randomness. High entropy ensures keys cannot be predicted or brute-forced.


How to Run
pip install -r requirements.txt
python main.py

Default Users
carter / password123 / admin
bob / letmein / user

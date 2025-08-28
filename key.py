import secrets

# Generate a secure random secret key
secret_key = secrets.token_hex(32)
print("secret key is:", secret_key)
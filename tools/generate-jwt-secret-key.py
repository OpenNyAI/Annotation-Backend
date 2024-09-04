import secrets

# Generate a random secret key
secret_key = secrets.token_urlsafe(32)

print("JWT_TOKEN_SECRET_KEY:", secret_key)

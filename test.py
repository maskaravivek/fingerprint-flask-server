import argon2
 
# Declare the password as a bytes object
password = b'MySecurePassword'
 
# Hash the password using Argon2
hashed_password = argon2.PasswordHasher(password)
 
# Print the hashed password
print(hashed_password)
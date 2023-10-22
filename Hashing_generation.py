import hashlib

def generate_hashes(input_string):
    sha1_hash = hashlib.sha1(input_string.encode('utf-8')).hexdigest()
    sha256_hash = hashlib.sha256(input_string.encode('utf-8')).hexdigest()
    sha384_hash = hashlib.sha384(input_string.encode('utf-8')).hexdigest()
    sha512_hash = hashlib.sha512(input_string.encode('utf-8')).hexdigest()
    
    return sha1_hash, sha256_hash, sha384_hash, sha512_hash

# Example usage
input_string = input("Enter a string to hash: ")
sha1_hash, sha256_hash, sha384_hash, sha512_hash = generate_hashes(input_string)

print("SHA-1 Hash:", sha1_hash)
print("SHA-256 Hash:", sha256_hash)
print("SHA-384 Hash:", sha384_hash)
print("SHA-512 Hash:", sha512_hash)

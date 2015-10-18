from Crypto.Cipher import AES
import base64

MASTER_KEY = "12345678901234567890123456789012"


def encrypt_val(text):
    secret = AES.new(MASTER_KEY)
    tag_string = (str(text) + (AES.block_size - len(str(text)) % AES.block_size) * "\0")
    cipher_text = base64.b64encode(secret.encrypt(tag_string))

    return cipher_text


def decrypt_val(cipher):
    secret = AES.new(MASTER_KEY)
    decrypted = secret.decrypt(base64.b64decode(cipher))
    result = decrypted.rstrip("\0")
    return result


def main():
    temp = encrypt_val("Hello World")
    print(temp)
    print(decrypt_val(temp))


if __name__ == '__main__':
    main()

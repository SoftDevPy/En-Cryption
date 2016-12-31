import hashlib
import base64
import random

password = input('enter a password to encrypt : ')
salt = input('enter a random number : ')
masterPassword = input('enter your master password : ')


def makeSalt(salt):

    # when called takes the randomm number and uses it as 'salt'
    # to seed the random generator
    random.seed(salt)
    # shash is a hashlib.sha512() object or instance
    shash = hashlib.sha512()
    # since random is already seeded, a random number is generated called randstart
    randstart = random.random()
    # the hashlib object is updated with the bytearray value of the above random generated number
    shash.update(bytearray(str(randstart), 'utf-8'))
    # gsalt is the hexdigest or printed output after the updated() random number
    gsalt = shash.hexdigest()
    return gsalt

gsalt = makeSalt(salt)
print('gsalt', gsalt)


def key_for_acc_pass(masterPassword):

    # use this as encryption/decryption key for the password
    m_pass_ba = bytearray(masterPassword.encode())  # bytearray value of masterPassword
    gsalt_ba = bytearray(gsalt.encode())  # bytearray value of gsalt
    hashed_m_pass_ba = hashlib.sha512()   # the hashlib object
    hashed_m_pass_ba.update(m_pass_ba)   # the hashlib object updated with bytearray value of masterPassword
    hashed_m_pass_ba.update(gsalt_ba)  # the hashlib object updated again with bytearray value of gsalt
    m_pass_ba_hash_str = hashed_m_pass_ba.hexdigest()
    return m_pass_ba_hash_str

encryption_decryption_key = key_for_acc_pass(masterPassword)
print('encryption_decryption_key', encryption_decryption_key)


def encrypt_it(plain_text, encryption_decryption_key):

    # in plain_text pass password
    m_pass_ba_hash_str_ba = bytearray(encryption_decryption_key.encode())  # bytearray value of key
    plain_text_ba = bytearray(plain_text.encode())  # bytearray value of plain text
    cipher_text_ba = bytearray()
    # the XOR value of each item in bytearray of plain text and key in an empty bytearray
    for item in range(len(plain_text)):
        ord_now = plain_text_ba[item] ^ m_pass_ba_hash_str_ba[item]
        cipher_text_ba.append(ord_now)
    cipher_text_ba_b64 = base64.encodebytes(cipher_text_ba)
    cipher_text_ba_b64_str = cipher_text_ba_b64.decode()  # Base-64 encoding
    return cipher_text_ba_b64_str

encrypted = encrypt_it(password, encryption_decryption_key)
print('encrypted', encrypted)


def decrypt_it(get_key, cipher_text_ba_b64_str):

    # decrypts 1st position key against 2nd position encrypted string
    cipher_text_ba_b64_str_decode = base64.b64decode(cipher_text_ba_b64_str)
    m_pass_byte_hash_str = get_key
    m_pass_byte_hash_str_byte = bytearray (m_pass_byte_hash_str.encode())
    get_it_back = []
    for item in range(len(cipher_text_ba_b64_str_decode)):
        re_ord = m_pass_byte_hash_str_byte[item] ^ cipher_text_ba_b64_str_decode [item]
        recovered = chr(re_ord)
        get_it_back.append(recovered)
    plain_text_back = ''.join(get_it_back)
    return plain_text_back


masterPassword = input('enter your master password to decrypt: ')

decrypted = decrypt_it(key_for_acc_pass(masterPassword), encrypted)
print("password decrypted as: ", decrypted)


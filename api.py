import sympy
import hashlib
from binascii import hexlify
from flask import Flask, request, jsonify
import csv
import random
import math


def hash_to_int(x: bytes) -> int:
    hx = hashlib.sha256(x).digest()
    for i in range(11):
        hx += hashlib.sha256(hx).digest()
    return int.from_bytes(hx, 'little')


def sign(p: int, q: int, digest: bytes) -> tuple:
    """
    :param p: part of private key
    :param q: part of private key
    :param digest: message digest to sign
    :return: rabin signature (S: int, U: bytes)
    """
    n = p * q
    i = 0
    while True:
        h = hash_to_int(digest + b'\x00' * i) % n
        lp = q * pow(h, (p + 1) // 4, p) * pow(q, p - 2, p)
        rp = p * pow(h, (q + 1) // 4, q) * pow(p, q - 2, q)
        s = (lp + rp) % n
        if (s * s) % n == h % n:
            break
        i += 1
    return s, b'\x00' * i


def verify(n: int, digest: bytes, s: int, u: bytes) -> bool:
    """
    :param n: rabin public key
    :param digest: digest of signed message
    :param s: S of signature
    :param u: padding U of signature
    """
    return hash_to_int(digest + u) % n == (s * s) % n


bit_length = 1536  # 指定位数
left_privKey = sympy.randprime(2**(bit_length-1), 2**bit_length - 1)
while left_privKey % 4 != 3:
    left_privKey = sympy.randprime(2**(bit_length-1), 2**bit_length - 1)
right_privKey = sympy.randprime(2**(bit_length-1), 2**bit_length - 1)
while right_privKey % 4 != 3:
    right_privKey = sympy.randprime(2**(bit_length-1), 2**bit_length - 1)
print(left_privKey)
print(right_privKey)
pubKey = left_privKey * right_privKey
print(pubKey)
msg = 'Hello World!'
print(msg)
d_msg = hashlib.sha256(msg.encode('utf-8')).digest()
print("d-msg finish!")
sig_s, sig_u = sign(left_privKey, right_privKey, d_msg)
print(sig_s)
print(hexlify(sig_u))
print(verify(pubKey, d_msg, sig_s, sig_u))

print(type(d_msg))
print(type(sig_s))
print(type(sig_u))

file_name = 'student_data.csv'
def read_csv(file_name):
    data = {}
    with open(file_name, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            name = row['Name']
            gpa = row['GPA']
            data[name] = gpa
    return data

# Flask app
app = Flask(__name__)
data = read_csv('student_data.csv')

@app.route('/api/gpa', methods=['GET'])
def get_gpa():
    id = request.args.get('name')
    processed_id = id.replace('_', ' ')
    if processed_id in data:
        gpa = data[processed_id]
        d_gpa = hashlib.sha256(gpa.encode('utf-8')).digest()
        hex_d_gpa = hexlify(d_gpa).decode('utf-8')
        S,U = sign(left_privKey, right_privKey, d_gpa)
        info = {
            'GPA':gpa,

            'Digest':d_gpa.hex(),
            'Signatures':{
                'Rabin':{
                    'PubKey':pubKey,
                    'Sig_S':S,
                    'Sig_U':U.hex()
                }
            }
        }
        return jsonify(info)
    else:
        return jsonify({'error': 'Name not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
    #Test Example:
    #Rachel Williams 1.8
    #http://localhost:5000/api/gpa?name=Rachel_Williams

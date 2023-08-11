import sympy
import hashlib
from binascii import hexlify
from flask import Flask, request, jsonify
import csv
import random
import math
from flask_cors import CORS,cross_origin


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
""""
left_privKey = sympy.randprime(2**(bit_length-1), 2**bit_length - 1)
while left_privKey % 4 != 3:
    left_privKey = sympy.randprime(2**(bit_length-1), 2**bit_length - 1)
right_privKey = sympy.randprime(2**(bit_length-1), 2**bit_length - 1)
while right_privKey % 4 != 3:
    right_privKey = sympy.randprime(2**(bit_length-1), 2**bit_length - 1)

"""
left_privKey = 2156080367722899569999731053453720358158738117017616683882854117204203997378817937284926510479436880215828737085540130441104194724693365379491081914649522326113766759725215373118370592243095071694372728205983601387135121618020530467958335925164512144141818569480084077223911591251585891634203256678214657784010658379966523711311006255131453186089554730058167784424513570695174824923277733401848309182051914509890770698626490876351161830336248987398731951858793163
right_privKey = 1675870484941349616080095187743192261994904021570345583606005913139243357855366776949260184923578051833370077311269301323089375199771191926474223614757357710385131174647689175863115170231367505670541112817232943446992855517130410535240918860280608278456154660429542210971199394631410104353791272169727799001404808725528918278727786541660685348533508675353773671048763433280283920020723025344742622011381008847209174610598655211643554502659273997424991582428377927
#print(left_privKey)
#print(right_privKey)
pubKey = left_privKey * right_privKey
#print(pubKey)
msg_A = 'Hello World!'
msg_B = 'Good Morning BSV Guys!'
msg = msg_A + msg_B
#print(msg)
d_msg = hashlib.sha256(msg.encode('utf-8')).digest()
#print("d-msg finish!")
sig_s, sig_u = sign(left_privKey, right_privKey, d_msg)
#print(sig_s)
#print(hexlify(sig_u))
#print(verify(pubKey, d_msg, sig_s, sig_u))

#print(type(d_msg))
#print(type(sig_s))
#print(type(sig_u))

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
def read_csv_pk(file_name):
    data = {}
    with open(file_name, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            name = row['Name']
            pk = row['PubKey']
            data[name] = pk
    return data

# Flask app
app = Flask(__name__)
CORS(app)
CORS(app,origins = '*')
data = read_csv('student_data.csv')
datapk = read_csv_pk('student_data.csv')

@app.route('/api/gpa', methods=['GET'])
@cross_origin()
def get_gpa(): 
    id = request.args.get('name')
    processed_id = id.replace('_', ' ')
    if processed_id in data:
        gpa = data[processed_id]
        pk = datapk[processed_id]
        d_gpa = hashlib.sha256(gpa.encode('utf-8')).digest()
        d_pk = hashlib.sha256(pk.encode('utf-8')).digest()
        S,U = sign(left_privKey, right_privKey, d_gpa)
        PKS,PKU = sign(left_privKey, right_privKey, d_pk)
        info = {s
            'GPA':gpa,
            'PubKey':pk,

            'DigestGPA':d_gpa.hex(),
            'DigestPK':d_pk.hex(),
            
            'Signatures':{
                'Rabin':{
                    'PubKey':pubKey,
                    'Sig_S':S,
                    'Sig_U':U.hex()
                },
                'RabinPK':{
                    'PubKey':pubKey,
                    'Sig_S':PKS,
                    'Sig_U':PKU.hex()
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
    #http://16.171.36.57:5000/api/gpa?name=Rachel_Williams
    #http://ec2-16-171-36-57.eu-north-1.compute.amazonaws.com:5000/api/gpa?name=Rachel_Williams

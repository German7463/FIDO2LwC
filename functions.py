import json
import socket, hashlib, secrets
from ecdsa import SigningKey, NIST256p
from ecdsa.util import sigdecode_der, sigencode_der
import time
from tinyec import registry
import secrets
from drysponge.drygascon import DryGascon
import random
import os

### funciones útiles ###

def encodePaquete(paquete1):
    return bytes(paquete1.json(),encoding="utf-8")

def decodePaquete(paquete1):
    return json.loads(paquete1.decode('utf-8'))

def recibirPaquete(host,port,actororigen):
    try:
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sckt.settimeout(30.0)
        sckt.bind((host,port))
        print("Creación del socket")
        sckt.listen()
        conn, addr = sckt.accept()
        if actororigen == "rp":
            print("Conexión establecida con la Relying Party.")
        elif actororigen == "cf":
            print("Conexión establecida con el Cliente FIDO.")
        elif actororigen == "authtor":
            print("Conexión establecida con el authenticator.")
        else:
            print("Conexión establecida con un actor desconocido.")
        with conn:
            print(f"Conexión con: {addr}")
            while True:
                paquete = conn.recv(1024)
                print("Se ha recibido el paquete")
                break
            conn.close()
        sckt.close()
    except Exception as e:
        print("Se ha producido un error en la obtención de los datos, se procede a cerrar la conexión.")
        print(e)
        sckt.close()
    
    return decodePaquete(paquete)

def enviarPaquete(paquete,host,port,actordestino):
    try:
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sckt.settimeout(30.0)
        sckt.connect((host, port))
        if actordestino == "rp":
            print("Conexión establecida con la Relying Party.")
        elif actordestino == "cf":
            print("Conexión establecida con el Cliente FIDO.")
        elif actordestino == "authtor":
            print("Conexión establecida con el authenticator.")
        else:
            print("Conexión establecida con un actor desconocido.")
        sckt.sendall(encodePaquete(paquete))
        print("Se ha enviado correctamente el paquete.")
        sckt.close()
    except Exception as e:
        print("Se ha producido un error en la obtención de los datos, se procede a cerrar la conexión.")
        print(e)
        sckt.close()
    
    return 0

def enviar_dato(data,host,port):
    try:
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sckt.settimeout(30.0)
        sckt.connect((host, port))
        print("Conexión establecida.")
        sckt.sendall(data)
        print("Se ha enviado correctamente el dato.")
        sckt.close()
    except Exception as e:
        print("Se ha producido un error en la obtención de los datos, se procede a cerrar la conexión.")
        print(e)
        sckt.close()
    
    return 0

def recibir_dato(host,port):
    try:
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sckt.settimeout(30.0)
        sckt.bind((host,port))
        print("Creación del socket")
        sckt.listen()
        conn, addr = sckt.accept()
        print("Conexión establecida.")
        with conn:
            print(f"Conexión con: {addr}")
            while True:
                data = conn.recv(1024)
                print("Se ha recibido el dato.")
                break
        sckt.close()

    except Exception as e:
        print("Se ha producido un error en la obtención de los datos, se procede a cerrar la conexión.\n")
        print(e)
        sckt.close()
    
    return data

def enviar_datos_dryGascon(plaintext,key,host,port):
    try:
        ciphertext, nonce  = encrypt_DryGASCON(encodePaquete(plaintext),key)

        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sckt.settimeout(30.0)
        sckt.connect((host, port))
        print("Envío cifrado con dryGASCON - Conexión establecida.\n")
        time.sleep(0.01)
        sckt.sendall(ciphertext)
        print("Se ha enviado el texto cifrado.")
        time.sleep(0.01)
        sckt.sendall(nonce)
        print("Se ha enviado el nonce.")
        sckt.close()
    except Exception as e:
        print("Se ha producido un error en la obtención de los datos, se procede a cerrar la conexión.\n")
        print(e)
        sckt.close()
    
    return 0

def recibir_datos_dryGascon(host,port,key):
    try:
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sckt.settimeout(30.0)
        sckt.bind((host,port))
        print("Creación del socket")
        sckt.listen()
        conn, addr = sckt.accept()
        print("Recibo de información cifrado con dryGASCON - Conexión establecida.\n")
        with conn:
            print(f"Conexión con: {addr}")
            while True:
                ciphertext = conn.recv(2048)
                print("Se ha recibido el texto cifrado.")
                nonce = conn.recv(2048)
                print("Se ha recibido el nonce.")
                break
        sckt.close()
        
        plaintext = decrypt_DryGASCON(ciphertext, nonce, key)

    except Exception as e:
        print("Se ha producido un error en la obtención de los datos, se procede a cerrar la conexión.\n")
        print(e)
        sckt.close()
    
    return decodePaquete(plaintext)

def buscar_Credenciales(nombreusuario):
    credentialStoreList = os.listdir(".//CredentialStore")
    flag = False
    for i in credentialStoreList:
        ruta = '.\CredentialStore\\' + i
        with open(ruta) as f:
            data = json.loads(json.loads(f.read()))
            if data['user']['displayName'].strip() == nombreusuario.strip():
                print("Se ha encontrado los datos del usuario ",nombreusuario)
                flag = True
                break
    if flag:
        return data
    else:
        return 0

def buscar_Credenciales_authenticator(nombreusuario):
    credentialSourceList = os.listdir(".//CredentialSources")
    flag = False
    for i in credentialSourceList:
        ruta = '.\CredentialSources\\' + i
        with open(ruta) as f:
            data = json.loads(json.loads(f.read()))
            print(data['userHandle']['displayName'])
            print(type(data['userHandle']['displayName']))
            print(nombreusuario)
            if data['userHandle']['displayName'].strip() == nombreusuario.strip():
                print("Se ha encontrado los datos del usuario ",nombreusuario)
                flag = True
                break
    if flag:
        return data
    else:
        return 0


### funciones de cifrado/descifrado y generación de claves ###

def comprimir_clavePubECC(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2: ]

curve = registry.get_curve('brainpoolP256r1')

def generarClavePrivECC():
    return secrets.randbelow(curve.field.n)

def generarClavePubECC(clavePriv):
    return clavePriv * curve.g

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def generarClavePrivECDSA():
    return SigningKey.generate(curve=NIST256p)

def generarClavePubECDSA(clavePriv):
    return clavePriv.verifying_key

def firmar_ECDSA(plaintext, llavePriv):
    return llavePriv.sign(plaintext,sigencode= sigencode_der)

def verificar_ECDSA(plaintext, firma, llavePub):
    return llavePub.verify(firma,plaintext,sigdecode= sigdecode_der)

#Python-oauth2/oauth2/__init__.py https://github.com/joestump/python-oauth2/blob/81326a07d1936838d844690b468660452aafdea9/oauth2/__init__.py#L165
def generate_nonce(length):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def encrypt_DryGASCON(msg, secretKey):
    nonce = bytes(generate_nonce(16), encoding='utf-8')
    dryGasconCipher = DryGascon.DryGascon256().instance()
    ciphertext = dryGasconCipher.encrypt(secretKey,nonce,msg)
    return (ciphertext,nonce)

def decrypt_DryGASCON(ciphertext, nonce, secretKey):
    dryGasconCipher = DryGascon.DryGascon256().instance()
    plaintext = dryGasconCipher.decrypt(secretKey,nonce,ciphertext)
    return plaintext

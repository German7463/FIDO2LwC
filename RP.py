from random import randint
import classes as c
import functions as f
from pydantic import *
import json
from ecdsa import VerifyingKey, NIST256p
import ascon as asc
# from Crypto.Hash import SHA256

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 7800   # Puerto de comunicación con el Cliente FIDO

print("\n")
print("*****************************************************")
print("****************    Relying Party    ****************")
print("*****************************************************")
print("\n")

opcion = f.recibir_dato(HOST,PORT-3).decode('ascii')

print("Introduzca el dominio del servidor: ")
domain = "uah.es"

if opcion == '1':

    #################### Fase de Registro ####################
    print("**************** Fase de Registro ****************")

    ############# Fase de Registro --- Parte 0: Solicitud de registro, recibo del usuario. #############
    print("Fase de Registro --- Parte 0: Solicitud de registro, recibo del usuario. \n")

    username = f.recibir_dato(HOST, PORT-1)

    origen1 = c.origin(host="80.26.225.82", domain=str("www." + domain), port=7800)
    usuario1 = c.usuario(userID=randint(1000000,9999999), displayName=username)
    pubkeycp1 = c.pubKeyCredParams()

    paquetePaso1 = c.createRegistration(origin=origen1, rpid=domain, user=usuario1, challenge="abcdefg", timeout=6.5, pubKeyCredParams=pubkeycp1)

    ############# Fase de Registro --- Paso 1: Envío de la información de la RP ###############
    print("Fase de Registro --- Paso 1: Envío de la información de la Relying Party.\n")

    f.enviarPaquete(paquetePaso1, HOST, PORT, "cf")
    print("Se ha envíado la información 'credential.create'.\n")

    ############# Fase de Registro --- Paso 4: Obtención del attestationObject y del ClientDataJSON ###############

    print("Fase de Registro --- Paso 4: Obtención del attestationObject y del ClientDataJSON\n")

    clientDataJSON = f.recibirPaquete(HOST, PORT+1, "cf")
    attestationObject = f.recibirPaquete(HOST, PORT+2, "cf")

    rpID = asc.ascon_hash(domain.encode(encoding='utf-8')).hex()
    # Versión noLwC: rpID = SHA256.new(domain.encode(encoding='utf-8')).hexdigest() 
    
    attestationObject1 = c.attestationObject(authenticatorData=attestationObject['authenticatorData'], attestationStatement=attestationObject['attestationStatement'])

    collect = c.CredentialStoreData(credentialID= attestationObject1.authenticatorData.attestedCredData.credentialID,rpid=domain, origen=origen1, pubKey= attestationObject1.authenticatorData.attestedCredData.credentialPublicKey, user= usuario1, counter= attestationObject1.authenticatorData.signCount)

    cSDjson = collect.json()
    ruta = '.\CredentialStore\\' + attestationObject1.authenticatorData.attestedCredData.credentialID + '.json'

    # Almacenamos credentialSource para futuras autenticaciones.
    with open(ruta, 'w') as json_file:
        json.dump(cSDjson, json_file)

    print("Se ha almacenado la siguiente información en el servidor:\n ",cSDjson)

    print("\n Se ha finalizado el proceso de registro.")


elif opcion == '2':
    print("**************** Fase de autenticación ****************")

    ############# Fase de autenticación --- Paso 1: Comprobación del nombre de usuario, envío de CollectFromCredentialStore #############

    print("Fase de autenticación --- Paso 1: Comprobación del nombre de usuario y recuperación de los datos de registro, envío de CollectFromCredentialStore \n")

    username = f.recibir_dato(HOST, PORT-1)

    origen1 = c.origin(host="80.26.225.82", domain=str("www." + domain), port=7800)
    usuario1 = c.usuario(userID=randint(1000000,9999999), displayName=username)
    pubkeycp1 = c.pubKeyCredParams()

    challenge = "abcdefg"

    collectFromCredStoreP1 = c.CollectFromCredentialStore(origen=origen1, rpid=domain, user=usuario1, challenge=challenge, timeout=30.0)

    datos = f.buscar_Credenciales(username.decode("utf-8"))

    if datos == 0:
        print("No se ha encontrado el nombre de usuario nombrado, Fin de programa.")
    else:
        print("Datos del usuario:")
        print(datos)
        print("\nSe envían los datos necesarios al Cliente FIDO.")

        f.enviarPaquete(collectFromCredStoreP1,HOST,PORT,"fc")

    
    ############# Fase de autenticación --- Paso 4: Comprobación de los datos enviados por el autenticador #############

    print("Fase de autenticación --- Paso 4: Comprobación de los datos enviados por el autenticador \n")

    assertObj = f.recibirPaquete(HOST,PORT+1,"fc")
    firma = f.recibir_dato(HOST,PORT+2)

    clientData1 = c.clientData(type= assertObj['clientData']['type'], challenge= assertObj['clientData']['challenge'], origin= assertObj['clientData']['origin'], user= assertObj['clientData']['user'])

    h = bytes(asc.ascon_hash(clientData1.json().encode(encoding='utf-8')).hex(), encoding="utf-8")
    
    try:

        if f.verificar_ECDSA(h, firma, VerifyingKey.from_pem(datos['pubKey'])):
            print("Se ha verificado la firma obtenida del autenticador satisfactoriamente.")

            if clientData1.challenge == challenge:
                print("Se ha verificado el challenge.")
                
                if assertObj['authenticatorData']['signCount'] == datos['counter']+1:
                    print("Verificación del counter satisfactoria.")
                    print("Se da permiso al usuario a los recursos del servidor y se actualiza el counter registrado en CredentialStore.")

                    credStoreData = c.CredentialStoreData(credentialID = datos['credentialID'], rpid= datos['rpid'], origen= datos['origen'], pubKey= datos['pubKey'], user= datos['user'], counter= datos['counter']+1)
                    ruta = '.\CredentialStore\\' + datos['credentialID'] + '.json'
                    print("\n")

                    with open(ruta, 'w') as json_file: # Actualizamos credentialSource 
                        json.dump(credStoreData.json(), json_file)

                else:
                    print("Ha fallado la verificación del counter, acceso denegado a los recursos del servidor.")
            else:
                print("Ha fallado la verificación del challenge, acceso denegado a los recursos del servidor.")
        else:
            print("Ha fallado la verificación de la firma, acceso denegado a los recursos del servidor.")
    except:
        print("Ha habido un error o ha fallado alguna verificación del servidor.")

else:
    print("Fin de programa.")

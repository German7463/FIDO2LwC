import uuid
import classes as c
import functions as f
from tinyec import registry
from tinyec.ec import Point
from ecdsa import SigningKey
import json
import ascon as asc
#from Crypto.Hash import SHA256

print("\n")
print("*****************************************************")
print("****************    Authenticator    ****************")
print("*****************************************************")
print("\n")

HOST = "127.0.0.1"
PORT = 8844
credentialID = uuid.uuid1()

opcion = f.recibir_dato(HOST,PORT-1).decode('ascii')

print(opcion)

if opcion == '1':
    
    print("**************** Fase de Registro ****************\n")

    ### ECDH Key Exchange con el Cliente FIDO ###

    #1. Generamos las claves pública y privada.

    authPrivKey = f.generarClavePrivECC()
    authPubKey = f.generarClavePubECC(authPrivKey)

    authPubKeyob = c.publicKeyECDH(x = authPubKey.x,y = authPubKey.y, curve = 'brainpoolP256r1')

    #2. Intercambiamos las claves públicas con el Cliente FIDO

    FIDOClientPublicKeyob = f.recibirPaquete(HOST,8887,'fc') 
    f.enviarPaquete(authPubKeyob,HOST,8888,'fc')

    FIDOClientPublicKey = Point(registry.get_curve(FIDOClientPublicKeyob['curve']), FIDOClientPublicKeyob['x'], FIDOClientPublicKeyob['y'])

    #3. Generamos la clave compartida.

    sharedKey = f.ecc_point_to_256_bit_key(FIDOClientPublicKey * authPrivKey)

    ############# Fase de Registro ---Paso 2: Recibo de información del FC, creación del par de claves pública y privada, junto al UserHandle ###############

    print("Fase de Registro ---Paso 2: Recibo de información del FC, creación del par de claves pública y privada, junto al UserHandle\n")

    paquetePaso2 = f.recibir_datos_dryGascon(HOST,PORT+9,sharedKey)
    # Versión noLwC: paquetePaso2 = f.recibir_datos_AES(HOST,PORT+9,sharedKey) 

    userHandle1 = paquetePaso2['userEntity']

    print("Generando clave pública y privada - Curva elíptica")
    clavePriv = f.generarClavePrivECDSA()
    clavePub = f.generarClavePubECDSA(clavePriv)

    credentialSource1 = c.credentialSource(credentialID = str(credentialID), clavePrivada= clavePriv.to_pem(), rpid= paquetePaso2['rpid'], 
    userHandle= userHandle1, counter = 0)
    cSjson = credentialSource1.json()

    print("tipo del json: " , type(cSjson))
    print("\nSe ha creado el archivo: ")
    ruta = '.\CredentialSources\\' + str(credentialID) + '.json'
    print("\n")

    with open(ruta, 'w') as json_file: # Almacenamos credentialSource para futuras autenticaciones.
        json.dump(cSjson, json_file)

    ############# Fase de Registro --- Paso 3: creación y envío del clientDataHash y del attestationObject al Cliente FIDO ###############

    print("Fase de Registro --- Paso 3: creación y envío del clientDataHash y del attestationObject al Cliente FIDO\n")

    rpIDHash1 = asc.ascon_hash(paquetePaso2['rpid'].encode(encoding='utf-8')).hex()
    # Versión noLwC: rpIDHash1 = hashlib.sha256(paquetePaso2['rpid'].encode('utf-8')).hexdigest()

    attestedCredData1 = c.attestedCredentialData(credentialID = str(credentialID), credentialPublicKey = clavePub.to_pem())
    authData = c.authenticatorData(rpidHash= rpIDHash1, attestedCredData= attestedCredData1, signCount= 0)
            
    ### Firmar clientDataHash ###

    clientDataHashsign = f.firmar_ECDSA(paquetePaso2['clientDataHash'].encode('utf-8'),clavePriv)

    attestationObject1 = c.attestationObject(authenticatorData= authData, attestationStatement= str(clientDataHashsign))

    f.enviar_datos_dryGascon(attestationObject1,sharedKey,HOST,PORT+1)
    # Versión noLwC: f.enviar_datos_AES(attestationObject1,sharedKey,HOST,PORT+1)

    f.enviar_dato(clientDataHashsign,HOST,PORT+2)

elif opcion == '2':
    print("**************** Fase de autenticación ****************")

    ### ECDH Key Exchange con el Cliente FIDO ###

    #1. Generamos las claves pública y privada.

    authPrivKey = f.generarClavePrivECC()
    authPubKey = f.generarClavePubECC(authPrivKey)

    authPubKeyob = c.publicKeyECDH(x = authPubKey.x,y = authPubKey.y, curve = 'brainpoolP256r1')

    #2. Intercambiamos las claves públicas con el Cliente FIDO

    FIDOClientPublicKeyob = f.recibirPaquete(HOST,8887,'fc') 
    f.enviarPaquete(authPubKeyob,HOST,8888,'fc')

    FIDOClientPublicKey = Point(registry.get_curve(FIDOClientPublicKeyob['curve']), 
        FIDOClientPublicKeyob['x'], FIDOClientPublicKeyob['y'])

    #3. Generamos la clave compartida.

    sharedKey = f.ecc_point_to_256_bit_key(FIDOClientPublicKey * authPrivKey)

    ############# Fase de autenticación --- Paso 2: Recibo de información del FC, obtención del CredentialSource, aumento del counter y realizar la firma###############

    print("Fase de autenticación --- Paso 2: Recibo de información del FC, obtención del CredentialSource, aumento del counter y realizar la firma\n")

    getAssertionP2 = f.recibir_datos_dryGascon(HOST,PORT,sharedKey)
    # Versión noLwC: f.enviar_datos_AES(attestationObject1,sharedKey,HOST,PORT+1)

    credentialSource1 = f.buscar_Credenciales_authenticator(getAssertionP2['clientData']['user']['displayName'])

    print("Información encontrada del usuario: ", credentialSource1)

    credSource = c.credentialSource(credentialID = credentialSource1['credentialID'], clavePrivada= credentialSource1['clavePrivada'], 
    rpid= credentialSource1['rpid'], userHandle= credentialSource1['userHandle'], counter= credentialSource1['counter'] + 1)

    ruta = '.\CredentialSources\\' + credentialSource1['credentialID'] + '.json'
    print("\n")

    with open(ruta, 'w') as json_file: # Actualizamos credentialSource 
        json.dump(credSource.json(), json_file)

    clientDataHashsign = f.firmar_ECDSA(getAssertionP2['clientDataHash'].encode('utf-8'),SigningKey.from_pem(credSource.clavePrivada))
    rpIDHash1 = asc.ascon_hash(credSource.rpid.encode(encoding='utf-8')).hex()
    # Versión noLwC: rpIDHash1 = SHA256.new(credSource.rpid.encode('utf-8')).hexdigest()

    ############# Fase de autenticación --- Paso 3: Envío de la respuesta por parte del autenticador al Cliente FIDO###############

    print("Fase de autenticación --- Paso 3: Envío de la respuesta por parte del autenticador al Cliente FIDO\n")

    attestedCredData1 = c.attestedCredentialDataAuthentication(credentialID = credSource.credentialID)

    authData = c.authenticatorDataAuthentication(rpidHash= rpIDHash1, signCount= credSource.counter, attestedCredData= attestedCredData1, userHandle= credSource.userHandle)

    assertionObject1 = c.assertionObject(authenticatorData= authData, clientData= getAssertionP2['clientData'], signature= str(clientDataHashsign))

    f.enviar_datos_dryGascon(assertionObject1,sharedKey,HOST,PORT+1)
    # Versión noLwC: f.enviar_datos_AES(assertionObject1,sharedKey,HOST,PORT+1)

    f.enviar_dato(clientDataHashsign,HOST,PORT+2)

    print("\nDatos enviados, se ha terminado la interacción con el autenticador.")

else:
    print("Fin de programa.")


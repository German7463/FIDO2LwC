from pydoc import cli
import classes as c
import functions as f
from tinyec import registry
from tinyec.ec import Point
from ecdsa import VerifyingKey, NIST256p
from pydantic import *
import ascon as asc

HOST = "127.0.0.1"  # The server's hostname or IP address
PORTRP = 7800  # Puerto de comunicación con la RP
PORTAUTH = 8844  # Puerto de comunicación con el authenticator


print("////////// Simulador FIDO2 - Python. //////////")
print("Introduzca el número de una opción para seleccionarla: ")
print("1. Registro de credenciales.")
print("2. Inicio de sesión.")
print("Cualquier otra opción cerrará el programa.")
print("\n")

opcion = input()

f.enviar_dato(bytes(opcion,encoding="utf-8"), HOST, PORTRP-3)
f.enviar_dato(bytes(opcion,encoding="utf-8"), HOST, PORTAUTH-1)

print("\n")
print("**************************************************")
print("****************    FIDOClient    ****************")
print("**************************************************")
print("\n")

if opcion == '1':

    print("**************** Fase de Registro ****************")

    ############# Fase de Registro --- Parte 0: Solicitud al servidor y establecimiento del nombre de usuario y PIN #############

    print("Fase de Registro --- Parte 0: Solicitud al servidor y establecimiento del nombre de usuario y PIN\n")

    print("Introducza el nombre de usuario que desea utilizar: ")
    username = input()

    f.enviar_dato(username.encode("utf-8"),HOST,PORTRP-1)

    print("\n Se ha envíado el nombre de usuario")

    ############# Fase de Registro --- Parte 1: Creación del ClientDataHash ###############

    print("Fase de Registro --- Parte 1: Creación del ClientDataHash")

    paquetePaso1 = f.recibirPaquete(HOST, PORTRP, "rp")

    clientData1 = c.clientData(type="webauthn.create", challenge=paquetePaso1['challenge'], origin=paquetePaso1['origin'], 
    user= paquetePaso1['user'])
    clientDataJSON1 = clientData1.json()
    clientDataHash1 = asc.ascon_hash(clientDataJSON1.encode(encoding='utf-8')).hex()
    # Versión noLwC: clientDataHash1 = SHA256.new(clientDataJSON1.encode(encoding='utf-8')).hexdigest() 

    ############# Fase de Registro --- Paso 2: creación y envío del authenticatorMakeCredential ###############

    print("Fase de Registro --- Paso 2: creación y envío del authenticatorMakeCredential\n")

    ### ECDH Key Exchange con el Authenticator ###

    #1. Generamos las claves pública y privada.

    fcPrivKey = f.generarClavePrivECC()
    fcPubKey = f.generarClavePubECC(fcPrivKey)

    fcPubKeyob = c.publicKeyECDH(x = fcPubKey.x, y = fcPubKey.y, curve = 'brainpoolP256r1')

    #2. Intercambiamos las claves pública y privada con el Authenticator

    f.enviarPaquete(fcPubKeyob,HOST,8887,"authtor")
    authenticatorPublicKeyob = f.recibirPaquete(HOST,8888,"authtor") 
    
    authenticatorPublicKey = Point(registry.get_curve(authenticatorPublicKeyob['curve']), authenticatorPublicKeyob['x'], authenticatorPublicKeyob['y'])

    #3. Generamos la clave compartida.

    sharedKey = f.ecc_point_to_256_bit_key(authenticatorPublicKey * fcPrivKey)

    #############################

    mkCredential1 = c.makeCredential(clientDataHash=clientDataHash1,
                                    rpid=paquetePaso1['rpid'], userEntity=paquetePaso1['user'], credTypesandPubKeyAlgs=paquetePaso1['pubKeyCredParams'])

    f.enviar_datos_dryGascon(mkCredential1, sharedKey, HOST, PORTAUTH+9)
    # Versión noLwC: f.enviar_datos_AES(mkCredential1, sharedKey, HOST, PORTAUTH+9) 

    ############ Fase de Registro --- Paso 3: recibir y comprobar los datos del autenticador ############

    print("Fase de Registro --- Paso 3: recibir y comprobar los datos del autenticador \n")
    paquetePaso3 = f.recibir_datos_dryGascon(HOST, PORTAUTH+1, sharedKey)
    # Versión noLwC: paquetePaso3 = f.recibir_datos_AES(HOST, PORTAUTH+1, sharedKey)

    Publickey = paquetePaso3['authenticatorData']['attestedCredData']['credentialPublicKey']
    h = bytes(clientDataHash1, encoding="utf-8")

    firma = f.recibir_dato(HOST, PORTAUTH+2)

    attestationObject = c.attestationObject(authenticatorData= paquetePaso3['authenticatorData'], attestationStatement= paquetePaso3['attestationStatement'])

    if f.verificar_ECDSA(h, firma, VerifyingKey.from_pem(Publickey)):
        print("Se verificado la firma obtenida del autenticador satisfactoriamente")
        okFirma = True
    else:
        print("Ha fallado la verificación de la firma, se procede a cerrar la sesión de registro.")
        okFirma = False

    ############ Fase de Registro --- Paso 4: envíar ClientDataJSON y attestationObject a la Relying Party ############

    print("Fase de Registro --- Paso 4: envíar ClientDataJSON y attestationObject a la Relying Party\n")

    if okFirma:
        print("\n Fase de Registro --- Paso 4: envíar ClientDataJSON y attestationObject a la Relying Party \n")

        f.enviarPaquete(clientData1, HOST, PORTRP+1, "rp")
        f.enviarPaquete(attestationObject, HOST, PORTRP+2, "rp")
    
    else:
        print("Fin de programa.")

elif opcion == '2':
    print("**************** Fase de autenticación ****************")

    ############# Fase de autenticación --- Paso 0: Solicitud al servidor, envío del nombre de usuario. #############

    print("Fase de autenticación --- Paso 0: Solicitud al servidor, envío del nombre de usuario. \n")

    print("Introducza el nombre de usuario que desea utilizar: ")
    username = input()

    f.enviar_dato(username.encode("utf-8"),HOST,PORTRP-1)

    print("\n Se ha envíado el nombre de usuario")

    ############# Fase de autenticación --- Parte 1: Recibir Objeto 'CollectFromCredentialStore', crear ClientDataHash y envíar 'GetAssertion'###############

    print("Fase de autenticación --- Parte 1: Recibir Objeto 'CollectFromCredentialStore', crear ClientDataHash y envíar 'GetAssertion'")

    dato = f.recibirPaquete(HOST,PORTRP,"rp")
    print(dato)

    clientData1 = c.clientData(type="webauthn.create", challenge=dato['challenge'], origin=dato['origen'], user= dato['user'])
    clientDataJSON1 = clientData1.json()
    clientDataHash1 = asc.ascon_hash(clientDataJSON1.encode(encoding='utf-8')).hex()
    # Versión noLwC: clientDataHash1 = SHA256.new(clientDataJSON1.encode(encoding='utf-8')).hexdigest()
    
    ############# Fase de autenticación --- Paso 2: Envíar 'GetAssertion'###############

    print("Fase de autenticación --- Paso 2: Envíar 'GetAssertion'")
    getAssertion = c.authenticatorGetAssertion(rpid= dato['rpid'],clientDataHash=clientDataHash1, clientData= clientData1)

    ### ECDH Key Exchange con el Authenticator ###

    #1. Generamos las claves pública y privada.

    fcPrivKey = f.generarClavePrivECC()
    fcPubKey = f.generarClavePubECC(fcPrivKey)

    fcPubKeyob = c.publicKeyECDH(x = fcPubKey.x, y = fcPubKey.y, curve = 'brainpoolP256r1')

    #2. Intercambiamos las claves pública y privada con el Authenticator

    f.enviarPaquete(fcPubKeyob,HOST,8887,"authtor")
    authenticatorPublicKeyob = f.recibirPaquete(HOST,8888,"authtor") 
    
    authenticatorPublicKey = Point(registry.get_curve(authenticatorPublicKeyob['curve']), authenticatorPublicKeyob['x'], authenticatorPublicKeyob['y'])

    #3. Generamos la clave compartida.

    sharedKey = f.ecc_point_to_256_bit_key(authenticatorPublicKey * fcPrivKey)

    #############################

    f.enviar_datos_dryGascon(getAssertion,sharedKey,HOST,PORTAUTH)
    # Versión noLwC:  f.enviar_datos_AES(getAssertion,sharedKey,HOST,PORTAUTH)

    ############# Fase de autenticación --- Paso 3: Recibo de información del autenticador y redirección de esta a la Relying Party###############

    print("Fase de autenticación --- Paso 3: Recibo de información del autenticador y redirección de esta a la Relying Party\n")

    assertionObject1 = f.recibir_datos_dryGascon(HOST,PORTAUTH+1,sharedKey)
    # Versión noLwC:  assertionObject1 = f.recibir_datos_AES(HOST,PORTAUTH+1,sharedKey)

    firma = f.recibir_dato(HOST,PORTAUTH+2)

    assertObj = c.assertionObject(authenticatorData= assertionObject1['authenticatorData'], clientData= assertionObject1['clientData'], signature= assertionObject1['signature'])

    print(assertObj)

    f.enviarPaquete(assertObj,HOST,PORTRP+1,"rp")
    f.enviar_dato(firma,HOST,PORTRP+2)

    print("\nFin interacción con el Cliente FIDO, solo queda la verificación de la Relying Party")


else:
    print("Fin de programa.")

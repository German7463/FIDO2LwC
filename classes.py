from pydantic import *

class usuario(BaseModel):
    userID: int
    displayName: str

class origin(BaseModel): 
    scheme = "HTTPS"
    host: str # dominio o dirección IP
    port: int # puerto
    domain: str # dominio

class pubKeyCredParams(BaseModel):
    type = "PUBLIC_KEY" #Establecido como el tipo de credencial que se va a generar
    alg = "ECDSA" # Elliptic Curve Digital Signature Algorithm

class createRegistration(BaseModel):
    origin: origin
    rpid: str #RPid es el identificador de la Relying Party, suele ser el dominio de la página web.
    user: usuario
    challenge: str
    timeout: float
    pubKeyCredParams: pubKeyCredParams

class makeCredential(BaseModel):
    clientDataHash: bytes
    rpid: str
    userEntity: usuario
    credTypesandPubKeyAlgs: pubKeyCredParams

class clientData(BaseModel):
    type: str
    challenge: str
    origin: origin
    user: usuario

class credentialSource(BaseModel):
    credentialID: str
    type = "public-key"
    clavePrivada: bytes
    rpid: str
    userHandle: usuario
    counter: int

class attestedCredentialData(BaseModel):
    AAGUID= "737935ab-318d-4350-8cf9-3f3110b3b804" ##Identificador único para el autenticador.
    credentialID: str
    credentialPublicKey: bytes

class authenticatorData(BaseModel):
    rpidHash: str
    signCount: int
    attestedCredData: attestedCredentialData

class attestationObject(BaseModel):
    authenticatorData: authenticatorData
    attestationStatement: bytes #Este atributo en FIDO2 real es una firma constrastada del autenticador, en mi caso utilizaré el clientDataHash
                              # firmado con la clave privada como seguro.

class publicKeyECDH(BaseModel):
    x: int
    y: int
    curve: str

class CredentialStoreData(BaseModel):
    credentialID: str
    rpid: str
    origen: origin
    pubKey: bytes
    user: usuario
    counter: int

### Authentication ###

class CollectFromCredentialStore(BaseModel):
    rpid: str
    origen: origin
    challenge: str
    timeout: float
    user: usuario

class authenticatorGetAssertion(BaseModel):
    rpid: str
    clientDataHash: bytes
    clientData: clientData

class attestedCredentialDataAuthentication(BaseModel):
    AAGUID= "737935ab-318d-4350-8cf9-3f3110b3b804" ##Identificador único para el autenticador.
    credentialID: str

class authenticatorDataAuthentication(BaseModel):
    rpidHash: str
    signCount: int
    attestedCredData: attestedCredentialDataAuthentication

class assertionObject(BaseModel):
    authenticatorData: authenticatorDataAuthentication
    clientData: clientData
    signature: bytes 
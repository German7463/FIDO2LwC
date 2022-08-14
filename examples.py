from contextlib import nullcontext
from pickletools import long1
import string
from tokenize import String
from pydantic import *
import hashlib
from Crypto.PublicKey import ECC

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
    alg = "ECC256"

class createRegistration(BaseModel):
    origin: origin
    RPid: str #RPid es el identificador de la Relying Party, suele ser el dominio de la página web.
    user: usuario
    challenge: str
    timeout: float

class clientData(BaseModel):
    type: str
    challenge: str
    origin: origin


usuario1 = usuario(userID = 42462463136, displayName ="nombreusuario1")

# datosFIDOCl1 = createRegistration(RPid= 5256744, user= usuario1)

origen1 = origin(host = "80.26.225.82", domain = "germanesteban.com", port = -1)

clientData1 = clientData(type = "webauthn.create", challenge= "3jckl43j54234r94kc9r2kr932mr", origin = origen1)

u1JSON = usuario1.json()

# dfidocl1 = datosFIDOCl1.json()

clientDataJSON = clientData1.json()

clientDataHash = hashlib.sha256(clientDataJSON.encode('utf-8')).hexdigest()

print("JSON original:")
print(clientDataJSON)
print("SHA256 hash del JSON:")
print(clientDataHash)
import hmac
from basics import point, ser, ser32, ser256, serp, parse256

n=int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',16)


def HMAC_SHA512(k, data):
    #function that does hmac using SHA512
    b = hmac.new(k, msg=data, digestmod='SHA512').digest()
    return format(int.from_bytes(b, byteorder='big'), '0512b')

def split_I(I):
    l = len(I)//2
    return I[:l], I[l:]


def CKDpriv(kp, cp, index): #kp, cp, and index are all integers
    if index > (2**31)-1:
        data = f'0x00{ser(kp, 256)}{ser(index, 32)}'
    else:
        data = f'{serp(point(kp))}{ser(index, 32)}'
    I = HMAC_SHA512(cp, data)
    Il, Ir = split_I(I)
    ki = f'{parse256(Il)}{kp%n}' #n is order of secpk256
    ci = Ir
    if parse256(Il) >= n or ki==0:
        CKDpriv(kp, cp, index+1)
    return Il, Ir

def CKDpub(kp, cp, index): #kp, cp, and index are all integers
    if index > (2**31)-1:
        return 'Error, hardened key not allowed for private key to public key'
    I = HMAC_SHA512(cp, f'{serp(kp)}{ser32(index)}')
    Il, Ir = split_I(I)
    Ki = f'{point(parse256(Il))}{kp}'
    ci = Ir
    if parse256(Il) >= n or ki == infinity:
        CKDpub(kp, cp, index+1)
    return Ki, ci

def N(k, c): #computes extended public key
    #k, and c are all integers
    K = point(k)
    return K, c

def PubChildKey(k, c, i):
    #k, c, and i are all integers
    return N(CKDpriv(k, c, i), 0)

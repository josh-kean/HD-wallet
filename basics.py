import math
from textwrap import wrap
import ecc_operations as ecc
bpoint_c = '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'
bpoint = '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'

def point(i): 
    #multiplies the integer i with the base point of secp256k1 curve
    p = int(bpoint,16)
    return ecc.multiplication(p, i)

def curve_eq(x): #solves for y
    return math.sqrt(x**3 + 7)

def ser(i, n):
    #serializes a uint (32 or 256 bit) into byte representation
    #use of f string so either 32 or 256 bits can be specified
    i = format(i, f'0{n}b')
    #wrap splits binary number in string representation into 8 bit chunks
    binary = wrap(i, 8)
    return bytes([int(x, 2) for x in binary])

def serp(p): #input coords as [x,y]
    y = lambda i: '0x02' if i < 0 else '0x03'
    return f'{y(p[1])}{ser(p[0], 256)}'

def parse256(p): #input as a 32 byte sequence
    return format(int.from_bytes(p, byteorder='big'), '0256b')

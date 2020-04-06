from functions import split_I, CKDpriv, CKDpub, N
from basics import parse256
import hmac as h
import mnemonic_phrase
import hashlib

def mnemonic_gen(phrase=None): #considering returning an iterable object so the binary seed and the word list can be returned from this function
    seed_and_phrase = mnemonic_phrase.new_seed(phrase)
    return seed_and_phrase

def master_key(b_seq):
    b_seq = b_seq.encode('utf-8')
    b = h.new(b'Bitcoin Seed', msg=b_seq, digestmod=hashlib.sha512).digest()
    I = format(int.from_bytes(b, byteorder='big'), '0512b')
    iL, iR = split_I(I)
    m_key = parse256(int(iL,16)) #parse256 needsto be input as byte sequence
    c_code = iR
    return [m_key, c_code]

if __name__ == '__main__':
    bseq = mnemonic_gen()
    res = master_key(bseq)
    m_key = res[0]
    c_code = res[1]
    print(f'm_key {m_key}\n\n\n')
    print(f'c_code {c_code}')


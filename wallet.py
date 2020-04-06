from functions import split_I, CKDpriv, CKDpub, N
from basics import parse256
import hmac as h
import mnemonic_phrase
import hashlib

class Wallet:
    def __init__(self, mnemonic_phrase = None):
        self.mnemonic_phrase = mnemonic_phrase
        self.initial_seed = None
        self.public_keys = {}
        self.private_keys = {} #dictionary key = branch, dictionary value = array [key, chaincode]

    def mnemonic_gen(self): #considering returning an iterable object so the binary seed and the word list can be returned from this function
        seed_and_phrase = mnemonic_phrase.new_seed(self.mnemonic_phrase)
        self.initial_seed = seed_and_phrase[0]
        if not self.mnemonic_phrase: self.mnemonic_phrase = seed_and_phrase[1]

    def master_key(self):
        b_seq = self.initial_seed.encode('utf-8')
        b = h.new(b'Bitcoin Seed', msg=b_seq, digestmod='SHA512').digest()
        I = format(int.from_bytes(b, byteorder='big'), '0512b')
        iL, iR = split_I(I)
        self.private_keys['master']= [parse256(int(iL,16)), iR] 

    def private_child_key(self, branch, parent_index, index, hardened = False):
        if hardened: index+=(2**31)
        key = self.private_keys[branch][parent_index][0]
        chain_code = self.private_keys[branch][parent_index][1]
        return CKDpriv(key, chain_code, index)

    def public_child_key(self, branch, parent_index, index):
        key = self.public_keys[branch][parent_index][0]
        chain_code = self.public_keys[branch][parent_index][1]
        return CKDpub(key, chain_code, index)

    def create_branch(parent_branch, parent_index, new_branch, key_indicies, branch_type):
        if branch_type == 'private':
            self.private_keys[new_branch] = [self.private_child_key(parent_branch, parent_index, i) for i in key_indixies]
        if branch_type == 'public':
            self.public_keys[new_branch] = [self.public_child_key(parent_branch, parent_index, i) for i in key_indixies]



if __name__ == '__main__':
    bseq = mnemonic_gen()
    res = master_key(bseq)
    m_key = res[0]
    c_code = res[1]
    print(f'm_key {m_key}\n\n\n')
    print(f'c_code {c_code}')


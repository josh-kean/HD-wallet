#this is an implementation of BIP 39
#it takes in a set amount of words from the BIP 39 word list to create a 512 bit number
import hashlib as hsh
import tkinter as tk
import random as rand
import sys
import os

#class containing all the hashing functions
class HashingFunctions:
    def __init__(self, result_word_list = None):
        self.word_list = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'words.txt'), 'r').readlines()
        self.word_list = [word[:-1] for word in self.word_list]
        self.word_list_length = len(self.word_list)
        self.entropy = None
        self.entropy_bin = None
        self.result_word_list = result_word_list
        self.binary_seed = None
        self.passphrase = 'TREZOR'
        self.check_sum = None

    def create_entropy(self, length='256'): #user length can be adjusted by input from gui
        self.entropy = format(rand.randrange(2**int(length)), 'x')

    def create_binary_ent(self):
        b = len(self.entropy)*4
        if b <= 128:
            self.entropy_bin = format(int(self.entropy, 16), "0128b")
        elif b <= 160:
            self.entropy_bin = format(int(self.entropy, 16), "0160b")
        elif b <= 192:
            self.entropy_bin = format(int(self.entropy, 16), "0192b")
        elif b <= 224:
            self.entropy_bin = format(int(self.entropy, 16), "0224b")
        elif b <= 256:
            self.entropy_bin = format(int(self.entropy, 16), "0256b")

    def create_check_sum(self):
        entropy_hash = hsh.sha256(bytes.fromhex(self.entropy)).hexdigest()
        entropy_hash = format(int(entropy_hash,16), "0256b")#converts entropy hash to binary
        self.check_sum = entropy_hash[:len(self.entropy_bin)//32]

    def create_word_list(self):
        ent_and_chk = f'{self.entropy_bin}{self.check_sum}'
        self.result_word_list = ' '.join([self.word_list[int(ent_and_chk[11*x:11*(x+1)],2)] for x in range(len(ent_and_chk)//11
)])

    def create_binary_seed(self):
        self.binary_seed = hsh.pbkdf2_hmac('sha512', str.encode(self.result_word_list), str.encode('mnemonic'+self.passphrase), 2048).hex()

    def create_master_key(self):
        self.create_entropy()
        self.create_binary_ent()
        self.create_check_sum()
        self.create_word_list()
        self.create_binary_seed()

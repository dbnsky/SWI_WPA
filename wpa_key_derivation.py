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

# Les trames de la capture se trouvent dans un tableau. Légendes des indices (trames)
# 0. Beacon
# 1. Auth
# 2. Auth
# 3. Assoc
# 4. Assoc
# 5. Handshake 
# 6. Handshake
# 7. Handshake
# 8. Handshake
# 9. Data
# 10. Data 

# Depuis la trame Beacon, recuperer le ssid
ssid        = wpa[0].info
# Depuis la trame Beacon, recuperer l'adresse MAC de l'AP
APmac       = a2b_hex(wpa[0].addr2.replace(":",""))
# Depuis la trame d'auth, recuperer l'adresse MAC du client
Clientmac   = a2b_hex(wpa[1].addr1.replace(":",""))
# Depuis la première trame du handshake, récuperer le nonce de l'AP
ANonce      = (wpa[5].load)[13:45]
# Depuis la deuxième trame du handshake, récuperer le nonce du client
SNonce      = (wpa[6].load)[13:45]
# Depuis la quatrième trame du handshake, récuperer le MIC (à tester)
mic_to_test = b2a_hex((wpa[8].load)[77:93])

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

#String used to replace the mic in the raw data
replaceStr  = "0" * len(mic_to_test)

data        = b2a_hex(str((wpa[8])[EAPOL]))
data        = data.replace(mic_to_test,replaceStr)

print "\n\nValues used to derivate keys"
print "============================"
print "Passphrase: ",passPhrase,"\n"
print "SSID: ",ssid,"\n"
print "AP Mac: ",b2a_hex(APmac),"\n"
print "CLient Mac: ",b2a_hex(Clientmac),"\n"
print "AP Nonce: ",b2a_hex(ANonce),"\n"
print "Client Nonce: ",b2a_hex(SNonce),"\n"


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

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(a2b_hex(pmk),A,B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print "\nResults of the key expansion"
print "============================="
print "PMK:\t\t",pmk,"\n"
print "PTK:\t\t",b2a_hex(ptk),"\n"
print "KCK:\t\t",b2a_hex(ptk[0:16]),"\n"
print "KEK:\t\t",b2a_hex(ptk[16:32]),"\n"
print "TK:\t\t",b2a_hex(ptk[32:48]),"\n"
print "MICK:\t\t",b2a_hex(ptk[48:64]),"\n"
print "MIC:\t\t",mic.hexdigest(),"\n"

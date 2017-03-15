# -*- coding: utf-8 -*- 
import socket
import argparse
import random

modelCable = []

from pktSnmp import * 
#from models.DPC3928SL import * 



#              SNMP
testMethod 	= ['snmp','http','all']
check 		= ['credentials','system','config','all']

banner = '''

#  ====================================================== # 
#  ------------------------------------------------------
#   tool for audit your cablemodem 
# 
#  ------------------------------------------------------
# [Created by]
#  	+Bertin Bervis Bonilla 
#  	+Ezequiel Fernandez
#  ====================================================== # 

'''

parser = argparse.ArgumentParser(
	description='Test your Cablemodem -  DPC3928SL DOCSIS 3.0 - ',
	epilog="auditCableModem.py --host <host> --method <method> --check < option-check >",
	version="0.1"
)

parser.add_argument('--host'            ,	dest="aHOST", 			help='Host', 		required=True)
#																									  |'snmp'|
parser.add_argument('--method' ,'-m'    , 	dest="aMETHOD", 		help='Method', 		choices=['http', 'snmp','all'], required=True)
# EN PROCESO...                                                                                       # fix, harcoded
parser.add_argument('--model' , '-md'   ,	dest="MODEL", 			help='select you cablemodem ',choices=['DPC3928SL','DPC2100'] , required=True)

parser.add_argument('--community' ,'-cm', 	dest="COMMUNITY", 		help='Community string')

# READ \ WRITE

parser.add_argument('--show-model', '-sm',	dest="showMODELS", 	help='show cablemodems ' 	)

parser.add_argument('--check', 	dest="aCHECK", 	help='view ', 		choices=['sysinfo','credentials', 'all'])
parser.add_argument('--set', 	dest="aSET", 	help='Set config', 	choices=['credentials', 'system','all'], default='credentials')

args		=  parser.parse_args()

HOST		=  args.aHOST
METHOD		=  (args.aMETHOD).lower()
CHECK		=  str(args.aCHECK).lower()

COMMstr 	= ''

#try:
COMMstr =  args.COMMUNITY
#except:
#	pass

cableMODEL 	= args.MODEL

# ----------------------------------------------------------------------------------
# BUSCAR ALTERNATIVA A ESTA 'CHANCHADA'
getModel ='from models.'+cableMODEL+' import *'
try:
	exec(getModel )
except:
	print 'model selected no found'

# ---------------------------------------------------------------------------------- #

snmpPORT 	= 	['161','162']
httpPORT 	= 	['80','8080']
frmSnmp 	= 	'' 
 
# 

# Function: asctohex(string_in):
# ascii string to hex string 
def asctohex(string_in):
	a=""
	for x in string_in:
		a = a + ("0"+((hex(ord(x)))[2:]))[-2:]
	return a

def snmpMethod(addrOID,nmComm,oidName):

	frameSNMP = getFUllPkt(addrOID,nmComm)
	#print 'enviando '+frameSNMP

	client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	try:
		client.sendto(frameSNMP.decode('hex'),(HOST,int(snmpPORT[0])))
		response1  = client.recv(1024).encode('hex')

	except (KeyboardInterrupt, SystemExit, Exception), d:
		print 'host not found'
		#print e


	# ------------------------------------------------------------------ #
	lengthOID 	= int(len(addrOID))
	initOID 	= int(response1.find(addrOID))
	finOID  	= initOID + lengthOID

	initResp  	=  finOID + 4
	# ------------------------------------------------------------------ #

	viewResponse = str(response1[initResp:]).decode('hex')

	#print 'DBG -- full response :'+response1
	print oidName+' '+viewResponse
	
	'''
	if transaction == 1:
		print 'pass length: \t'+ str(len(viewResponse)) + '\n'
	'''

	client.close()

# ------------------------------------------------------------------ #
def httpMethod():
	print 'plin plan plum'
	print 'Aki Bertin'
	print 'wait...'
# ------------------------------------------------------------------ #


def initApp():

	try: 
		if len(COMMstr) > 2:
			communityString = asctohex(COMMstr)
		else:
			pass
	except:
		communityString = '696e7365637572697479'

	transID = 0
	if METHOD == testMethod[0]:
		for oids in disclosureOIDs:

			#              -- transID --     
			#					 | 
			#   				 +       / ---- 0 ---> OID address
			#                    V      /
			#    disclosureOIDs[ N ][ 0 ]  ---- 1 ---> OID name

			OIDaddr = disclosureOIDs[oids][0] #  OID addres
			OIDname = disclosureOIDs[oids][1] #  OID name

			snmpMethod(OIDaddr,communityString,OIDname)
			
			transID +=1


	elif METHOD == testMethod[1]:
			httpMethod()
	else:
		print 'bad method'



initApp()
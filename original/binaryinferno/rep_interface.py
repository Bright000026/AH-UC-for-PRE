

# This file performs a parallel serialization pattern search via the gnu-parallel command in
# rep_parallel.sh

from Sigma import ascii2sigma,bytes2ascii,intmsgs,hexmsgs
from Sigma import msgs as msgsf
from kill import kill_parallel
from time import sleep

def rep_par_BE(msgs,mml=1000):
	return rep_par(msgs,mml=mml,endianess="BE")

def rep_par_LE(msgs,mml=1000):
	return rep_par(msgs,mml=mml,endianess="LE")


def rep_par(msgs,mml=1000,endianess="XE"):
    
	# mml = min([len(m) for m in msgs])

	# # if type(msgs)==type(bytes()):
	# print(type(msgs),len(msgs))
	# for m in msgs.split("\n"):
	# 	print("\t",m)
	msgs = msgs.replace("\t","")
	msgs = msgs.replace(" ","")
	if "--" in msgs:
		msgs = msgs.split("--")[1]

	import sys
	import re
	import pickle
	#data = sys.stdin.read()
	# print("Data is len",len(data))

	import subprocess
	# Where 1000 is min message length
	cmd = ['./rep_parallel.sh '+ str(mml) + " " + endianess] #['awk', 'length($0) > 5']
	in_data = msgs.encode('utf-8')
	try:  
		#result = subprocess.run(cmd, stdout=subprocess.PIPE, input=in_data,shell=True,stderr=subprocess.PIPE, timeout = 60 )
		result = subprocess.run(cmd, stdout=subprocess.PIPE, input=in_data, shell=True,stderr=subprocess.PIPE, timeout = 20 )
	except subprocess.TimeoutExpired:
		kill_parallel()
		#print("Command timed out after 1 minutes.")
		sleep(5)
		#stdout = result.stdout
	#	return None
	with open("log.txt", "r",encoding = 'utf-8') as f:
		data = f.read().strip()
	#data = result.stdout.decode('utf-8').strip()
	#print("data",len(data))
	sigmas = []
	for m in re.findall("<<<([a-z0-9]*?)>>>",data,flags=re.MULTILINE):
		#print("m")
		sigmas+= pickle.loads(bytes.fromhex(m))
		#print("m",sigmas)
	sigmas = sorted(sigmas,key=lambda s:(len(s.fields),-sum([f.value for f in s.fields]) ))[:100]
	#sigmas = sigmas[:1]
	return sigmas

def main():

	import sys

	if len(sys.argv) == 2:
		endianess = sys.argv[1]


	else:
		endianess = "XE"
	#data = sys.stdin.read()
	#fname="dataset/top-level/100/"+input()+".txt.input"
	#data = sys.stdin.read()
	fname=input()
	with open(fname,"r") as f:
		data=f.read()
	print("start")
	sigmas = rep_par(data,endianess=endianess)
	print("Got ",len(sigmas),"sigmas")
	#sigmas = sorted(sigmas,key=lambda s:len(s.fields))
	for s in sigmas: #sorted(sigmas,key=lambda s:-sum([f.value for f in s.fields])): # s:len(s.fields)):
		print(len(s.fields),sum([f.value for f in s.fields]),[f.annotation for f in s.fields],[f.value for f in s.fields],s)

	# sub = defaultdict(lambda:[])
	# for i in range(len(sigmas)):
	# 	for j in range(i,len(sigmas)):
	# 		if i != j:
	# 			print(i,j,sigmas[i]==sigmas[j])


if __name__ == '__main__':
	main()

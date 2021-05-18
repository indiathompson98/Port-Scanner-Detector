#!/usr/bin/env python
# coding: utf-8

# # TCP scan detector 
# 
# ## suleiman hijazeen , Thalia Vazquez , India thompson 

# ### TCP scan Overview
# Tcp scan will scan for TCP port like port 22, 21, 23, 445 etc and ensure for listening port (open) through 3-way handshake connection between the source and destination port. If the port is open then source made request with SYN packet, a response destination sent SYN, ACK packet and then source sent ACK packets, at last source again sent RST, ACK packets.
# 
# ![image.png](attachment:image.png)
# 
# >Source sent SYN packet to the destination
# 
# >Destination sent SYN, ACK to source
# 
# >Source sent ACK packet to the destination
# 
# >Source again sent RST, ACK to destination
# 
# 

# Source sent SYN pack and if the port is close the receiver will be sent a response through RST, ACK.
# 
# ![image.png](attachment:image.png)
# 
# 
# >Source sent SYN packet to the destination
# 
# >Destination sent RST, ACK packet to the source
# 

# ### ICMP Attack 
# 
# The ICMP protocol is designed to provide error information and perform simple diagnostic actions (like ping). As such, even passive monitoring of ICMP traffic on a network can provide a wealth of data to an adversary. Eavesdropping on ICMP packet can help to identify the hosts on a network and if certain systems are up, down or malfunctioning.
# 
# However, an attacker can also actively use ICMP in a number of different ways. Two of the most common are using the protocol for network scanning/mapping and for data exfiltration and command-and-control.
# 
# #### Scanning
# 
# The ICMP protocol is crucial to the operation of the ping and traceroute protocols. Ping involves sending an ICMP ping request and looking for an ICMP ping response. Traceroute, on the other hand, uses UDP packets for requests and ICMP for responses.
# 
# The primary purpose of these protocols is to determine if a system at a particular IP address exists and is operational. As a result, they can be used for mapping a network during the reconnaissance phase of an attack. ICMP packets should be blocked at the network boundary, and unusual ICMP traffic from a host may indicate scanning by an attacker in preparation for lateral movement through the network.
# 
# ![image.png](attachment:image.png)

# 
# ### Code Overview
# 
# the code will loop ach packet in the file and will do the fellowing:
# 
# >1- will discard any packets that is not ip or TCP or ICMP
# 
# >2- it will keep acount of the number of syn and ICMP each host send and the number of acq-sync 
# 
# >3- will store each port ahost scaned and each the time stampe 
# 
# >4- will store each IP send a ping and stor the Time stampe
# 
# >4- will consider a host as an attacker if:
# 
# >>i-the num of syn is more than "SYN_SYNACK_RATIO" times of the number of acq-syn 
# 
# >>ii-if the number of syn is higher than SYN_MIN_THR
# 
# >>iii- if the number of pings is higher than PING_NUM_THR 

# In[1]:


import dpkt, socket, sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pandas import DataFrame
import seaborn as sns


# In[128]:



#=CONSTANTS===================================================================#

SYN_SYNACK_RATIO = 3 # ratio of the SYN to SYN_ACQ
PING_NUM_THR= 50 # num of ping attemps to be an attacker
SYN_MIN_THR=30 # min number of syN attept to be an attacker
SYN_MIN_THR_ACK=60 # min number of ACQ attept to be an attacker
prd=50 #the min number of periodicity consider the attack as regular
#=FUNCTIONS===================================================================#

#f = open(pcap)
def tcpFlags(tcp):
    """Returns a list of the set flags in this TCP packet."""
    ret = list()

    if tcp.flags & dpkt.tcp.TH_FIN != 0:
        ret.append('FIN')
    if tcp.flags & dpkt.tcp.TH_SYN  != 0:
        ret.append('SYN')
    if tcp.flags & dpkt.tcp.TH_RST  != 0:
        ret.append('RST')
    if tcp.flags & dpkt.tcp.TH_PUSH != 0:
        ret.append('PSH')
    if tcp.flags & dpkt.tcp.TH_ACK  != 0:
        ret.append('ACK')
    if tcp.flags & dpkt.tcp.TH_URG  != 0:
        ret.append('URG')
    if tcp.flags & dpkt.tcp.TH_ECE  != 0:
        ret.append('ECE')
    if tcp.flags & dpkt.tcp.TH_CWR  != 0:
        ret.append('CWR')
    
    return ret


def compare_IPs(ip1, ip2):
    """
    Return negative if ip1 < ip2, 0 if they are equal, positive if ip1 > ip2.
    """
    return sum(map(int, ip1.split('.'))) - sum(map(int, ip2.split('.')))

#=ARG PARSING=================================================================#

# Must include a pcap to read from.
if len(sys.argv) <= 1:
    print ("{0}: needs a filepath to a PCAP file".format(sys.argv[0]))
    sys.exit(-1)

# Try to open the pcap file and create a pcap.Reader object.


outliers=[]
def detect_outlier(data_1):
    
    threshold=3
    mean_1 = np.mean(data_1)
    std_1 =np.std(data_1)
    
    
    for y in data_1:
        z_score= (y - mean_1)/std_1 
        if np.abs(z_score) > threshold:
            outliers.append(y)
    return outliers

def outlier_treatment(datacolumn):
 sorted(datacolumn)
 Q1,Q3 = np.percentile(datacolumn , [25,75])
 IQR = Q3 - Q1
 lower_range = Q1 - (1.5 * IQR)
 upper_range = Q3 + (1.5 * IQR)
 return lower_range,upper_range
curPacket1 = 0 
#for ts, buf in pcap:
#    curPacket1 += 1
def is_periodic(samples,perdcity,p):
    
 diffs = [a-b for a, b in zip(samples, samples[1:])]
 l=0
 i=0
 f=0
 while i < len(diffs)-1 :
  if  (diffs[i] == diffs[i+1]):
    l=l+1 
    while (l+i)<len(diffs):
      if  (diffs[i] == diffs[i+l]) and  (l<len(diffs)):   
       l=l+1
       if l>=len(diffs):
            print(' The attack was periodic between packet number',suspects[p]['duration'][i],"and",suspects[p]['duration'][i+l],"with a periodicty of",abs(diffs[i]),"\n") 
            l=0
            f=1
            break
      else:
             
             if l>=perdcity:
              print(' The attack was periodic between packet number',suspects[p]['duration'][i],"and",suspects[p]['duration'][i+l],"with a periodicty of",abs(diffs[i]),"\n") 
              f=1
             i=i+l
             if i> len(diffs) :
              break 
             l=0
             
  if i> len(diffs) :
     break    
  else:
   i=i+1

  i=i+1
 if f==0:
  print(' The attack was not periodic on the whole period of the scan',"\n")
 return 0


# In[129]:


pcap1 ='C:/Users/sulem/OneDrive/Documents/GitHub/Port-Scan-Detector-master/Port-Scan-Detector-master/test.pcap'
print("please input PCAP file location with '/' instead of '\'")
pcap1 = input()
#pcap1 ='C:/Users/sulem/OneDrive/Documents/ping_tcp.pcap'
try:
    f = open(pcap1, 'rb')
    pcap = dpkt.pcap.Reader(f)
except (IOError, KeyError):
    print ("Cannot open file:", sys.argv[1])
    sys.exit(-1)
#=MAIN========================================================================#

suspects = dict() # Dictionary of suspects. suspect's IP: {# SYNs, # SYN-ACKs}
dur_type=dict()
curPacket = 0     # Current packet number.
ports=[]
dur=[]
time=[]
# Analyze captured packets.
for ts, buf in pcap:
    curPacket += 1
    time.append(ts)
    # Ignore malformed packets
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.UnpackError, IndexError):
        continue

    # Packet must include IP protocol to get TCP,ICMP
    ip = eth.data
    if not ip:
        continue
    
    # Skip packets that are not TCP or ICMP
    tcp = ip.data
    
    dur.append(0)
    if (type(tcp) != dpkt.tcp.TCP) and (type(tcp) != dpkt.icmp.ICMP):
        continue

    # Get all of the set flags in this TCP packet andallICMP 
    

    srcIP = socket.inet_ntoa(ip.src)
    dstIP = socket.inet_ntoa(ip.dst)
    #print(type(tcp.data))
    if type(tcp) != dpkt.icmp.ICMP:
     tcpFlag = tcpFlags(tcp)
     scrprt = ip.data.sport
     desprt = ip.data.dport
     ports.append(scrprt)
     ports.append(desprt)
    # Fingerprint possible suspects.
    if ({'SYN'} == set(tcpFlag)) or (type(tcp.data)==dpkt.icmp.ICMP.Echo):          # A 'SYN' request.
        if srcIP not in suspects: suspects[srcIP] = {'PING': 0,'SYN': 0, 'SYN-ACK': 0, 'ACK': 0, 'ports':[], 'ports_rang':[], 'duration':[],'dur_plot':[]}
        if srcIP not in dur_type: dur_type[srcIP] = {curPacket:[]}
        if ({'SYN'} == set(tcpFlag)) :
         suspects[srcIP]['SYN'] += 1
         dur_type[srcIP][curPacket]=[1]
         suspects[srcIP]['duration'].append(curPacket)
        if (type(tcp.data)==dpkt.icmp.ICMP.Echo):
         suspects[srcIP]['PING'] += 1
         dur_type[srcIP][curPacket]=[2]
         suspects[srcIP]['duration'].append(curPacket)
        if ({'ACK'} == set(tcpFlag)) :    
         suspects[srcIP]['ACK'] += 1
         suspects[srcIP]['duration'].append(curPacket)
        suspects[srcIP]['ports'].append(desprt)
        suspects[srcIP]['ports_rang']=list(set(suspects[srcIP]['ports']))
        
    elif {'SYN', 'ACK'} == set(tcpFlag): # A 'SYN-ACK' reply.
        if dstIP not in suspects: suspects[dstIP] = {'SYN': 0, 'SYN-ACK': 0}
        if srcIP not in suspects: suspects[srcIP] = {'SYN': 0, 'SYN-ACK': 0, 'ports':[], 'ports_rang':[], 'duration':[],'dur_plot':[],'PING': 0}
        if srcIP not in dur_type: dur_type[srcIP] = {curPacket:[]}    
        suspects[dstIP]['SYN-ACK'] += 1
        dur_type[srcIP][curPacket]=[3]
        suspects[srcIP]['SYN-ACK'] += 1
        suspects[srcIP]['ports'].append(desprt)
        suspects[srcIP]['ports_rang']=list(set(suspects[dstIP]['ports']))
        suspects[srcIP]['duration'].append(curPacket)

prt_count=[]
prt_count_aft=[]
sus_bf=list(suspects.keys())
for s in list(suspects.keys()):
    prt_count.append(len(suspects[s]['ports']))
    
    if ((suspects[s]['SYN'] < (suspects[s]['SYN-ACK'] * SYN_SYNACK_RATIO)) or ((suspects[s]['SYN'] < SYN_MIN_THR) and (suspects[s]['ACK'] < SYN_MIN_THR_ACK))) and suspects[s]['PING'] < PING_NUM_THR:
        del suspects[s]
    else:
        prt_count_aft.append(len(suspects[s]['ports']))
df_bf_del =  pd.DataFrame({'prt_count':prt_count, 'ip':sus_bf}) 
df_aft_del =  pd.DataFrame({'prt_count':prt_count_aft, 'ip':list(suspects.keys())}) 

ax = df_bf_del.plot.bar(rot=0,figsize=(9,7))

ax.set_title('All ip detected')
ax.set_xlabel('IPs')
ax.set_ylabel('Port counts]', labelpad=18)

ax = df_aft_del.plot.bar(rot=0,figsize=(9,7))

ax.set_title('Real ip suspects')
ax.set_xlabel('IPs')
ax.set_ylabel('Port counts]', labelpad=18)
# Output results.
print ("Analyzed", curPacket, "packets:")

if not suspects:
    print ('no suspicious packets detected...')


f.close()
fig, axes = plt.subplots(len(suspects.keys())*2, 1, figsize=(20, 17))

p=1
type_str=['PING','SYN','SYN-ACK']
type_count=[0,0,0]
for s in list(suspects.keys()):
 suspects[s]['dur_plot']=np.zeros(curPacket)
 i=0
 print('Potential attack coming from IP: ',s)  
 if suspects[s]['PING']>suspects[s]['SYN']:
  print(' The type of the attack is ping and this many times',suspects[s]['PING'],"\n") 
  type_count[0]=type_count[0]+suspects[s]['PING']
  is_periodic(suspects[s]['duration'],prd,s)
 if suspects[s]['SYN']>suspects[s]['PING']:
  print(' The type of the attack is TCP SYN and duration of the port scan is ',-time[suspects[s]['duration'][0]]+time[suspects[s]['duration'][len(suspects[s]['duration'])-1]],"s\n")
  is_periodic(suspects[s]['duration'],prd,s)
  type_count[1]=type_count[1]+suspects[s]['SYN']
 if (suspects[s]['SYN-ACK']>suspects[s]['SYN']) and (suspects[s]['ACK']>suspects[s]['PING']) :
  print(' The type of the attack is TCP SYN-ACK and duration of the port scan is ',-time[suspects[s]['duration'][0]]+time[suspects[s]['duration'][len(suspects[s]['duration'])-1]],"s\n")
  is_periodic(suspects[s]['duration'],prd,s)
  type_count[2]=type_count[2]+suspects[s]['SYN-ACK']

 for t in dur: 
    if i in suspects[s]['duration']:
     suspects[s]['dur_plot'][i]=dur_type[s][i][0]
    i=i+1
 
 df = DataFrame (suspects[s]['ports'],columns=[s])
 axes[p-1].set_title('Attack from '+s)
 axes[p-1].set_xlabel('packets [p]')
 axes[p-1].set_ylabel('Attack]', labelpad=18)   
 axes[p-1].plot(suspects[s]['dur_plot'])
 plt.subplots_adjust(wspace=.7, hspace=.7) 
 axes[(p-1)+((len(suspects.keys())))].set_title('range of port search by '+s)
 axes[(p-1)+((len(suspects.keys())))].set_xlabel('ports [prt]')
 axes[(p-1)+((len(suspects.keys())))].set_ylabel('Range', labelpad=18)   
 sns.violinplot(x =s, data = df,ax=axes[(p-1)+((len(suspects.keys())))]) 
 p=p+1
print("in the Duration plot 1 is a TCP SYN scan attack , 2 is a ping attack and 3 is TCP SCN-ACk")    
df_typ_ount =  pd.DataFrame({'count':type_count},index=type_str) 
plot = df_typ_ount.plot.pie(y='count', figsize=(10, 10))


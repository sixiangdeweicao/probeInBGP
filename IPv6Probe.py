#coding:utf-8
import os
import random
import zmapscan
import os
from tqdm import tqdm
import pyasn
import ipaddress
from copy import deepcopy
from statistic import statistic
import argparse
athers=[]
ipv6countALL=0

def checkbgpState(filename,bgprespo):
    '''
    function:
        Query the number of bgp prefixes covered by the seed address file and the number of prefixes not covered. Return the prefix set without coverage
    Args:
        filename :the file of seed addresses
        bgprespo：bgp prefix library
    return:bgplistNoIPs
        bgplistNoIPs:Set of prefixes not covered

    '''
    bgplist = set()
    # filename = "/home/liguo/source1.txt"
    bgpdb = pyasn.pyasn(bgprespo)
    # read the active file ipv6
    for line in open(filename):
        if line == "\n":
            continue
        line = line.replace("\n", "")
        bgp_prefix = bgpdb.lookup(line)[1]
        if bgp_prefix != None:
            bgplist.add(bgp_prefix)
    # load all bgp_prefix
    bgplistALL = set()
    for line in open(bgprespo):
        if line == "\n":
            continue
        bgp_pre= line.split()[0]
        if bgp_pre == ";":
            continue
        bgplistALL.add(bgp_pre)

    allcount = len(bgplistALL)
    bgplistNoIPs = bgplistALL - bgplist
    noexitcount = len(bgplistNoIPs)
    print("the active include bgp prefix counts is {}".format(allcount - noexitcount))
    print("the no active address of bgp prefix count is {}".format(noexitcount))

    # write the result in file
    return bgplistNoIPs


def probe(bgp_prefix):
    '''
    Function:
        probe the space of bgpPrefix 
    Args:
        bgp_prefix : the bgp prefix 
    Return:
        the result store the file that named by bgp prefix

    '''
    print("begin to probe in {} bgp prefix".format(bgp_prefix))
    global athers
    global ipv6countALL
    ipv6pre=[]
    prefix=bgp_prefix.split("/")
    bgp=prefix[0]
    prefix_space=int(prefix[1])
    # print(prefix_space)
    if prefix_space <=112:
        for i in range(2**16):
            if prefix_space<=96:
                ipv6=bgp+str(hex(i))[2:]
                ipv6pre.append(ipv6)
        prefile="BGP/"+bgp+"_"+str(prefix_space)+".csv"
        with open(prefile,'w') as f:
            for line in ipv6pre:
                f.write(line+"\n")
        activefile=prefile+"active.csv"
        zmapscan.IPv6activeScan("2001:da8:ff:212::20:5", prefile, activefile)
        command='wc -l '+activefile
        v6_result=os.popen(command)
        hited_number=float(v6_result.read().split()[0])
        v6_result.close()
        command="rm -rf "+prefile
        os.system(command)
        if hited_number==0:
            command="rm -rf "+activefile
            os.system(command)
        else:
            ipv6list=[]
            for line in open(activefile):
                line=line.replace("{","")
                line=line.replace("}","").strip().split(": ")[1].replace("\"","").replace("\"","")
                #print(line)
                ipv6list.append(line)
            y=len(ipv6list)
            ipv6countALL=ipv6countALL+y
            print("probe the prefix {},found {} ipv6 active address".format(bgp_prefix,y))
            print("now we total fonud ipv6 address is :{}".format(ipv6countALL))
            with open(activefile,'w') as f:
                for ipv6 in ipv6list:
                    f.write(ipv6+"\n")
    else:
        print("bgp warnning{}".format(bgp_prefix))
        athers.append(bgp_prefix)
            

def Random_LowBytes_Extend(bgp_prefix):
    '''
    Function:
        probe the space of bgpPrefix used random lowbytes
    Args:
        bgp_prefix : the bgp prefix 
    Return:
        the result store the file that named by bgp prefix

    '''
    print("begin to probe in {} bgp prefix".format(bgp_prefix))
    global ipv6countALL
    ipv6pre=[]
    prefix=bgp_prefix.split("/")
    bgp=prefix[0]
    bgpcopy=deepcopy(bgp)
    prefix_space=int(prefix[1])
    #bgp prefix used 0 filled eg:2001:da8::/32 =>2001:0da8:0000:0000:0000:0000:0000:0000
    bgp=ipaddress.IPv6Address(bgp)
    bgp=bgp.exploded
    # eg:2001:da8::/32
    # extend in 5 cases:
    # case1:112-128 low bytes  =>2001:0da8:0000:0000:0000:0000:0000:0000-2001:0da8:0000:0000:0000:0000:0000:ffff
    # case3:96-112  low bytes  =>2001:0da8:0000:0000:0000:0000:0000:0000-2001:0da8:0000:0000:0000:0000:ffff:0000 or 2001:0da8:0000:0000:0000:0000:0000:0000-2001:0da8:0000:0000:0000:0000:ffff:0001
    # case3:90-96   low bytes  =>2001:0da8:0000:0000:0000:0000:0000:0000-2001:0da8:0000:0000:0000:ffff:0000:0000 or 2001:0da8:0000:0000:0000:0000:0000:0000-2001:0da8:0000:0000:0000:ffff:0000:0001
    # case4:64-90   low bytes  =>2001:0da8:0000:0000:0000:0000:0000:0000-2001:0da8:0000:ffff:0000:0000:0000:0000 or 2001:0da8:0000:0000:0000:0000:0000:0000-2001:0da8:0000:ffff:0000:0000:0000:0001
    # case5:32-48   low bytes  =>2001:0da8:0000:0000:0000:0000:0000:0000-2001:0da8:ffff:0000:0000:0000:0000:0000 or 2001:0da8:0000:0000:0000:0000:0000:0000-2001:0da8:ffff:0000:0000:0000:0000:0001
    
    # store the bgp by list which can changed by later
    bgp=bgp.split(":")
    if prefix_space%4!=0:
        prefix_space=(int(prefix_space/16)+1)*16   
    while prefix_space<112:
        position=prefix_space/16
        for i in range(2**16):
            nybble_4=str(hex(i))[2:]
            ip=""
            for j in range(8):
                if j!=position and j<7:
                    ip=ip+bgp[j]+":"
                elif j!=7:
                    ip=ip+nybble_4+":"
                else:
                    iptemp=deepcopy(ip)
                    ip=ip+"0000"
                    ip=ipaddress.IPv6Address(ip)
                    ipv6pre.append(ip)
                    iptemp=iptemp+"0001"
                    iptemp=ipaddress.IPv6Address(iptemp)
                    ipv6pre.append(iptemp)

        prefix_space+=16
    for i in range(2**16):
        nybble_4=str(hex(i))[2:]
        ip=""
        for j in range(7):
            ip=ip+bgp[j]+":"
        ip=ip+nybble_4
        ip=ipaddress.IPv6Address(ip)
        ipv6pre.append(ip)

    # store the result
    prefile="extendLowBytes/"+bgpcopy+"_"+prefix[1]+".csv"
    with open(prefile,'w') as f:
        for line in ipv6pre:
            f.write(str(line)+"\n")
    activefile="extendLowBytes/"+bgpcopy+"_"+prefix[1]+"_"+"active.csv"
    ipv6local=args.ipv6
    zmapscan.IPv6activeScan(ipv6local, prefile, activefile)
    command='wc -l '+activefile
    v6_result=os.popen(command)
    hited_number=float(v6_result.read().split()[0])
    v6_result.close()
    command="rm -rf "+prefile
    os.system(command)
    if hited_number==0:
        command="rm -rf "+activefile
        os.system(command)
    else:
        ipv6list=set()
        for line in open(activefile):
            line=line.replace("{","")
            line=line.replace("}","").strip().split(": ")[1].replace("\"","").replace("\"","")
            #print(line)
            ipv6list.add(line)
        y=len(ipv6list)
        ipv6countALL=ipv6countALL+y
        print("probe the prefix {},found {} ipv6 active address".format(bgp_prefix,y))
        print("now we total fonud ipv6 address is :{}".format(ipv6countALL))
        with open(activefile,'w') as f:
            for ipv6 in ipv6list:
                f.write(ipv6+"\n")
       
            

def load_bgp(bgprespo):
    '''
    Function:
        load the bgp prefix
    Args:
        bgpreo:the bgp prefix reo file
    Return:bgplistALL
        the list of bgp prefix
    '''
    bgplistALL = []
    for line in open(bgprespo):
        if line == "\n":
            continue
        bgp_pre= line.split()[0]
        if bgp_pre == ";":
            continue
        bgplistALL.append(bgp_pre)
    allcount = len(bgplistALL)
    print("the bgp prefix count is :{}".format(allcount))
    return bgplistALL


def running(bgplist,hostcount):
    '''
    Function:
        runing the program that probe ipv6 in bgp prefix
    Args:
        bgplist:the list of bgp prefix
    Return:null
        the result store in the file that named by bgp prefix
        
    '''
    count=len(bgplist)
    if (hostcount-1)*5000 >count:
        print("the hostcount is error")
        exit()
    x=(hostcount-1)*5000
    y=hostcount*5000
    if x<count and y>count:
       for i in tqdm(range(x,count)):
           Random_LowBytes_Extend(bgplist[i])
            
    else:
       for i in tqdm(range(x,y)):
           Random_LowBytes_Extend(bgplist[i])
           
        # probe(bgplist[i])
    

    if len(athers)>0:
        print("store the bgp prefix without probeing in withoutProbe.scv")
        with open("withoutProbe.csv", 'w') as f:
            for bgp in athers:
                f.write(bgp+"\n")

    
if __name__ == "__main__":
    parse=argparse.ArgumentParser()
    parse.add_argument('--count', type=int, help='the host of running pro counts')
    parse.add_argument('--ipv6', type=str, help='the host of running pro counts')
    args=parse.parse_args()
    bgprespo="ipasn.csv"
    bgplist=load_bgp(bgprespo)
    hostcount=args.count
    running(bgplist,hostcount)
    statistic()

    

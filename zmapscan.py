#coding:utf-8
import argparse,os
import time
from prettytable import PrettyTable
'''
Parameters
--filename: ipv6 address  which may be not active
--output: the active addree result are stored in this file
--IPv6: local IPv6 address
'''
def IPv6activeScan(IPv6,filename,output):
    '''
    ipv6 scan
    '''
    start = time.time()
    command ="zmap -q -i ens3 --ipv6-source-ip="+IPv6 +" --ipv6-target-file="+filename +" -M icmp6_echoscan  -f saddr -O json -o  "+output
    # print(command)
    os.system(command)
    end=time.time()
    scantime=float(end-start)
    # print("zmap scanning time is :"+str(scantime)+"s")
    # statistic info
    # command='wc -l '+filename
    # v6_target=os.popen(command)
    # target_number=float(v6_target.read().split()[0])
    # v6_target.close()
    # command='wc -l '+output
    # v6_result=os.popen(command)
    # hited_number=float(v6_result.read().split()[0])
    # v6_result.close()
    # hit_rate=hited_number/target_number
    # statistic= PrettyTable([ "target_number","hited_number","hit_rate","time"])
    # statistic.add_row([int(target_number),int(hited_number),hit_rate,scantime])
    #print(statistic)



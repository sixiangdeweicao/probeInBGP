import os
def statistic():
    filelist=os.listdir("extendLowBytes4")
    print("the BGP that has ipv6 address number is {}".format(len(filelist)))
    # 获取bgp活跃信息
    ipv6_active_list=set()
    bgpset=set()
    bgp_active={}
    for file in filelist:
        bgpinfo=file.split("_")
        bgp_prefix=bgpinfo[0]+"/"+bgpinfo[1]
        bgpset.add(bgp_prefix)
        # read the active file
        count=0
        #print(file)
        if os.path.exists("extendLowBytes4/"+file):
            for line in open("extendLowBytes4/"+file):
                if line=="\n":
                    continue
                ipv6_active_list.add(line)
        else:
            continue
        bgp_active[bgp_prefix]=count
    print("according to probeing all bgp,we find the active ipv6 address number ：{}".format(len(ipv6_active_list)))
    with open("extend_LowBytes_BGP4.csv",'w') as f:
        for ipv6 in ipv6_active_list:
            f.write(ipv6)
    return bgpset

def uniquePro(filename):
    ips=set()
    for line in open(filename):
        ips.add(line)
    print("the count is {}".format(len(ips)))

if __name__ == "__main__":
    statistic()
    #uniquePro("ipv6_active_BGP.csv")
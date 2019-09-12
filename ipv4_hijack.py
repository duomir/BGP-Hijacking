import os
import sys
import time
import requests
import ipaddress
import bz2

from Whois.whoisParser import whoisParser
#from NXDomains.xmlParser import xmlParser

def get_overlap_nets(inet, net_list):
    net_src = ipaddress.IPv4Network(inet)
    net_match = []
    for net in net_list:
        start, end = net['inet'].split('-')
        start_seg = start.strip().split('.')
        end_seg = end.strip().split('.')
        net_len = 0
        for i in range(0,4):
            x = int(end_seg[i]) ^ int(start_seg[i])
            l = 0
            while (x%2 != 0):
                x = int(x/2)
                l += 1
            net_len += (8-l)
            if (l > 0):
                break
        #print(net['inet'], net_len)
        net_format = start.strip()+'/'+str(net_len)
        subnet = ipaddress.IPv4Network(net_format,strict=False)
        if (net_src.overlaps(subnet)):
            net_match.append(net)
    return net_match

def asn_cor(asnlist1, asnlist2, asn_info):
    for asn1 in asnlist1:
        for asn2 in asnlist2:
            if (asn1 == asn2):
                return True
            if (asn1 not in asn_info) or (asn2 not in asn_info):
                return True
            if (set(asn_info[asn1]['orglist']) & set(asn_info[asn2]['orglist'])):
                return True
            #if (org_cor(asn_info[asn1]['orglist'], asn_info[asn2]['orglist'])):
            #    return True
    return False

def co_prefix(str1, str2):
    i = 0
    while (i < len(str1) and i <len(str2)):
        if (str1[i] == str2[i]):
            i += 1
        else:
            break
    return i


def org_cor(orglist1, orglist2, org_info):
    for org1 in orglist1:
        for org2 in orglist2:
            if (co_prefix(org1, org2) > 2):
                return True
    return False


as_rank_url = "http://as-rank.caida.org/api/v1/asns/"

def getASinfo(asn):
        request_url = as_rank_url + str(asn)
        r = requests.get(request_url)
        try:
            res = eval(r.text)
            return res['data']
        except:
            return {}

def getASattr(asn, attr):
        res = getASinfo(asn)
        if (attr in res):
            return int(res[attr])
        else:
            return -1


bgp_folder = "../data/bgp/"
a = whoisParser()

def bgp_scan(date):
    bgp_dir = bgp_folder + date + '/'
    bgp_files = os.listdir(bgp_dir)
    asn_info =  a.getASN('arin',  date)
    inet_info = a.getInet('arin', date)
    for file in bgp_files:
        if not (file.startswith('oix-full-snapshot-')):
            continue
        with bz2.open(bgp_dir+file, 'r') as f:
            inet = ''
            last_inet = ''
            for line in f:
                if (line.startswith('*')):
                    segs = line.split()
                    last_inet = inet
                    inet = segs[1]
                    src = segs[-2]
                    net_len = inet.split('/')[-1]
                    if (last_inet == inet or int(net_len) < 24):
                        continue
                    key = '.'.join(inet.split('.')[:3])
                    if (key in inet_info):
                        net = get_overlap_nets(inet, inet_info[key])
                        asn_path = [segs[i] for i in range(6,len(segs)-1) if segs[i] != segs[i+1]]
                        if (not net['asn'] and getASattr(src, 'rank') > 1000):
                            if (src not in asn_info or (not set(net['orglist']) & set(asn_info[src]['orglist']))):
                                print(inet, src, net['inet'], ' '.join(asn_path))
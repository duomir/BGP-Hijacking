import os
import ipaddress

data_folder = os.getcwd()+'/20180924'
asn_file = data_folder+'/asn_arin'
asn_org = {}
with open(asn_file,'r',encoding = 'latin1') as f:
    col_names = f.readline().strip().split('\t')
    print(col_names)
    for line in f:
        segs = line.strip().split('\t')
        if (segs[4] not in asn_org):
            asn_org[segs[4]] = [segs[2]]
        else:
            asn_org[segs[4]].append(segs[2])

def ipv6_norm(s):
    [src,dst] = s.split('-')
    src = src.strip().split(':')
    dst = dst.strip().split(':')
    cnt = 0
    for i in range(len(src)):
        if (src[i] == dst[i]):
            cnt += 16
        else:
            if (src[i] != ''):
                s = bin(int(src[i],16)^int(dst[i],16))[2:]
                cnt += 16-(len(s)-s.find('1'))
            break
    return ':'.join(src)+'/'+str(cnt)

ip_file = data_folder+'/inetnum_arin'
ip_net = {}
with open(ip_file,'r',encoding = 'latin1') as f:
    col_names = f.readline().strip().split('\t')
    print(col_names)
    for line in f:
        segs = line.strip().split('\t')
        if (segs[0] == 'inet6num'):
            ip_range = ipv6_norm(segs[2])
            #print(ip_range)
            key = ':'.join(ip_range.split(':')[:2])
            key = key[:-3]
            val = (ip_range,segs[6],segs[8])
            if (key not in ip_net):
                ip_net[key] = [val]
            else:
                ip_net[key].append(val)

org_file = data_folder+'/org_arin'
org_map = {}
with open(org_file,'r',encoding = 'latin1') as f:
    col_names = f.readline().strip().split('\t')
    print(col_names)
    for line in f:
        segs = line.strip().split('\t')
        org_id = segs[1]
        org_map[org_id] = []
        org_map[org_id] = [seg for seg in segs[1:3]+segs[4:14] if seg != '']

def asn_cor(asn1,asn2):
    if (asn1 == asn2):
        return True
    if (asn1 not in asn_org) or (asn2 not in asn_org):
        return True
    for org1 in asn_org[asn1]:
        for org2 in asn_org[asn2]:
            if (set(org_map[org1]) & set(org_map[org2])):
                return True
    return False

def org_cor(asn, org):
    for org1 in asn_org[asn]:
        if (set(org_map[org1]) & set(org_map[org])):
            return True
    return False

bgp_file = data_folder+'/bgpTable_ipv6_formatted'

cnt = 0
unmatch = []

with open(bgp_file,'r') as f:
    for line in f:
        [ip,asn] = line.strip().split('\t')
        key = ':'.join(ip.split(':')[:2])
        key = key[:-3]
        if (key in ip_net and asn in asn_org):
            whois_pair = ('','','')
            whois_nets = [item for item in ip_net[key] if (ipaddress.IPv6Network(ip).overlaps(ipaddress.IPv6Network(item[0],strict=False)))]
            is_match = False
            for item in whois_nets:
                for whois_asn in item[1].split(','):
                    if (asn_cor(asn,whois_asn) or org_cor(asn,item[2])):
                        is_match = True
                        break
                    elif (item[1] in asn_org):
                        if (item[0][-2:] > whois_pair[0][-2:]):
                            whois_pair = (item[0],item[1],asn_org[item[1]][0])
            if (not is_match) and (whois_nets):
                cnt += 1
                print('error: ip and asn inconsistent',ip,asn,asn_org[asn])
                print(whois_pair)
                unmatch.append((ip,asn,asn_org[asn][0])+whois_pair)

                #org same
                #elif (asn in asn_org):
                #    if not ((set(asn_org[asn]) & set(ip_org[ip_range]))):
                #        cnt2 += 1
                        #print('error: ip and asn org inconsistent',ip,asn)
                        #org_arin profile
                        #sapmhuas blacklist
                        #ASN blacklist
print(cnt)

with open('output','w') as f:
    f.write('bgp_ip\tbgp_asn\tbgp_org\twhois_ip\twhois_asn\twhois_org\n')
    for line in unmatch:
        f.write('\t'.join(line)+'\n')
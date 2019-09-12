import os
import csv
import bisect

asn_16 = 'as-numbers-1.csv'
asn_32 = 'as-numbers-2.csv'

asn_info = []

def get_asn(filename):
    with open(filename, newline='') as csvfile:
        f = csv.DictReader(csvfile)
        for line in f:
            #print(line['Number'], line['Description'])
            if ('-' not in line['Number']):
                src = dst = line['Number']
            else:
                (src, dst) = line['Number'].split('-')
            asn_info.append((src,dst,line['Description']))


get_asn(asn_16)
get_asn(asn_32)

def in_range(asn, range):
    for item in range:
        if (int(asn) >= int(item[0]) and int(asn) <= int(item[1])):
            return True
    return False

cur_folder = os.getcwd()+'/20180820/'

registry = ['arin']

known_asn = set()
resv_asn = set()

for reg in registry:
    asn_file = cur_folder+'asn_'+reg

    with open(asn_file,'r',encoding = 'latin1') as f:
        col_names = f.readline().strip().split('\t')
        #print(col_names)
        for line in f:
            segs = line.strip().split('\t')
            asn = segs[4]
            if (reg != 'arin' and reg != 'lacnic'):
                asn = asn[2:]
            if ('-' in asn):
                (src, dst) = asn.split('-')
            else:
                src = dst = asn
            for i in range(int(src), int(dst)+1):
                if ('Reserved' in line):
                    resv_asn.add(str(i))
                else:
                    known_asn.add(str(i))

print(len(known_asn), len(resv_asn))

resv_asn = set()
unalloc_asn = set()

def query_asn(a):
    asn_list = [item[0] for item in asn_info]
    idx = bisect.bisect_left(asn_list,a)
    #print(idx)
    if (idx and 'ARIN' in asn_info[idx-1][2]):
        return True
    return False

bgp_file = cur_folder+'bgpTable_ipv4'

with open(bgp_file,'r') as f:
    for line in f:
        [ip,asn] = line.strip().split('\t')
        for a in asn.split('|'):
            if (query_asn(a)):
                if (a in known_asn):
                    continue
                elif (a in resv_asn):
                    print(ip, a)
                    resv_asn.add(a)
                else:
                    print(ip, a)
                    unalloc_asn.add(a)

print(len(resv_asn), len(unalloc_asn))

with open('unknown asn','w') as f:
    for asn in unalloc_asn:
        f.write(asn+'\n')
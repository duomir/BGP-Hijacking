from collections import Counter

def getBGPrelation(srcFolder):
    as_neighbor = {}
    with open(srcFolder) as f:
        for line in f:
            segs = line.split()
            if (len(segs) > 0 and segs[0] == '*'):
                for i in range(6,len(segs)-2):
                    if (segs[i] == segs[i+1]):
                        continue;
                    elif (segs[i] in as_neighbor):
                        as_neighbor[segs[i]].add(segs[i+1])
                    else:
                        as_neighbor[segs[i]] = set([segs[i+1]])

    return as_neighbor

def getDropAsn(srcFolder):
    drop_asn = []
    with open(srcFolder) as f:
        for line in f:
            asn = line.strip().split(';')[0]
            if (asn):
                drop_asn.append(asn[2:].strip())

    return drop_asn

MAXLEN = 5

def is_in_path(asn, droplist, path):
    if (asn not in as_neighbor) or (len(path) == MAXLEN):
        return False

    for nexthop in as_neighbor[asn]:
        path.append(nexthop)
        if (nexthop in droplist):
            return True
        if (is_in_path(nexthop, droplist, path)):
            return True
        path = path[:-1]
    return False


as_neighbor = getBGPrelation("oix-full-snapshot-2018-07-04-0200")

#print(as_neighbor['13537'])

def traverse_asn(asn, asnlist):
    if (asn not in as_neighbor):
        return
    for nexthop in as_neighbor[asn]:
        asnlist.add(nexthop)
        traverse_asn(nexthop, asnlist)
    return

'''
watchlist = ['197426', '205869', '57756']

for asn in watchlist:
    asnlist = set([asn])
    traverse_asn(asn, asnlist)

    for item in asnlist:
        if (item in as_neighbor):
            print(item, as_neighbor[item])

'''

drop_asn = getDropAsn("asndrop_2018-07-04")
print(len(drop_asn))
asn_host = {}
for asn in drop_asn:
    #droplist = set(drop_asn) - {asn}
    #path = [asn]
    #if (is_in_path(asn, droplist, path)):
    if (asn in as_neighbor):
        asn_host[asn]= as_neighbor[asn]
        #for nexthop in as_neighbor:
        #    asn_host[nexthop] = as_neighbor[nexthop]

print(len(asn_host))

with open("asn_graph.dot", 'w') as f:
    f.write("digraph <asndrop_2018-07-04> {\n")
    for key in asn_host.keys():
        if (key in drop_asn):
            f.write(key+'[color = red]\n')
    for key,val in asn_host.items():
        f.write(key+'->{'+';'.join(val)+'}\n')
    f.write("}")


with open("asn_host", 'w') as f:
    for key,val in asn_host.items():
        f.write(key+'\t'+','.join(val)+'\n')
import requests
import ipaddress

class ASparser:

    def __init__(self):
        self.drop_asn = []
        self.drop_ipnet = {}
        self.as_neighbor = {}
        self.susp_asn = {}
        self.as_info = {}
        self.as_rank_url = "http://as-rank.caida.org/api/v1/asns/"

    def getBGPrelation(self, bgpFile):
        with open(bgpFile) as f:
            for line in f:
                if (line.startswith('*')):
                    segs = line.split()
                    for i in range(6, len(segs) - 2):
                        if (segs[i] == segs[i + 1]):
                            continue;
                        elif (segs[i] in self.as_neighbor):
                            self.as_neighbor[segs[i]].add(segs[i + 1])
                        else:
                            self.as_neighbor[segs[i]] = set([segs[i + 1]])
        return self.as_neighbor

    def is_overlap(self, ipnet, ipnet_dict):
        key = '.'.join(ipnet.split('.')[:2])
        if (key not in ipnet_dict):
            return False
        for ipnet_tmp in ipnet_dict[key]:
            net1 = ipaddress.ip_network(ipnet,False)
            net2 = ipaddress.ip_network(ipnet_tmp, False)
            if (net1.overlaps(net2)):
                return True
        return False

    def getDropIpNet(self, spamhausFile):
        with open(spamhausFile) as f:
            for line in f:
                ipnet = line.strip().split(';')[0]
                if (ipnet):
                    key = '.'.join(ipnet.split('.')[:2])
                    if (key in self.drop_ipnet):
                        self.drop_ipnet[key].append(ipnet.strip())
                    else:
                        self.drop_ipnet[key] = [ipnet.strip()]

        return self.drop_ipnet

    def getSuspASN(self, bgpFile, dropFile):
        drop_ipnet = self.getDropIpNet(dropFile)
        if not (drop_ipnet):
            return None

        with open(bgpFile) as f:
            for line in f:
                if (line.startswith('*')):
                    segs = line.split()
                    ipnet = segs[1]
                    src_asn = segs[-2]
                    if (src_asn in self.susp_asn):
                        continue
                    elif (self.is_overlap(ipnet,drop_ipnet)):
                        print(src_asn)
                        self.susp_asn.add(src_asn)

        return self.susp_asn


    def getDropASN(self, spamhausFile):
        with open(spamhausFile) as f:
            for line in f:
                asn = line.strip().split(';')[0]
                if (asn):
                    self.drop_asn.append(asn[2:].strip())

        return self.drop_asn

    def getASinfo(self, asn):
        request_url = self.as_rank_url + str(asn)
        r = requests.get(request_url)
        try:
            res = eval(r.text)
            return res['data']
        except:
            return {}

    def getASattr(self, asn, attr):
        res = self.getASinfo(asn)
        if (attr in res):
            return int(res[attr])
        else:
            return -1

###test###
def saveSuspASN_info():
    a = ASparser()
    as_neighbor = a.getBGPrelation("../data/bgp/oix-full-snapshot-2019-07-04-0200")
    a.susp_asn = set(a.getDropASN("../data/blacklist/asndrop_2019-07-04"))
    a.susp_asn = a.getSuspASN("../data/bgp/oix-full-snapshot-2019-07-04-0200", "../data/blacklist/drop_2019-07-04")

    with open('susp_asn_2019-07-04', 'w') as f:
        for asn in a.susp_asn:
            rank = a.getASattr(asn, 'rank')
            if (asn in as_neighbor):
                f.write(asn+'\t'+str(rank)+'\t'+','.join(as_neighbor[asn])+'\n')

def getASgraph():
    susp_asn = {}
    with open('susp_asn_2019-07-04')  as f:
        for line in f:
            segs = line.strip().split('\t')
            if (int(segs[1]) > 1000 or int(segs[1]) == -1):
                susp_asn[segs[0]] = {'rank': segs[1]}
                susp_asn[segs[0]]['neigh'] = segs[2]

    a = ASparser()
    drop_asn = set(a.getDropASN("../data/blacklist/asndrop_2019-07-04"))
    with open("asn_graph_2019-07-04.dot", 'w') as f:
        f.write("digraph <asndrop_2019-07-04> {\n")
        asn_set = set()
        for key,val in susp_asn.items():
            asn_set.add(key)
            if ('neigh' in val):
                asn_set |= set(val['neigh'].split(','))
        for asn in asn_set:
            if (asn in drop_asn):
                f.write(asn + '[color = red]\n')
            elif (asn in susp_asn):
                f.write(asn + '[color = blue]\n')
        for key, val in susp_asn.items():
            if ('neigh' in val):
                f.write(key + '-> {' + val['neigh'] + '}\n')
        f.write("}")

#saveSuspASN_info()
getASgraph()
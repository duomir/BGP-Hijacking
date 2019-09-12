
class whoisParser():
    def __init__(self):
        self.whois_folder = "../data/whois/"
        self.registry = ['arin']

    def getASN(self, src, date):
        asn_info = {}
        asn_file = self.whois_folder + date+ '/asn_'+ src
        with open(asn_file,'r',encoding = 'latin1') as f:
            col_names = f.readline().strip().split('\t')
            print(col_names)
            for line in f:
                segs = line.strip().split('\t')
                item = {'orglist': segs[2].split('|'), 'src': src}
                asn = segs[1][2:]
                if (asn not in asn_info):
                    asn_info[asn] = item
                else:
                    asn_info[asn]['orglist'] += segs[2].split('|')
        return asn_info

    def getInet(self, src, date):
        inet_info = {}
        ip_file = self.whois_folder + date+'/inetnum_' + src
        with open(ip_file,'r',encoding = 'latin1') as f:
            col_names = f.readline().strip().split('\t')
            print(col_names)
            for line in f:
                segs = line.strip().split('\t')
                #only select inet4
                if (segs[0] == 'inetnum'):
                    inet = segs[2]
                    key = '.'.join(inet.split('.')[:3])
                    ip_net = {'inet':inet, 'asn':segs[6], 'orglist':segs[8].split('|')}
                    if (key not in inet_info):
                        inet_info[key] = [ip_net]
                    else:
                        inet_info[key].append(ip_net)
        return inet_info

    def getOrg(self, src, date):
        org_info = {}
        org_file = self.whois_folder + date + '/org_' + src
        with open(org_file, 'r', encoding='latin1') as f:
            col_names = f.readline().strip().split('\t')
            print(col_names)
            for line in f:
                segs = line.strip().split('\t')
                org_id = segs[1]
                org_info[org_id] = []
                org_info[org_id] = [seg for seg in segs[1:3] + segs[4:14] if seg != '']
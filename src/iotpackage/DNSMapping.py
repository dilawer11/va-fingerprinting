import pandas as pd
import os.path
import json

class DNSMapper:
    post_dns_mapping_path = None
    def __init__(self, post_dns_mapping=None, save_mapping_on_update=False):
        self.DNS_mapping = {}
        self.post_DNS_mapping = None
        self.save_mapping_on_update = save_mapping_on_update
        if isinstance(post_dns_mapping, str):
            self.post_dns_mapping_path = post_dns_mapping
            with open(post_dns_mapping, 'r') as f:
                self.post_DNS_mapping = json.load(f)
        else:
            self.post_DNS_mapping = post_dns_mapping
        
    def saveDNSMapping(self):
        if self.post_dns_mapping_path is None: return
        mapping = self.post_DNS_mapping
        mapping.update(self.DNS_mapping)
        with open(self.post_dns_mapping_path, 'w+') as f:
            json.dump(mapping, f, indent=4)
        return
    
    def processDNSMapping(self, dns, dns_mapping={}):
        if not isinstance(dns, pd.DataFrame):
            dns = pd.read_csv(dns)
        dns.apply(self.addDNSResponseToMapping, axis=1, args=(dns_mapping,))
        return dns_mapping

    def addDNSResponseToMapping(self, res, dns_mapping):
        hostname = res['dns.qry.name']
        a_records = res['dns.a']
        if not isinstance(a_records, str): return
        a_records = a_records.split(',')
        for ip in a_records:
            dns_mapping[ip] = hostname
        return

    def assignHostnames(self, packets, dns_fp=None, method='both'):
        packets['hostname'] = None
        if method in ['both', 'live']:
            packets = self.assignHostnamesLive(packets, dns_fp)
        if method in ['both', 'post']:
            leftover_idx = packets['hostname'].isna()
            packets.loc[leftover_idx, 'hostname'] = packets.loc[leftover_idx, 'ip'].apply(self.getHostnameFromMapping, args=(self.post_DNS_mapping,))
        leftover_idx = packets['hostname'].isna()
        packets.loc[leftover_idx, 'hostname'] = packets.loc[leftover_idx, 'ip'].copy()
        return packets
       
    def __addDNSResponseToList(self, res, dns_list):
        """
        Adds DNS response to DNS List. Adds by taking hostname and response time and A records and storing them as (time, hostname, a_records) tuple in the list
        """
        hostname = res['dns.qry.name']
        a_records = res['dns.a']
        if not isinstance(a_records, str): return
        a_records = a_records.split(',')
        dns_list.append((res['frame.time_epoch'], hostname, a_records))
        return

    def getHostnameFromMapping(self, ip, dns_mapping):
        if ip in dns_mapping:
            return dns_mapping[ip]
        else:
            return None
        
    def __loadDNSDataList(self, dns_fname:str):
        """
        Description
        -----------
        Takes the path to a dns csv file loads it from disk and returns the dns list of tuples to be used to assign hostnames
        
        Parameters
        ----------
        dns_fname: the path to a dns file created when converting pcaps to csv by PCAP2CSV script

        Returns
        -------
        list: the list of dns entries which need to be processed
        """
        dns_data = pd.read_csv(dns_fname)
        dns_list = []
        dns_data.apply(self.__addDNSResponseToList, axis=1, args=(dns_list,))
        return dns_list

    def __getHostnameFromDNS(self, pkt):
        # The pkt is None condition is required to enter any remaining records to the mapping. Don't delete it
        if pkt is None:
            pkt_time = float('inf')
            pkt_ip = ''
        else:
            pkt_time = pkt['frame.time_epoch']
            pkt_ip = pkt['ip']
        while self.DNS_ptr < self.__n_DNS_data and self.DNS_data[self.DNS_ptr][0] <= pkt_time:
            host_name = self.DNS_data[self.DNS_ptr][1]
            ips = self.DNS_data[self.DNS_ptr][2]
            for ip in ips:
                self.DNS_mapping[ip] = host_name
            self.DNS_ptr += 1
        if pkt_ip in self.DNS_mapping: return self.DNS_mapping[pkt_ip]
        else: return None

    def assignHostnamesLive(self, packets, dns_fp):
        if packets.shape[0]:
            self.DNS_ptr = 0
            self.DNS_data = self.__loadDNSDataList(dns_fp)
            self.__n_DNS_data = len(self.DNS_data)
            packets['hostname'] = packets.apply(self.__getHostnameFromDNS, axis=1)
            # Add the remaining DNS records to mapping file
            self.__getHostnameFromDNS(None)
            if (self.__n_DNS_data > 0) and self.save_mapping_on_update: self.saveDNSMapping()
        else:
            packets['hostname'] = None
        return packets
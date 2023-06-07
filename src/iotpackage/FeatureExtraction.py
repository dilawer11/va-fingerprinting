import os
import numpy as np
import pandas as pd
import logging

l = logging.getLogger('FeatureExtraction')

class FeatureExtracter:
    __minPackets = None
    __burstThreshold = None
    __burstCols = ['direction', 'start_time', 'end_time', 'n_packets', 'length']
    __protoTCP = 6
    __protoUDP = 17
    __protoICMP = 1

    def __init__(self, min_packets=1, burst_threshold=2, flow_threshold=2):
        self.__minPackets = min_packets
        self.__burstThreshold = burst_threshold
        self.__flowThreshold = flow_threshold

    def getIPOctet(self, ip, octets=3):
        ipArray = ip.split('.')
        ipoctets = '.'.join(ipArray[:octets])
        return ipoctets

    def getTldPlus(self, hostname, plus=1):
        idx = -(plus + 1)
        hostname_arr = hostname.split('.')
        tldhostname = '.'.join(hostname_arr[idx:])
        return tldhostname


# N Count Dicts
    # def extractDevicePortCount(self, allPackets, outgoingPackets, incomingPackets):
    #     '''
    #     FEATURES
    #         Device Port Dict
    #         Device Port TLSTCP
    #         Device Port DNS
    #         Device Port UDP
    #         Device Port NTP
    #     '''
    #     device_port_dict = self.extractDevicePortCountHelper(outgoingPackets, incomingPackets, protocols=None)
    #     tlstcp_device_port = self.extractDevicePortCountHelper(outgoingPackets, incomingPackets, protocols=self.__TLSTCPList)
    #     dns_device_port = self.extractDevicePortCountHelper(outgoingPackets, incomingPackets, protocols=self.__DNSList)
    #     udp_device_port = self.extractDevicePortCountHelper(outgoingPackets, incomingPackets, protocols=self.__UDPList)
    #     ntp_device_port = self.extractDevicePortCountHelper(outgoingPackets, incomingPackets, protocols=self.__NTPList)

    #     return [
    #         device_port_dict,
    #         tlstcp_device_port,
    #         dns_device_port,
    #         udp_device_port,
    #         ntp_device_port]
    def extractExternalPortCount(self, allPackets, outgoingPackets, incomingPackets, featureDict:dict) -> None:
        '''
        FEATURES
            all_dict_extport
            tcp_dict_extport
            udp_dict_extport
        '''
        featureDict['all_dict_extport'] = self.extractExternalPortCountHelper(allPackets, protos=None)
        featureDict['tcp_dict_extport'] = self.extractExternalPortCountHelper(allPackets, protos=[self.__protoTCP])
        featureDict['udp_dict_extport'] = self.extractExternalPortCountHelper(allPackets, protos=[self.__protoUDP])

        return

    def extractContactedIP(self, allPackets:pd.DataFrame, outgoingPackets:pd.DataFrame, incomingPackets:pd.DataFrame, featureDict:dict) -> None:
        '''
        FEATURES
            all_dict_ip
            tcp_dict_ip
            udp_dict_ip
        '''
        featureDict['all_dict_ip'] = self.extractContactedIPHelper(allPackets, protos=None)
        featureDict['tcp_dict_ip'] = self.extractContactedIPHelper(allPackets, protos=[self.__protoTCP])
        featureDict['udp_dict_ip'] = self.extractContactedIPHelper(allPackets, protos=[self.__protoUDP])

        return

    def extractContactedHostName(self, allPackets:pd.DataFrame, outgoingPackets:pd.DataFrame, incomingPackets:pd.DataFrame, featureDict:dict) -> None:
        '''
        FEATURES
            all_dict_hostname
            tcp_dict_hostname
            udp_dict_hostname
        '''
        featureDict['all_dict_hostname'] = self.extractContactedHostNameHelper(allPackets, protos=None)
        featureDict['tcp_dict_hostname'] = self.extractContactedHostNameHelper(allPackets, protos=[self.__protoTCP])
        featureDict['udp_dict_hostname'] = self.extractContactedHostNameHelper(allPackets, protos=[self.__protoUDP])

        return

    def extractProtocols(self, allPackets:pd.DataFrame, outgoingPackets:pd.DataFrame, incomingPackets:pd.DataFrame, featureDict:dict) -> None:
        '''
        FEATURES
            in_protocols_dict_protocols
            out_protocols_dict_protocols
            in_protos_dict_protocols
            out_protos_dict_protocols
        '''
        try:
            in_protocols = dict(incomingPackets['_ws.col.Protocol'].value_counts())
        except:
            logging.exception("in_protocols")
            in_protocols = dict()

        try:
            out_protocols = dict(outgoingPackets['_ws.col.Protocol'].value_counts())
        except:
            logging.exception("out_protocols")
            out_protocols = dict()
            
        try:
            in_protos = dict(incomingPackets['ip.proto'].value_counts())
        except:
            logging.exception("in_protos")
            in_protos = dict()

        try:
            out_protos = dict(outgoingPackets['ip.proto'].value_counts())
        except:
            logging.exception("out_protos")
            out_protos = dict()
        
        featureDict['in_protocols_dict_protocols'] = in_protocols
        featureDict['out_protocols_dict_protocols'] = out_protocols
        featureDict['in_protos_dict_protocols'] = in_protos
        featureDict['out_protos_dict_protocols'] = out_protos
        return

    def extractPacketSizes(self, allPackets:pd.DataFrame, outgoingPackets:pd.DataFrame, incomingPackets:pd.DataFrame, featureDict:dict) -> None:
        '''
        FEATURES
            out_all_dict_packetlens
            out_tcp_dict_packetlens
            out_udp_dict_packetlens
            in_all_dict_packetlens
            in_tcp_dict_packetlens
            in_udp_dict_packetlens
        '''
        
        featureDict['out_all_dict_packetlens'] = self.extractPacketSizesHelper(outgoingPackets, protos=None)
        featureDict['out_tcp_dict_packetlens'] = self.extractPacketSizesHelper(outgoingPackets, protos=[self.__protoTCP])
        featureDict['out_udp_dict_packetlens'] = self.extractPacketSizesHelper(outgoingPackets, protos=[self.__protoUDP])

        featureDict['in_all_dict_packetlens'] = self.extractPacketSizesHelper(incomingPackets, protos=None)
        featureDict['in_tcp_dict_packetlens'] = self.extractPacketSizesHelper(incomingPackets, protos=[self.__protoTCP])
        featureDict['in_udp_dict_packetlens'] = self.extractPacketSizesHelper(incomingPackets, protos=[self.__protoUDP])

        return

    def extractRequestReplyLengths(self, allPackets:pd.DataFrame, outgoingPackets:pd.DataFrame, incomingPackets:pd.DataFrame, featureDict:dict) -> None:
        '''
        FEATURES
            all_dict_reqreplylens
            tcp_dict_reqreplylens
            udp_dict_reqreplylens
        '''
        featureDict['all_dict_reqreplylens'] = self.extractRequestReplyLengthsHelper(allPackets, protos=None)
        featureDict['tcp_dict_reqreplylens'] = self.extractRequestReplyLengthsHelper(allPackets, protos=[self.__protoTCP])
        featureDict['udp_dict_reqreplylens'] = self.extractRequestReplyLengthsHelper(allPackets, protos=[self.__protoUDP])

        return

# Helpers
    def groupBurstPackets(self, allPackets):
        # l.info(f'Grouping Burst Packets, threshold: {self.__burstThreshold}')
        lstpktip = ''
        lstpkttype = ''
        burstpkts = 0
        burstsize = 0
        startpktime = None
        lstpkttime = None
        newburst = True
        burstsArray=[]
        for pkt in allPackets.iterrows():
            pktType = pkt[1]['direction']
            pktTime = pkt[1]['frame.time_epoch']
            pktIP = pkt[1]['ip']
            pktLength = pkt[1]['frame.len']
            if lstpkttype == pktType and lstpktip == pktIP:
                if newburst:
                    startpktime = lstpkttime
                    newburst = False
                burstpkts += 1
                burstsize += pktLength
            else:
                if burstpkts >= self.__burstThreshold:
                    burstsArray.append([lstpkttype, startpktime, lstpkttime, burstpkts, burstsize])
                newburst = True
                burstpkts = 1
                burstsize = pktLength
            lstpkttype = pktType
            lstpktip = pktIP
            lstpkttime = pktTime
        if burstpkts >= self.__burstThreshold:
            burstsArray.append([lstpkttype, startpktime, lstpkttime, burstpkts, burstsize])
        return pd.DataFrame(burstsArray, columns=self.__burstCols)

    def groupFlowPackets(self, allPackets):
        # l.info(f'Grouping Flow Packets, threshold: {self.__flowThreshold}')
        
        flows = []

        def func(pkts):
            if pkts.shape[0] > self.__flowThreshold:
                flow = {}
                flow['direction'] = pkts.name[0]
                flow['start_time'] = pkts['frame.time_epoch'].min()
                flow['end_time'] = pkts['frame.time_epoch'].max()
                flow['n_packets'] = pkts.shape[0]
                flow['length'] = pkts['frame.len'].sum()
                flows.append(flow)
        
        allPackets.groupby(['direction', 'ip', 'int.port', 'ext.port', 'ip.proto'], group_keys=False).apply(func)
        if len(flows):
            flows = pd.DataFrame(flows)
        else:
            flows = pd.DataFrame([], columns=self.__burstCols)
        return flows

    # def __convertTimeStamp(self, timestamps, from_unit='nano', to_unit='milli'):
    #     value = 0
    #     if from_unit == 'nano':
    #         value -= 9
    #     elif from_unit == 'micro':
    #         value -= 6
    #     elif from_unit == 'milli':
    #         value -= 3
    #     else:
    #         raise Exception('from_unit not recognized: {}'.format(from_unit))
    #     if to_unit == 'nano':
    #         value += 9
    #     elif to_unit == 'micro':
    #         value += 6
    #     elif to_unit == 'milli':
    #         value += 3
    #     else:
    #         raise Exception('to_unit not recognized: {}'.format(to_unit))
    #     multiplier = 10 ** value
    #     retVal = np.float64(timestamps) * multiplier
    #     try:
    #         len(retVal)
    #     except:
    #         retVal = [retVal]
    #     finally:
    #         return retVal
    # def extractProtocolBasedInterPacketDelayHelper(self, allPackets, outgoingPackets, incomingPackets, protocols, outgoing=True, incoming=True):
    #     # TODO: Add 10per
    #     '''
    #     FEATURES
    #         out_mean_inter_proto_pkt_delay          
    #         out_median_inter_proto_pkt_delay          
    #         out_25per_inter_proto_pkt_delay
    #         out_75per_inter_proto_pkt_delay
    #         out_90per_inter_proto_pkt_delay
    #         out_std_inter_proto_pkt_delay
    #         out_max_inter_proto_pkt_delay
    #         out_min_inter_proto_pkt_delay
    #         in_mean_inter_proto_pkt_delay          
    #         in_median_inter_proto_pkt_delay          
    #         in_25per_inter_proto_pkt_delay
    #         in_75per_inter_proto_pkt_delay
    #         in_90per_inter_proto_pkt_delay
    #         in_std_inter_proto_pkt_delay
    #         in_max_inter_proto_pkt_delay
    #         in_min_inter_proto_pkt_delay
    #     '''
    #     returnArray = []

    #     if outgoing:
    #         try:
    #             proto_outgoingPackets = outgoingPackets[outgoingPackets['Protocol'].isin(protocols)]
    #             proto_outgoingPackets_time = proto_outgoingPackets['TimeStamp'].values
    #             proto_outgoingPackets_interpktdelay = proto_outgoingPackets_time[1:] - proto_outgoingPackets_time[:-1]
    #             proto_outgoingPackets_interpktdelay = self.__convertTimeStamp(proto_outgoingPackets_interpktdelay)
    #         except Exception as e:
    #             print(e)
    #             proto_outgoingPackets_interpktdelay = []
    #         if len(proto_outgoingPackets_interpktdelay):
    #             out_mean_inter_proto_pkt_delay = np.mean(proto_outgoingPackets_interpktdelay)      
    #             out_median_inter_proto_pkt_delay = np.median(proto_outgoingPackets_interpktdelay)           
    #             out_25per_inter_proto_pkt_delay = np.percentile(proto_outgoingPackets_interpktdelay, 25)
    #             out_75per_inter_proto_pkt_delay = np.percentile(proto_outgoingPackets_interpktdelay, 75)
    #             out_90per_inter_proto_pkt_delay = np.percentile(proto_outgoingPackets_interpktdelay, 90)
    #             out_std_inter_proto_pkt_delay = np.std(proto_outgoingPackets_interpktdelay)
    #             out_max_inter_proto_pkt_delay = np.max(proto_outgoingPackets_interpktdelay)
    #             out_min_inter_proto_pkt_delay = np.min(proto_outgoingPackets_interpktdelay)
    #         else:
    #             out_mean_inter_proto_pkt_delay = np.nan           
    #             out_median_inter_proto_pkt_delay = np.nan           
    #             out_25per_inter_proto_pkt_delay = np.nan 
    #             out_75per_inter_proto_pkt_delay = np.nan 
    #             out_90per_inter_proto_pkt_delay = np.nan 
    #             out_std_inter_proto_pkt_delay = np.nan 
    #             out_max_inter_proto_pkt_delay = np.nan 
    #             out_min_inter_proto_pkt_delay = np.nan 

    #         returnArray.extend([
    #             out_mean_inter_proto_pkt_delay,          
    #             out_median_inter_proto_pkt_delay,          
    #             out_25per_inter_proto_pkt_delay,
    #             out_75per_inter_proto_pkt_delay,
    #             out_90per_inter_proto_pkt_delay,
    #             out_std_inter_proto_pkt_delay,
    #             out_max_inter_proto_pkt_delay,
    #             out_min_inter_proto_pkt_delay
    #         ])
    #     if incoming:
    #         try:
    #             proto_incomingPackets = incomingPackets[incomingPackets['Protocol'].isin(protocols)]
    #             proto_incomingPackets_time = proto_incomingPackets['Time'].values
    #             proto_incomingPackets_interpktdelay = proto_incomingPackets_time[1:] - proto_incomingPackets_time[:-1]
    #             proto_incomingPackets_interpktdelay = self.__convertTimeStamp(proto_incomingPackets_interpktdelay)
    #         except Exception as e:
    #             print(e)
    #             proto_incomingPackets_interpktdelay = []
        
    #         if len(proto_incomingPackets_interpktdelay):
    #             in_mean_inter_proto_pkt_delay = np.mean(proto_incomingPackets_interpktdelay)      
    #             in_median_inter_proto_pkt_delay = np.median(proto_incomingPackets_interpktdelay)           
    #             in_25per_inter_proto_pkt_delay = np.percentile(proto_incomingPackets_interpktdelay, 25)
    #             in_75per_inter_proto_pkt_delay = np.percentile(proto_incomingPackets_interpktdelay, 75)
    #             in_90per_inter_proto_pkt_delay = np.percentile(proto_incomingPackets_interpktdelay, 90)
    #             in_std_inter_proto_pkt_delay = np.std(proto_incomingPackets_interpktdelay)
    #             in_max_inter_proto_pkt_delay = np.max(proto_incomingPackets_interpktdelay)
    #             in_min_inter_proto_pkt_delay = np.min(proto_incomingPackets_interpktdelay)
    #         else:
    #             in_mean_inter_proto_pkt_delay = np.nan           
    #             in_median_inter_proto_pkt_delay = np.nan           
    #             in_25per_inter_proto_pkt_delay = np.nan 
    #             in_75per_inter_proto_pkt_delay = np.nan 
    #             in_90per_inter_proto_pkt_delay = np.nan 
    #             in_std_inter_proto_pkt_delay = np.nan 
    #             in_max_inter_proto_pkt_delay = np.nan 
    #             in_min_inter_proto_pkt_delay = np.nan 

    #         returnArray.extend([
    #             in_mean_inter_proto_pkt_delay,          
    #             in_median_inter_proto_pkt_delay,          
    #             in_25per_inter_proto_pkt_delay,
    #             in_75per_inter_proto_pkt_delay,
    #             in_90per_inter_proto_pkt_delay,
    #             in_std_inter_proto_pkt_delay,
    #             in_max_inter_proto_pkt_delay,
    #             in_min_inter_proto_pkt_delay
    #         ])
    #     return returnArray
    # def extractInternalPortCountHelper(self, allPackets, protos):
    #     '''
    #     Counts the frequency of internal ports of packets using given proto (TCP, UDP etc.). If proto=None counts for all protos
    #     '''
    #     try:
    #         if protos is not None:
    #             idx = allPackets['ip.proto'].isin(protos)
    #             vc = dict(allPackets.loc[idx, 'int.port'].value_counts())
    #         else:
    #             vc = dict(allPackets['int.port'].value_counts())
    #     except:
    #         l.exception('extractInternalPortCountHelper')
    #         vc = dict()
        
    #     return dict(vc)
    def extractExternalPortCountHelper(self, allPackets, protos=None):
        '''
        Counts the frequency of external ports of packets using given proto (TCP, UDP etc.). If proto=None counts for all protos
        '''
        try:
            if protos is not None:
                idx = allPackets['ip.proto'].isin(protos)
                vc = dict(allPackets.loc[idx, 'ext.port'].value_counts())
            else:
                vc = dict(allPackets['ext.port'].value_counts())
        except:
            l.exception('extractExternalPortCountHelper')
            vc = dict()
        
        return dict(vc)
        
    def extractContactedIPHelper(self, allPackets, protos=None):
        '''
        extracts the contacted ips in all packets in given protos. If protos=None extracts from all protos
        contacted_ip
        '''
        try:
            if protos is not None:
                idx = allPackets['ip.proto'].isin(protos)
                contacted_ips = allPackets.loc[idx, 'ip'].apply(self.getIPOctet)
                vc = dict(contacted_ips.value_counts())
            else:
                contacted_ips = allPackets['ip'].apply(self.getIPOctet)
                vc = dict(contacted_ips.value_counts())
        except:
            l.exception('extractContactedIPHelper')
            vc = dict()
        return vc
    def extractContactedHostNameHelper(self, allPackets, protos=None):
        '''
        Extracts the contacted hostnames in packets of given protos. If protos=None extracts from all packets
        '''
        try:
            if protos is not None:
                idx = allPackets['ip.proto'].isin(protos)
                vc = dict(allPackets.loc[idx, 'hostname'].value_counts())
            else:
                vc = dict(allPackets['hostname'].value_counts())
        except:
            l.exception('extractContactedHostNameHelper')
            vc = dict()
        
        return vc
    def extractPacketSizesHelper(self, allPackets:pd.DataFrame, protos:list=None) -> pd.Series:
        '''
        Extracts frequences of unique packet sizes from the packets of given protos. If protos=None uses all packets
        '''
        try:
            if protos is not None:
                idx = allPackets['ip.proto'].isin(protos)
                vc = dict(allPackets.loc[idx, 'frame.len'].value_counts())
            else:
                vc = dict(allPackets['frame.len'].value_counts())
        except:
            l.exception('extractPacketSizesHelper')
            vc = dict()
        
        return vc

    def extractRequestReplyLengthsHelper(self, allPackets:pd.DataFrame, protos:list=None):
        '''
        Extracts the request-reply total packet lengths from packets of given protos. If protos=None uses all packets
        '''
        if protos is not None:
            packets = allPackets[allPackets['ip.proto'].isin(protos)]
        else:
            packets = allPackets
        requestreplylengths_pair_arr = []
        keyValStore = {} 
        for _, pkt in packets.iterrows():
            pktLength = pkt['frame.len']
            pktProto = pkt['ip.proto']
            pktIP = pkt['ip']
            pktIntPort = pkt['int.port']
            pktExtPort = pkt['ext.port']
            pktDirection = pkt['direction']
            conn_id = (pktIP, pktIntPort, pktExtPort, pktProto).__hash__()
            if pktDirection == 'out':
                if conn_id in keyValStore:
                    if keyValStore[conn_id][1] > 0:
                        requestreplylengths_pair_arr.append((keyValStore[conn_id][0], keyValStore[conn_id][1]))
                        keyValStore[conn_id] = [pktLength, 0]
                    else:
                        keyValStore[conn_id][0] += pktLength
                else:
                    keyValStore[conn_id] = [pktLength, 0]
            elif pktDirection == 'in':
                if conn_id in keyValStore:
                    keyValStore[conn_id][1] += pktLength
                    del keyValStore[conn_id]
            else:
                raise AssertionError(f"Unexpected packet 'direction' {pktDirection}")
        for conn_id in keyValStore:
            requestreplylengths_pair_arr.append((keyValStore[conn_id][0], keyValStore[conn_id][1]))
        # Count the frequencies
        unique, counts = np.unique(requestreplylengths_pair_arr, return_counts=True)
        freq = dict(np.array([unique, counts]).T)
        return freq

# Feature Extracting Functions Level 2
    def __extractTotalPkts(self, allPackets:pd.DataFrame, outgoingPackets:pd.DataFrame, incomingPackets:pd.DataFrame, featureDict:dict) -> None:
        '''
        FEATURES:
            out_totalpkts
            in_totalpkts
        '''
        try:
            out_totalpkts = outgoingPackets.shape[0]
        except:
            l.exception('__extractTotalPkts, out_totalpkts')
            out_totalpkts = 0
        try:
            in_totalpkts = incomingPackets.shape[0]
        except:
            l.exception('__extractTotalPkts, in_totalpkts')
            in_totalpkts = 0

        featureDict['out_totalpkts'] = out_totalpkts
        featureDict['in_totalpkts'] = in_totalpkts
        return

    def __extractTotalBytes(self, allPackets:pd.DataFrame, outgoingPackets:pd.DataFrame, incomingPackets:pd.DataFrame, featureDict:dict) -> None:
        '''
        FEATURES: 
            out_totalbytes
            in_totalbytes
        '''
        try:
            out_totalbytes = outgoingPackets['frame.len'].sum()
        except:
            l.exception('__extractTotalBytes, out_totalbytes')
            out_totalbytes = 0
        try:
            in_totalbytes = incomingPackets['frame.len'].sum()
        except:
            l.exception('__extractTotalBytes, in_totalbytes')
            in_totalbytes = 0

        featureDict['out_totalbytes'] = out_totalbytes
        featureDict['in_totalbytes'] = in_totalbytes
        return

    def __extractUniqueLen(self, allPackets:pd.DataFrame, outgoingPackets:pd.DataFrame, incomingPackets:pd.DataFrame, featureDict:dict) -> None:
        '''
        FEATURES:
            out_mean_uniquelen
            in_mean_uniquelen
            out_median_uniquelen
            in_median_uniquelen
            out_10per_uniquelen
            in_10per_uniquelen
            out_25per_uniquelen
            in_25per_uniquelen
            out_75per_uniquelen
            in_75per_uniquelen
            out_90per_uniquelen
            in_90per_uniquelen
            out_std_uniquelen
            in_std_uniquelen
            out_len_uniquelen
            in_len_uniquelen
            out_max_uniquelen
            in_max_uniquelen
            out_min_uniquelen
            in_min_uniquelen
        '''
        try:
            outgoing_uniquelens = outgoingPackets['frame.len'].unique()
        except:
            l.exception('__extractUniqueLen, outgoing_uniquelens')
            outgoing_uniquelens = np.array([])
        try:
            incoming_uniquelens = incomingPackets['frame.len'].unique()
        except:
            l.exception('__extractUniqueLen, incoming_uniquelens')
            incoming_uniquelens = np.array([])
        
        featureDict['out_mean_uniquelen'] = 0
        featureDict['out_median_uniquelen'] = 0
        featureDict['out_10per_uniquelen'] = 0
        featureDict['out_25per_uniquelen'] = 0
        featureDict['out_75per_uniquelen'] = 0
        featureDict['out_90per_uniquelen'] = 0
        featureDict['out_std_uniquelen'] = 0
        featureDict['out_len_uniquelen'] = 0
        featureDict['out_max_uniquelen'] = 0
        featureDict['out_min_uniquelen'] = 0
        
        featureDict['in_mean_uniquelen'] = 0
        featureDict['in_median_uniquelen'] = 0
        featureDict['in_10per_uniquelen'] = 0
        featureDict['in_25per_uniquelen'] = 0
        featureDict['in_75per_uniquelen'] = 0
        featureDict['in_90per_uniquelen'] = 0
        featureDict['in_std_uniquelen'] = 0
        featureDict['in_len_uniquelen'] = 0
        featureDict['in_max_uniquelen'] = 0
        featureDict['in_min_uniquelen'] = 0

        try:
            if outgoing_uniquelens.size > 0:
                featureDict['out_mean_uniquelen'] = np.mean(outgoing_uniquelens)
                featureDict['out_median_uniquelen'] = np.median(outgoing_uniquelens)
                featureDict['out_10per_uniquelen'] = np.percentile(outgoing_uniquelens, 10)
                featureDict['out_25per_uniquelen'] = np.percentile(outgoing_uniquelens, 25)
                featureDict['out_75per_uniquelen'] = np.percentile(outgoing_uniquelens, 75)
                featureDict['out_90per_uniquelen'] = np.percentile(outgoing_uniquelens, 90)
                featureDict['out_std_uniquelen'] = np.std(outgoing_uniquelens)
                featureDict['out_len_uniquelen'] = outgoing_uniquelens.size
                featureDict['out_max_uniquelen'] = np.max(outgoing_uniquelens)
                featureDict['out_min_uniquelen'] = np.min(outgoing_uniquelens)

        except:
            l.exception('__extractUniqueLen, compute out uniquelen features')
            raise

        try:
            if incoming_uniquelens.size > 0:
                featureDict['in_mean_uniquelen'] = np.mean(incoming_uniquelens)
                featureDict['in_median_uniquelen'] = np.median(incoming_uniquelens)
                featureDict['in_10per_uniquelen'] = np.percentile(incoming_uniquelens, 10)
                featureDict['in_25per_uniquelen'] = np.percentile(incoming_uniquelens, 25)
                featureDict['in_75per_uniquelen'] = np.percentile(incoming_uniquelens, 75)
                featureDict['in_90per_uniquelen'] = np.percentile(incoming_uniquelens, 90)
                featureDict['in_std_uniquelen'] = np.std(incoming_uniquelens)
                featureDict['in_len_uniquelen'] = incoming_uniquelens.size
                featureDict['in_max_uniquelen'] = np.max(incoming_uniquelens)
                featureDict['in_min_uniquelen'] = np.min(incoming_uniquelens)

        except:
            l.exception('__extractUniqueLen, compute in uniquelen features')
            raise

        return

    def __extractLen(self, allPackets, outgoingPackets, incomingPackets, featureDict:dict) -> None:
        '''
        FEATURES:
            out_mean_len
            in_mean_len
            out_median_len
            in_median_len
            out_10per_len
            in_10per_len
            out_25per_len
            in_25per_len
            out_75per_len
            in_75per_len
            out_90per_len
            in_90per_len
            out_std_len
            in_std_len
            out_len_len
            in_len_len
            out_max_len
            in_max_len
            out_min_len
            in_min_len
        '''
        try:
            outgoing_lens = outgoingPackets['frame.len'].values
        except:
            l.exception('__extractLen, outgoing_lens')
            outgoing_lens = np.array([])
        try:
            incoming_lens = incomingPackets['frame.len'].values
        except:
            l.exception('__extractLen, incoming_lens')
            incoming_lens = np.array([])
        
        featureDict['out_mean_len'] = 0
        featureDict['out_median_len'] = 0
        featureDict['out_10per_len'] = 0
        featureDict['out_25per_len'] = 0
        featureDict['out_75per_len'] = 0
        featureDict['out_90per_len'] = 0
        featureDict['out_std_len'] = 0
        featureDict['out_len_len'] = 0
        featureDict['out_max_len'] = 0
        featureDict['out_min_len'] = 0
        
        featureDict['in_mean_len'] = 0
        featureDict['in_median_len'] = 0
        featureDict['in_10per_len'] = 0
        featureDict['in_25per_len'] = 0
        featureDict['in_75per_len'] = 0
        featureDict['in_90per_len'] = 0
        featureDict['in_std_len'] = 0
        featureDict['in_len_len'] = 0
        featureDict['in_max_len'] = 0
        featureDict['in_min_len'] = 0

        try:
            if outgoing_lens.size > 0:
                featureDict['out_mean_len'] = np.mean(outgoing_lens)
                featureDict['out_median_len'] = np.median(outgoing_lens)
                featureDict['out_10per_len'] = np.percentile(outgoing_lens, 10)
                featureDict['out_25per_len'] = np.percentile(outgoing_lens, 25)
                featureDict['out_75per_len'] = np.percentile(outgoing_lens, 75)
                featureDict['out_90per_len'] = np.percentile(outgoing_lens, 90)
                featureDict['out_std_len'] = np.std(outgoing_lens)
                featureDict['out_len_len'] = outgoing_lens.size
                featureDict['out_max_len'] = np.max(outgoing_lens)
                featureDict['out_min_len'] = np.min(outgoing_lens)

        except:
            l.exception('__extractLen, compute out len features')
            raise

        try:
            if incoming_lens.size > 0:
                featureDict['in_mean_len'] = np.mean(incoming_lens)
                featureDict['in_median_len'] = np.median(incoming_lens)
                featureDict['in_10per_len'] = np.percentile(incoming_lens, 10)
                featureDict['in_25per_len'] = np.percentile(incoming_lens, 25)
                featureDict['in_75per_len'] = np.percentile(incoming_lens, 75)
                featureDict['in_90per_len'] = np.percentile(incoming_lens, 90)
                featureDict['in_std_len'] = np.std(incoming_lens)
                featureDict['in_len_len'] = incoming_lens.size
                featureDict['in_max_len'] = np.max(incoming_lens)
                featureDict['in_min_len'] = np.min(incoming_lens)

        except Exception as e:
            l.exception('__extractLen, compute in len features')
            raise

        return

    def __extractPacketPercentage(self, allPackets:pd.DataFrame, outgoingPackets:pd.DataFrame, incomingPackets:pd.DataFrame, featureDict:dict):
        '''
        FEATURES: 
            out_percentage
            in_percentage
        '''
        try:
            allPacketsCount = allPackets.shape[0]
            outPacketsCount = outgoingPackets.shape[0]
        except:
            l.exception('__extractPacketPercentage, computing counts')

        try:
            if allPacketsCount > 0:
                out_percentage = outPacketsCount / allPacketsCount
                in_percentage = 1 - out_percentage
            else:
                out_percentage = 0
                in_percentage = 0
       
        except:
            l.exception('__extractPacketPercentage, computing percentages')
            out_percentage = np.nan
            in_percentage = np.nan

        featureDict['out_percentage'] = out_percentage
        featureDict['in_percentage'] = in_percentage
        return

    def __extractTCPFlags(self, allPackets, outgoingPackets, incomingPackets, featureDict):
        '''
        FEATURES: 
            out_tcpack_percentage
            out_tcpsyn_percentage
            out_tcpfin_percentage
            out_tcprst_percentage
            out_tcppsh_percentage
            out_tcpurg_percentage
            in_tcpack_percentage
            in_tcpsyn_percentage
            in_tcpfin_percentage
            in_tcprst_percentage
            in_tcppsh_percentage
            in_tcpurg_percentage

        '''
        featureDict['out_tcpack_percentage'] = np.nan
        featureDict['out_tcpsyn_percentage'] = np.nan
        featureDict['out_tcpfin_percentage'] = np.nan
        featureDict['out_tcprst_percentage'] = np.nan
        featureDict['out_tcppsh_percentage'] = np.nan
        featureDict['out_tcpurg_percentage'] = np.nan
        
        featureDict['in_tcpack_percentage'] = np.nan
        featureDict['in_tcpsyn_percentage'] = np.nan
        featureDict['in_tcpfin_percentage'] = np.nan
        featureDict['in_tcprst_percentage'] = np.nan
        featureDict['in_tcppsh_percentage'] = np.nan
        featureDict['in_tcpurg_percentage'] = np.nan

        try:
            out_ackflagSum = outgoingPackets['tcp.flags.ack'].sum()
            out_synflagSum = outgoingPackets['tcp.flags.syn'].sum()
            out_finflagSum = outgoingPackets['tcp.flags.fin'].sum()
            out_rstflagSum = outgoingPackets['tcp.flags.reset'].sum()
            out_pshflagSum = outgoingPackets['tcp.flags.push'].sum()
            out_urgflagSum = outgoingPackets['tcp.flags.urg'].sum()
            
            totalSum = out_ackflagSum + out_synflagSum + out_finflagSum + out_rstflagSum + out_pshflagSum + out_urgflagSum
        
            if totalSum > 0:
                featureDict['out_tcpack_percentage'] = out_ackflagSum / totalSum
                featureDict['out_tcpsyn_percentage'] = out_synflagSum / totalSum
                featureDict['out_tcpfin_percentage'] = out_finflagSum / totalSum
                featureDict['out_tcprst_percentage'] = out_rstflagSum / totalSum
                featureDict['out_tcppsh_percentage'] = out_pshflagSum / totalSum
                featureDict['out_tcpurg_percentage'] = out_urgflagSum / totalSum

        except:
            l.exception('__extractTCPFlags, out')
        
        try:
            in_ackflagSum = incomingPackets['tcp.flags.ack'].sum()
            in_synflagSum = incomingPackets['tcp.flags.syn'].sum()
            in_finflagSum = incomingPackets['tcp.flags.fin'].sum()
            in_rstflagSum = incomingPackets['tcp.flags.reset'].sum()
            in_pshflagSum = incomingPackets['tcp.flags.push'].sum()
            in_urgflagSum = incomingPackets['tcp.flags.urg'].sum()
            
            totalSum = in_ackflagSum + in_synflagSum + in_finflagSum + in_rstflagSum + in_pshflagSum + in_urgflagSum
            
            if totalSum > 0:
                featureDict['in_tcpack_percentage'] = in_ackflagSum / totalSum
                featureDict['in_tcpsyn_percentage'] = in_synflagSum / totalSum
                featureDict['in_tcpfin_percentage'] = in_finflagSum / totalSum
                featureDict['in_tcprst_percentage'] = in_rstflagSum / totalSum
                featureDict['in_tcppsh_percentage'] = in_pshflagSum / totalSum
                featureDict['in_tcpurg_percentage'] = in_urgflagSum / totalSum

        except:
            l.exception('__extractTCPFlags, in')
        
        return

    def __extractProtocols(self, allPackets, outgoingPackets, incomingPackets, featureDict):
        '''
        FEATURES
            out_tcp_percentage
            in_tcp_percentage
            out_udp_percentage
            in_udp_percentage
            out_dns_percentage
            in_dns_percentage
            out_icmp_percentage
            in_icmp_percentage
        '''
        featureDict['out_tcp_percentage'] = np.nan
        featureDict['in_tcp_percentage'] = np.nan
        featureDict['out_udp_percentage'] = np.nan
        featureDict['in_udp_percentage'] = np.nan
        featureDict['out_dns_percentage'] = np.nan
        featureDict['in_dns_percentage'] = np.nan
        featureDict['out_icmp_percentage'] = np.nan
        featureDict['in_icmp_percentage'] = np.nan

        totalOutgoingPackets = outgoingPackets.shape[0]
        totalIncomingPackets = incomingPackets.shape[0]

        if totalOutgoingPackets > 0:
            featureDict['out_tcp_percentage'] = (outgoingPackets['ip.proto'] == self.__protoTCP).sum() / totalOutgoingPackets
            featureDict['out_udp_percentage'] = (outgoingPackets['ip.proto'] == self.__protoUDP).sum() / totalOutgoingPackets
            featureDict['out_dns_percentage'] = (outgoingPackets['_ws.col.Protocol'] == 'DNS').sum() / totalOutgoingPackets
            featureDict['out_icmp_percentage'] = (outgoingPackets['ip.proto'] == self.__protoICMP).sum() / totalOutgoingPackets

        if totalIncomingPackets > 0:
            featureDict['in_tcp_percentage'] = (incomingPackets['ip.proto'] == self.__protoTCP).sum() / totalIncomingPackets
            featureDict['in_udp_percentage'] = (incomingPackets['ip.proto'] == self.__protoUDP).sum() / totalIncomingPackets
            featureDict['in_dns_percentage'] = (incomingPackets['_ws.col.Protocol'] == 'DNS').sum() / totalIncomingPackets
            featureDict['in_icmp_percentage'] = (incomingPackets['ip.proto'] == self.__protoICMP).sum() / totalIncomingPackets

        return

    # def __extractUniqueProtocols(self, allPackets, outgoingPackets, incomingPackets):
    #     # TODO: Remove
    #     '''
    #     FEATURES
    #         out_numuniqueprotocol
    #         in_numuniqueprotocol
    #     '''
    #     try:
    #         out_numuniqueprotocol = outgoingPackets['Protocol'].nunique()
    #     except:
    #         out_numuniqueprotocol = 0
    #     try:
    #         in_numuniqueprotocol = incomingPackets['Protocol'].nunique()
    #     except:
    #         in_numuniqueprotocol = 0

    #     return [
    #         out_numuniqueprotocol,
    #         in_numuniqueprotocol
    #     ]
    def __extractHostNameIP(self, allPackets, outgoingPackets, incomingPackets, featureDict):
        '''
        FEATURES
            unique_ip_extcount
            unique_ip_3octet_extcount
            unique_hostname_extcount
            unique_hostname_tldplus1_extcount
            ratio_extport443_extcount
        '''
        try:
            num_unique_ip = allPackets['ip'].nunique()
        except:
            l.exception('__extractHostNameIP, num_unique_ip_')
            num_unique_ip = 0
        try:
            num_unique_ip_3octet = allPackets['ip'].apply(self.getIPOctet).nunique()
        except:
            l.exception('__extractHostNameIP, num_unique_ip_3octet')
            num_unique_ip_3octet = 0
        try:
            num_unique_hostname = allPackets['hostname'].nunique()
        except:
            l.exception('__extractHostNameIP, num_unique_hostname')
            num_unique_hostname = 0
        try:
            num_unique_hostname_tldplus1 = allPackets['hostname'].apply(self.getTldPlus).nunique()
        except:
            l.exception('__extractHostNameIP, num_unique_hostname_tldplus1')
            num_unique_hostname_tldplus1 = 0

        try:
            unique_extport_extcount = allPackets['ext.port'].nunique()
        except:
            l.exception('__extractHostNameIP, unique_extport_extcount')
            unique_extport_extcount = 0

        try:
            allPacketsCount = allPackets.shape[0]
            if allPacketsCount > 0:
                extPort443Count = (allPackets['ext.port'] == 443).sum()
                ratio_extport443_extcount = extPort443Count / allPacketsCount
            else:
                ratio_extport443_extcount = 0
        except:
            l.exception('__extractHostNameIP, ratio_extport443_extcount')
            ratio_extport443_extcount = 0

        featureDict['unique_ip_extcount'] = num_unique_ip
        featureDict['unique_ip_3octet_extcount'] = num_unique_ip_3octet
        featureDict['unique_hostname_extcount'] = num_unique_hostname
        featureDict['unique_hostname_tldplus1_extcount'] = num_unique_hostname_tldplus1
        featureDict['unique_extport_extcount'] = unique_extport_extcount
        featureDict['ratio_extport443_extcount'] = ratio_extport443_extcount
        
        return

    def __extractInterPacketDelay(self, allPackets, outgoingPackets, incomingPackets, featureDict):
        '''
        FEATURES
            out_mean_interpktdelay          
            out_median_interpktdelay       
            out_10per_interpktdelay   
            out_25per_interpktdelay
            out_75per_interpktdelay
            out_90per_interpktdelay
            out_std_interpktdelay
            out_max_interpktdelay
            out_min_interpktdelay
            in_mean_interpktdelay          
            in_median_interpktdelay       
            in_10per_interpktdelay   
            in_25per_interpktdelay
            in_75per_interpktdelay
            in_90per_interpktdelay
            in_std_interpktdelay
            in_max_interpktdelay
            in_min_interpktdelay
        '''
        try:
            out_timestamps = outgoingPackets['frame.time_epoch'].values
            out_interpktdelays = out_timestamps[1:] - out_timestamps[:-1]
        except:
            l.exception('__extractInterPacketDelay, out')
            out_interpktdelays = np.array([])

        try:
            in_timestamps = incomingPackets['frame.time_epoch'].values
            in_interpktdelays = in_timestamps[1:] - in_timestamps[:-1]
        except:
            l.exception('__extractInterPacketDelay, in')
            in_interpktdelays = np.array([])
        
        featureDict['out_mean_interpktdelay'] = 0
        featureDict['out_median_interpktdelay'] = 0
        featureDict['out_10per_interpktdelay'] = 0
        featureDict['out_25per_interpktdelay'] = 0
        featureDict['out_75per_interpktdelay'] = 0
        featureDict['out_90per_interpktdelay'] = 0
        featureDict['out_std_interpktdelay'] = 0
        featureDict['out_max_interpktdelay'] = 0
        featureDict['out_min_interpktdelay'] = 0
        
        featureDict['in_mean_interpktdelay'] = 0
        featureDict['in_median_interpktdelay'] = 0
        featureDict['in_10per_interpktdelay'] = 0
        featureDict['in_25per_interpktdelay'] = 0
        featureDict['in_75per_interpktdelay'] = 0
        featureDict['in_90per_interpktdelay'] = 0
        featureDict['in_std_interpktdelay'] = 0
        featureDict['in_max_interpktdelay'] = 0
        featureDict['in_min_interpktdelay'] = 0

        if out_interpktdelays.size > 0:
            featureDict['out_mean_interpktdelay'] = np.mean(out_interpktdelays)
            featureDict['out_median_interpktdelay'] = np.median(out_interpktdelays)
            featureDict['out_10per_interpktdelay'] = np.percentile(out_interpktdelays, 10)
            featureDict['out_25per_interpktdelay'] = np.percentile(out_interpktdelays, 25)
            featureDict['out_75per_interpktdelay'] = np.percentile(out_interpktdelays, 75)
            featureDict['out_90per_interpktdelay'] = np.percentile(out_interpktdelays, 90)
            featureDict['out_std_interpktdelay'] = np.std(out_interpktdelays)
            featureDict['out_max_interpktdelay'] = np.max(out_interpktdelays)
            featureDict['out_min_interpktdelay'] = np.min(out_interpktdelays)
       
        if in_interpktdelays.size > 0:
            featureDict['in_mean_interpktdelay'] = np.mean(in_interpktdelays)
            featureDict['in_median_interpktdelay'] = np.median(in_interpktdelays)
            featureDict['in_10per_interpktdelay'] = np.percentile(in_interpktdelays, 10)
            featureDict['in_25per_interpktdelay'] = np.percentile(in_interpktdelays, 25)
            featureDict['in_75per_interpktdelay'] = np.percentile(in_interpktdelays, 75)
            featureDict['in_90per_interpktdelay'] = np.percentile(in_interpktdelays, 90)
            featureDict['in_std_interpktdelay'] = np.std(in_interpktdelays)
            featureDict['in_max_interpktdelay'] = np.max(in_interpktdelays)
            featureDict['in_min_interpktdelay'] = np.min(in_interpktdelays)

        return

    # def __extractProtocolBasedInterPacketDelay(self, allPackets, outgoingPackets, incomingPackets):
    #     # TODO: Remove UDP, NTP, TLS
    #     # TODO: Check what this is doing?
    #     '''
    #     FEATURES
    #     TLS IN/OUT 
    #     TCP IN/OUT
    #     DNS IN/OUT
    #     UDP IN/OUT
    #     NTP IN/OUT
    #     '''
    #     returnArray = []
        
    #     tls_in_out = self.extractProtocolBasedInterPacketDelayHelper(allPackets, outgoingPackets, incomingPackets, protocols=['TLSv1', 'TLSv1.2'], outgoing=True, incoming=True)
    #     tcp_in_out = self.extractProtocolBasedInterPacketDelayHelper(allPackets, outgoingPackets, incomingPackets, protocols=['TCP'], outgoing=True, incoming=True)
    #     dns_in_out = self.extractProtocolBasedInterPacketDelayHelper(allPackets, outgoingPackets, incomingPackets, protocols=['DNS'], outgoing=True, incoming=True)
    #     udp_in_out = self.extractProtocolBasedInterPacketDelayHelper(allPackets, outgoingPackets, incomingPackets, protocols=['UDP'], outgoing=True, incoming=True)
    #     ntp_in_out = self.extractProtocolBasedInterPacketDelayHelper(allPackets, outgoingPackets, incomingPackets, protocols=['NTP'], outgoing=True, incoming=True)

    #     returnArray.extend(tls_in_out)
    #     returnArray.extend(tcp_in_out)
    #     returnArray.extend(dns_in_out)
    #     returnArray.extend(udp_in_out)
    #     returnArray.extend(ntp_in_out)

    #     return returnArray
    def __extractInterBurstDelay(self, allBursts, outgoingBursts, incomingBursts, featureDict):
        '''
        FEATURES
            out_mean_interburstdelay 
            in_mean_interburstdelay
            out_median_interburstdelay
            in_median_interburstdelay
            out_10per_interburstdelay
            in_10per_interburstdelay
            out_25per_interburstdelay
            in_25per_interburstdelay
            out_75per_interburstdelay
            in_75per_interburstdelay
            out_90per_interburstdelay
            in_90per_interburstdelay
            out_std_interburstdelay
            in_std_interburstdelay
            out_max_interburstdelay 
            in_max_interburstdelay
            out_min_interburstdelay 
            in_min_interburstdelay
        '''
        try:
            out_startTime = outgoingBursts['start_time'].values[1:]
            out_endTime = outgoingBursts['end_time'].values[:-1]
            out_interburstdelays = out_startTime - out_endTime
            # out_interburstdelays = self.__convertTimeStamp(out_interburstdelays)
        except:
            l.exception('__extractInterBurstDelay, out_interburstdelays')
            out_interburstdelays = np.array([])
        try:
            in_startTime = incomingBursts['start_time'].values[1:]
            in_endTime = incomingBursts['end_time'].values[:-1]
            in_interburstdelays = in_startTime - in_endTime
            # in_interburstdelays = self.__convertTimeStamp(in_interburstdelays)
        except:
            l.exception('__extractInterBurstDelay, in_interburstdelays')
            in_interburstdelays = np.array([])

        featureDict['out_mean_interburstdelay'] = 0
        featureDict['out_median_interburstdelay'] = 0
        featureDict['out_10per_interburstdelay'] = 0
        featureDict['out_25per_interburstdelay'] = 0
        featureDict['out_75per_interburstdelay'] = 0
        featureDict['out_90per_interburstdelay'] = 0
        featureDict['out_std_interburstdelay'] = 0
        featureDict['out_max_interburstdelay'] = 0
        featureDict['out_min_interburstdelay'] = 0
        
        featureDict['in_mean_interburstdelay'] = 0
        featureDict['in_median_interburstdelay'] = 0
        featureDict['in_10per_interburstdelay'] = 0
        featureDict['in_25per_interburstdelay'] = 0
        featureDict['in_75per_interburstdelay'] = 0
        featureDict['in_90per_interburstdelay'] = 0
        featureDict['in_std_interburstdelay'] = 0
        featureDict['in_max_interburstdelay'] = 0
        featureDict['in_min_interburstdelay'] = 0

        if out_interburstdelays.size:
            featureDict['out_mean_interburstdelay'] = np.mean(out_interburstdelays)
            featureDict['out_median_interburstdelay'] = np.median(out_interburstdelays)
            featureDict['out_10per_interburstdelay'] = np.percentile(out_interburstdelays, 10)
            featureDict['out_25per_interburstdelay'] = np.percentile(out_interburstdelays, 25)
            featureDict['out_75per_interburstdelay'] = np.percentile(out_interburstdelays, 75)
            featureDict['out_90per_interburstdelay'] = np.percentile(out_interburstdelays, 90)
            featureDict['out_std_interburstdelay'] = np.std(out_interburstdelays)
            featureDict['out_max_interburstdelay'] = np.max(out_interburstdelays)
            featureDict['out_min_interburstdelay'] = np.min(out_interburstdelays)

        if in_interburstdelays.size:
            featureDict['in_mean_interburstdelay'] = np.mean(in_interburstdelays)
            featureDict['in_median_interburstdelay'] = np.median(in_interburstdelays)
            featureDict['in_10per_interburstdelay'] = np.percentile(in_interburstdelays, 10)
            featureDict['in_25per_interburstdelay'] = np.percentile(in_interburstdelays, 25)
            featureDict['in_75per_interburstdelay'] = np.percentile(in_interburstdelays, 75)
            featureDict['in_90per_interburstdelay'] = np.percentile(in_interburstdelays, 90)
            featureDict['in_std_interburstdelay'] = np.std(in_interburstdelays)
            featureDict['in_max_interburstdelay'] = np.max(in_interburstdelays)
            featureDict['in_min_interburstdelay'] = np.min(in_interburstdelays)
     
        return

    # def __extractInterFlowDelay(self, allFlows, outgoingFlows, incomingFlows, featureDict):
    #     '''
    #     FEATURES
    #         out_mean_interflowdelay 
    #         in_mean_interflowdelay
    #         out_median_interflowdelay
    #         in_median_interflowdelay
    #         out_10per_interflowdelay
    #         in_10per_interflowdelay
    #         out_25per_interflowdelay
    #         in_25per_interflowdelay
    #         out_75per_interflowdelay
    #         in_75per_interflowdelay
    #         out_90per_interflowdelay
    #         in_90per_interflowdelay
    #         out_std_interflowdelay
    #         in_std_interflowdelay
    #         out_max_interflowdelay 
    #         in_max_interflowdelay
    #         out_min_interflowdelay 
    #         in_min_interflowdelay
    #     '''
    #     try:
    #         out_startTime = outgoingFlows['start_time'].values[1:]
    #         out_endTime = outgoingFlows['end_time'].values[:-1]
    #         out_interflowdelays = out_startTime - out_endTime
    #         # out_interflowdelays = self.__convertTimeStamp(out_interflowdelays)
    #     except:
    #         l.exception('__extractInterBurstDelay, out_interflowdelays')
    #         out_interflowdelays = np.array([])
    #     try:
    #         in_startTime = incomingFlows['start_time'].values[1:]
    #         in_endTime = incomingFlows['end_time'].values[:-1]
    #         in_interflowdelays = in_startTime - in_endTime
    #         # in_interflowdelays = self.__convertTimeStamp(in_interflowdelays)
    #     except:
    #         l.exception('__extractInterBurstDelay, in_interflowdelays')
    #         in_interflowdelays = np.array([])

    #     featureDict['out_mean_interflowdelay'] = 0
    #     featureDict['out_median_interflowdelay'] = 0
    #     featureDict['out_10per_interflowdelay'] = 0
    #     featureDict['out_25per_interflowdelay'] = 0
    #     featureDict['out_75per_interflowdelay'] = 0
    #     featureDict['out_90per_interflowdelay'] = 0
    #     featureDict['out_std_interflowdelay'] = 0
    #     featureDict['out_max_interflowdelay'] = 0
    #     featureDict['out_min_interflowdelay'] = 0
        
    #     featureDict['in_mean_interflowdelay'] = 0
    #     featureDict['in_median_interflowdelay'] = 0
    #     featureDict['in_10per_interflowdelay'] = 0
    #     featureDict['in_25per_interflowdelay'] = 0
    #     featureDict['in_75per_interflowdelay'] = 0
    #     featureDict['in_90per_interflowdelay'] = 0
    #     featureDict['in_std_interflowdelay'] = 0
    #     featureDict['in_max_interflowdelay'] = 0
    #     featureDict['in_min_interflowdelay'] = 0

    #     if out_interflowdelays.size:
    #         featureDict['out_mean_interflowdelay'] = np.mean(out_interflowdelays)
    #         featureDict['out_median_interflowdelay'] = np.median(out_interflowdelays)
    #         featureDict['out_10per_interflowdelay'] = np.percentile(out_interflowdelays, 10)
    #         featureDict['out_25per_interflowdelay'] = np.percentile(out_interflowdelays, 25)
    #         featureDict['out_75per_interflowdelay'] = np.percentile(out_interflowdelays, 75)
    #         featureDict['out_90per_interflowdelay'] = np.percentile(out_interflowdelays, 90)
    #         featureDict['out_std_interflowdelay'] = np.std(out_interflowdelays)
    #         featureDict['out_max_interflowdelay'] = np.max(out_interflowdelays)
    #         featureDict['out_min_interflowdelay'] = np.min(out_interflowdelays)

    #     if in_interflowdelays.size:
    #         featureDict['in_mean_interflowdelay'] = np.mean(in_interflowdelays)
    #         featureDict['in_median_interflowdelay'] = np.median(in_interflowdelays)
    #         featureDict['in_10per_interflowdelay'] = np.percentile(in_interflowdelays, 10)
    #         featureDict['in_25per_interflowdelay'] = np.percentile(in_interflowdelays, 25)
    #         featureDict['in_75per_interflowdelay'] = np.percentile(in_interflowdelays, 75)
    #         featureDict['in_90per_interflowdelay'] = np.percentile(in_interflowdelays, 90)
    #         featureDict['in_std_interflowdelay'] = np.std(in_interflowdelays)
    #         featureDict['in_max_interflowdelay'] = np.max(in_interflowdelays)
    #         featureDict['in_min_interflowdelay'] = np.min(in_interflowdelays)
     
    #     return

    def __extractBurstNumPackets(self, allBursts, outgoingBursts, incomingBursts, featureDict):
        '''
        FEATURES
        out_mean_burstnumpkts
        in_mean_burstnumpkts
        out_median_burstnumpkts
        in_median_burstnumpkts
        out_10per_burstnumpkts
        in_10per_burstnumpkts
        out_25per_burstnumpkts
        in_25per_burstnumpkts
        out_75per_burstnumpkts
        in_75per_burstnumpkts
        out_90per_burstnumpkts
        in_90per_burstnumpkts
        out_std_burstnumpkts
        in_std_burstnumpkts
        out_max_burstnumpkts
        in_max_burstnumpkts
        out_min_burstnumpkts
        in_min_burstnumpkts
        '''
        try:
            out_burstnumpkts = outgoingBursts['n_packets'].values
        except:
            l.exception('__extractBurstNumPackets, out_burstnumpkts')
            out_burstnumpkts = np.array([])
        try:
            in_burstnumpkts = incomingBursts['n_packets'].values
        except:
            l.exception('__extractBurstNumPackets, in_burstnumpkts')
            in_burstnumpkts = np.array([])

        featureDict['out_mean_burstnumpkts'] = 0 
        featureDict['out_median_burstnumpkts'] = 0
        featureDict['out_10per_burstnumpkts'] = 0
        featureDict['out_25per_burstnumpkts'] = 0
        featureDict['out_75per_burstnumpkts'] = 0
        featureDict['out_90per_burstnumpkts'] = 0
        featureDict['out_std_burstnumpkts'] = 0
        featureDict['out_max_burstnumpkts'] = 0
        featureDict['out_min_burstnumpkts'] = 0
        
        featureDict['in_mean_burstnumpkts'] = 0
        featureDict['in_median_burstnumpkts'] = 0
        featureDict['in_10per_burstnumpkts'] = 0
        featureDict['in_25per_burstnumpkts'] = 0
        featureDict['in_75per_burstnumpkts'] = 0
        featureDict['in_90per_burstnumpkts'] = 0
        featureDict['in_std_burstnumpkts'] = 0
        featureDict['in_max_burstnumpkts'] = 0
        featureDict['in_min_burstnumpkts'] = 0
        if out_burstnumpkts.size:
            featureDict['out_mean_burstnumpkts'] = np.mean(out_burstnumpkts)
            featureDict['out_median_burstnumpkts'] = np.median(out_burstnumpkts)
            featureDict['out_10per_burstnumpkts'] = np.percentile(out_burstnumpkts, 10)
            featureDict['out_25per_burstnumpkts'] = np.percentile(out_burstnumpkts, 25)
            featureDict['out_75per_burstnumpkts'] = np.percentile(out_burstnumpkts, 75)
            featureDict['out_90per_burstnumpkts'] = np.percentile(out_burstnumpkts, 90)
            featureDict['out_std_burstnumpkts'] = np.std(out_burstnumpkts)
            featureDict['out_max_burstnumpkts'] = np.max(out_burstnumpkts)
            featureDict['out_min_burstnumpkts'] = np.min(out_burstnumpkts)
        
        if in_burstnumpkts.size:
            featureDict['in_mean_burstnumpkts'] = np.mean(in_burstnumpkts)
            featureDict['in_median_burstnumpkts'] = np.median(in_burstnumpkts)
            featureDict['in_10per_burstnumpkts'] = np.percentile(in_burstnumpkts, 10)
            featureDict['in_25per_burstnumpkts'] = np.percentile(in_burstnumpkts, 25)
            featureDict['in_75per_burstnumpkts'] = np.percentile(in_burstnumpkts, 75)
            featureDict['in_90per_burstnumpkts'] = np.percentile(in_burstnumpkts, 90)
            featureDict['in_std_burstnumpkts'] = np.std(in_burstnumpkts)
            featureDict['in_max_burstnumpkts'] = np.max(in_burstnumpkts)
            featureDict['in_min_burstnumpkts'] = np.min(in_burstnumpkts)

        return

    def __extractFlowNumPackets(self, allFlows, outgoingFlows, incomingFlows, featureDict):
        '''
        FEATURES
        out_mean_flownumpkts
        in_mean_flownumpkts
        out_median_flownumpkts
        in_median_flownumpkts
        out_10per_flownumpkts
        in_10per_flownumpkts
        out_25per_flownumpkts
        in_25per_flownumpkts
        out_75per_flownumpkts
        in_75per_flownumpkts
        out_90per_flownumpkts
        in_90per_flownumpkts
        out_std_flownumpkts
        in_std_flownumpkts
        out_max_flownumpkts
        in_max_flownumpkts
        out_min_flownumpkts
        in_min_flownumpkts
        '''
        try:
            out_flownumpkts = outgoingFlows['n_packets'].values
        except:
            l.exception('__extractBurstNumPackets, out_flownumpkts')
            out_flownumpkts = np.array([])
        try:
            in_flownumpkts = incomingFlows['n_packets'].values
        except:
            l.exception('__extractBurstNumPackets, in_flownumpkts')
            in_flownumpkts = np.array([])

        featureDict['out_mean_flownumpkts'] = 0 
        featureDict['out_median_flownumpkts'] = 0
        featureDict['out_10per_flownumpkts'] = 0
        featureDict['out_25per_flownumpkts'] = 0
        featureDict['out_75per_flownumpkts'] = 0
        featureDict['out_90per_flownumpkts'] = 0
        featureDict['out_std_flownumpkts'] = 0
        featureDict['out_max_flownumpkts'] = 0
        featureDict['out_min_flownumpkts'] = 0
        
        featureDict['in_mean_flownumpkts'] = 0
        featureDict['in_median_flownumpkts'] = 0
        featureDict['in_10per_flownumpkts'] = 0
        featureDict['in_25per_flownumpkts'] = 0
        featureDict['in_75per_flownumpkts'] = 0
        featureDict['in_90per_flownumpkts'] = 0
        featureDict['in_std_flownumpkts'] = 0
        featureDict['in_max_flownumpkts'] = 0
        featureDict['in_min_flownumpkts'] = 0
        if out_flownumpkts.size:
            featureDict['out_mean_flownumpkts'] = np.mean(out_flownumpkts)
            featureDict['out_median_flownumpkts'] = np.median(out_flownumpkts)
            featureDict['out_10per_flownumpkts'] = np.percentile(out_flownumpkts, 10)
            featureDict['out_25per_flownumpkts'] = np.percentile(out_flownumpkts, 25)
            featureDict['out_75per_flownumpkts'] = np.percentile(out_flownumpkts, 75)
            featureDict['out_90per_flownumpkts'] = np.percentile(out_flownumpkts, 90)
            featureDict['out_std_flownumpkts'] = np.std(out_flownumpkts)
            featureDict['out_max_flownumpkts'] = np.max(out_flownumpkts)
            featureDict['out_min_flownumpkts'] = np.min(out_flownumpkts)
        
        if in_flownumpkts.size:
            featureDict['in_mean_flownumpkts'] = np.mean(in_flownumpkts)
            featureDict['in_median_flownumpkts'] = np.median(in_flownumpkts)
            featureDict['in_10per_flownumpkts'] = np.percentile(in_flownumpkts, 10)
            featureDict['in_25per_flownumpkts'] = np.percentile(in_flownumpkts, 25)
            featureDict['in_75per_flownumpkts'] = np.percentile(in_flownumpkts, 75)
            featureDict['in_90per_flownumpkts'] = np.percentile(in_flownumpkts, 90)
            featureDict['in_std_flownumpkts'] = np.std(in_flownumpkts)
            featureDict['in_max_flownumpkts'] = np.max(in_flownumpkts)
            featureDict['in_min_flownumpkts'] = np.min(in_flownumpkts)

        return

    def __extractBurstBytes(self, allBursts, outgoingBursts, incomingBursts, featureDict):
        '''
        FEATURES
        out_mean_burstbytes
        in_mean_burstbytes
        out_median_burstbytes
        in_median_burstbytes
        out_10per_burstbytes
        in_10per_burstbytes
        out_25per_burstbytes
        in_25per_burstbytes
        out_75per_burstbytes
        in_75per_burstbytes
        out_90per_burstbytes
        in_90per_burstbytes
        out_std_burstbytes
        in_std_burstbytes
        out_max_burstbytes
        in_max_burstbytes
        out_min_burstbytes
        in_min_burstbytes
        '''
        try:
            out_burstbytes = outgoingBursts['length'].values
        except:
            l.exception('__extractBurstBytes, out_burstbytes')
            out_burstbytes = np.array([])
        try:
            in_burstbytes = incomingBursts['length'].values
        except Exception as e:
            l.exception('__extractBurstBytes, in_burstbytes')
            in_burstbytes = np.array([])
        
        featureDict['out_mean_burstbytes'] = 0
        featureDict['out_median_burstbytes'] = 0
        featureDict['out_10per_burstbytes'] = 0
        featureDict['out_25per_burstbytes'] = 0
        featureDict['out_75per_burstbytes'] = 0
        featureDict['out_90per_burstbytes'] = 0
        featureDict['out_std_burstbytes'] = 0
        featureDict['out_max_burstbytes'] = 0
        featureDict['out_min_burstbytes'] = 0

        featureDict['in_mean_burstbytes'] = 0
        featureDict['in_median_burstbytes'] = 0
        featureDict['in_10per_burstbytes'] = 0
        featureDict['in_25per_burstbytes'] = 0
        featureDict['in_75per_burstbytes'] = 0
        featureDict['in_90per_burstbytes'] = 0
        featureDict['in_std_burstbytes'] = 0
        featureDict['in_max_burstbytes'] = 0
        featureDict['in_min_burstbytes'] = 0

        if out_burstbytes.size:
            featureDict['out_mean_burstbytes'] = np.mean(out_burstbytes)
            featureDict['out_median_burstbytes'] = np.median(out_burstbytes)
            featureDict['out_10per_burstbytes'] = np.percentile(out_burstbytes, 10)
            featureDict['out_25per_burstbytes'] = np.percentile(out_burstbytes, 25)
            featureDict['out_75per_burstbytes'] = np.percentile(out_burstbytes, 75)
            featureDict['out_90per_burstbytes'] = np.percentile(out_burstbytes, 90)
            featureDict['out_std_burstbytes'] = np.std(out_burstbytes)
            featureDict['out_max_burstbytes'] = np.max(out_burstbytes)
            featureDict['out_min_burstbytes'] = np.min(out_burstbytes)
        
        if in_burstbytes.size:
            featureDict['in_mean_burstbytes'] = np.mean(in_burstbytes)
            featureDict['in_median_burstbytes'] = np.median(in_burstbytes)
            featureDict['in_10per_burstbytes'] = np.percentile(in_burstbytes, 10)
            featureDict['in_25per_burstbytes'] = np.percentile(in_burstbytes, 25)
            featureDict['in_75per_burstbytes'] = np.percentile(in_burstbytes, 75)
            featureDict['in_90per_burstbytes'] = np.percentile(in_burstbytes, 90)
            featureDict['in_std_burstbytes'] = np.std(in_burstbytes)
            featureDict['in_max_burstbytes'] = np.max(in_burstbytes)
            featureDict['in_min_burstbytes'] = np.min(in_burstbytes)
                
        return

    def __extractFlowBytes(self, allFlows, outgoingFlows, incomingFlows, featureDict):
        '''
        FEATURES
        out_mean_flowbytes
        in_mean_flowbytes
        out_median_flowbytes
        in_median_flowbytes
        out_10per_flowbytes
        in_10per_flowbytes
        out_25per_flowbytes
        in_25per_flowbytes
        out_75per_flowbytes
        in_75per_flowbytes
        out_90per_flowbytes
        in_90per_flowbytes
        out_std_flowbytes
        in_std_flowbytes
        out_max_flowbytes
        in_max_flowbytes
        out_min_flowbytes
        in_min_flowbytes
        '''
        try:
            out_flowbytes = outgoingFlows['length'].values
        except:
            l.exception('__extractFlowBytes, out_flowbytes')
            out_flowbytes = np.array([])
        try:
            in_flowbytes = incomingFlows['length'].values
        except Exception as e:
            l.exception('__extractFlowBytes, in_flowbytes')
            in_flowbytes = np.array([])
        
        featureDict['out_mean_flowbytes'] = 0
        featureDict['out_median_flowbytes'] = 0
        featureDict['out_10per_flowbytes'] = 0
        featureDict['out_25per_flowbytes'] = 0
        featureDict['out_75per_flowbytes'] = 0
        featureDict['out_90per_flowbytes'] = 0
        featureDict['out_std_flowbytes'] = 0
        featureDict['out_max_flowbytes'] = 0
        featureDict['out_min_flowbytes'] = 0

        featureDict['in_mean_flowbytes'] = 0
        featureDict['in_median_flowbytes'] = 0
        featureDict['in_10per_flowbytes'] = 0
        featureDict['in_25per_flowbytes'] = 0
        featureDict['in_75per_flowbytes'] = 0
        featureDict['in_90per_flowbytes'] = 0
        featureDict['in_std_flowbytes'] = 0
        featureDict['in_max_flowbytes'] = 0
        featureDict['in_min_flowbytes'] = 0

        if out_flowbytes.size:
            featureDict['out_mean_flowbytes'] = np.mean(out_flowbytes)
            featureDict['out_median_flowbytes'] = np.median(out_flowbytes)
            featureDict['out_10per_flowbytes'] = np.percentile(out_flowbytes, 10)
            featureDict['out_25per_flowbytes'] = np.percentile(out_flowbytes, 25)
            featureDict['out_75per_flowbytes'] = np.percentile(out_flowbytes, 75)
            featureDict['out_90per_flowbytes'] = np.percentile(out_flowbytes, 90)
            featureDict['out_std_flowbytes'] = np.std(out_flowbytes)
            featureDict['out_max_flowbytes'] = np.max(out_flowbytes)
            featureDict['out_min_flowbytes'] = np.min(out_flowbytes)
        
        if in_flowbytes.size:
            featureDict['in_mean_flowbytes'] = np.mean(in_flowbytes)
            featureDict['in_median_flowbytes'] = np.median(in_flowbytes)
            featureDict['in_10per_flowbytes'] = np.percentile(in_flowbytes, 10)
            featureDict['in_25per_flowbytes'] = np.percentile(in_flowbytes, 25)
            featureDict['in_75per_flowbytes'] = np.percentile(in_flowbytes, 75)
            featureDict['in_90per_flowbytes'] = np.percentile(in_flowbytes, 90)
            featureDict['in_std_flowbytes'] = np.std(in_flowbytes)
            featureDict['in_max_flowbytes'] = np.max(in_flowbytes)
            featureDict['in_min_flowbytes'] = np.min(in_flowbytes)
                
        return

    def __extractBurstTime(self, allBursts, outgoingBursts, incomingBursts, featureDict):
        '''
        FEATURES
        out_mean_bursttime
        in_mean_bursttime
        out_median_bursttime
        in_median_bursttime
        out_10per_bursttime,
        in_10per_bursttime,
        out_25per_bursttime
        in_25per_bursttime
        out_75per_bursttime
        in_75per_bursttime
        out_90per_bursttime
        in_90per_bursttime
        out_std_bursttime
        in_std_bursttime
        out_max_bursttime
        in_max_bursttime
        out_min_bursttime
        in_min_bursttime
        '''
        try:
            out_bursttime = outgoingBursts['end_time'].values - outgoingBursts['start_time'].values
            # out_bursttime = self.__convertTimeStamp(out_bursttime)
        except:
            l.exception('__extractBurstTime, out_burstttime')
            out_bursttime = np.array([])
        try:
            in_bursttime = incomingBursts['end_time'].values - incomingBursts['start_time'].values
            # in_bursttime = self.__convertTimeStamp(in_bursttime)
        except:
            l.exception('__extractBurstTime, in_burstttime')
            in_bursttime = np.array([])
        
        featureDict['out_mean_bursttime'] = 0
        featureDict['out_median_bursttime'] = 0
        featureDict['out_10per_bursttime'] = 0
        featureDict['out_25per_bursttime'] = 0
        featureDict['out_75per_bursttime'] = 0
        featureDict['out_90per_bursttime'] = 0
        featureDict['out_std_bursttime'] = 0
        featureDict['out_max_bursttime'] = 0
        featureDict['out_min_bursttime'] = 0

        featureDict['in_mean_bursttime'] = 0
        featureDict['in_median_bursttime'] = 0
        featureDict['in_10per_bursttime'] = 0
        featureDict['in_25per_bursttime'] = 0
        featureDict['in_75per_bursttime'] = 0
        featureDict['in_90per_bursttime'] = 0
        featureDict['in_std_bursttime'] = 0
        featureDict['in_max_bursttime'] = 0
        featureDict['in_min_bursttime'] = 0

        if out_bursttime.size:
            featureDict['out_mean_bursttime'] = np.mean(out_bursttime)
            featureDict['out_median_bursttime'] = np.median(out_bursttime)
            featureDict['out_10per_bursttime'] = np.percentile(out_bursttime, 10)
            featureDict['out_25per_bursttime'] = np.percentile(out_bursttime, 25)
            featureDict['out_75per_bursttime'] = np.percentile(out_bursttime, 75)
            featureDict['out_90per_bursttime'] = np.percentile(out_bursttime, 90)
            featureDict['out_std_bursttime'] = np.std(out_bursttime)
            featureDict['out_max_bursttime'] = np.max(out_bursttime)
            featureDict['out_min_bursttime'] = np.min(out_bursttime)
        
        if in_bursttime.size:
            featureDict['in_mean_bursttime'] = np.mean(in_bursttime)
            featureDict['in_median_bursttime'] = np.median(in_bursttime)
            featureDict['in_10per_bursttime'] = np.percentile(in_bursttime, 10)
            featureDict['in_25per_bursttime'] = np.percentile(in_bursttime, 25)
            featureDict['in_75per_bursttime'] = np.percentile(in_bursttime, 75)
            featureDict['in_90per_bursttime'] = np.percentile(in_bursttime, 90)
            featureDict['in_std_bursttime'] = np.std(in_bursttime)
            featureDict['in_max_bursttime'] = np.max(in_bursttime)
            featureDict['in_min_bursttime'] = np.min(in_bursttime)
        return

    def __extractFlowTime(self, allFlows, outgoingFlows, incomingFlows, featureDict):
        '''
        FEATURES
        out_mean_flowtime
        in_mean_flowtime
        out_median_flowtime
        in_median_flowtime
        out_10per_flowtime,
        in_10per_flowtime,
        out_25per_flowtime
        in_25per_flowtime
        out_75per_flowtime
        in_75per_flowtime
        out_90per_flowtime
        in_90per_flowtime
        out_std_flowtime
        in_std_flowtime
        out_max_flowtime
        in_max_flowtime
        out_min_flowtime
        in_min_flowtime
        '''
        try:
            out_flowtime = outgoingFlows['end_time'].values - outgoingFlows['start_time'].values
            # out_flowtime = self.__convertTimeStamp(out_flowtime)
        except:
            l.exception('__extractFlowTime, out_flowtime')
            out_flowtime = np.array([])
        try:
            in_flowtime = incomingFlows['end_time'].values - incomingFlows['start_time'].values
            # in_flowtime = self.__convertTimeStamp(in_flowtime)
        except:
            l.exception('__extractFlowTime, in_flowtime')
            in_flowtime = np.array([])
        
        featureDict['out_mean_flowtime'] = 0
        featureDict['out_median_flowtime'] = 0
        featureDict['out_10per_flowtime'] = 0
        featureDict['out_25per_flowtime'] = 0
        featureDict['out_75per_flowtime'] = 0
        featureDict['out_90per_flowtime'] = 0
        featureDict['out_std_flowtime'] = 0
        featureDict['out_max_flowtime'] = 0
        featureDict['out_min_flowtime'] = 0

        featureDict['in_mean_flowtime'] = 0
        featureDict['in_median_flowtime'] = 0
        featureDict['in_10per_flowtime'] = 0
        featureDict['in_25per_flowtime'] = 0
        featureDict['in_75per_flowtime'] = 0
        featureDict['in_90per_flowtime'] = 0
        featureDict['in_std_flowtime'] = 0
        featureDict['in_max_flowtime'] = 0
        featureDict['in_min_flowtime'] = 0

        if out_flowtime.size:
            featureDict['out_mean_flowtime'] = np.mean(out_flowtime)
            featureDict['out_median_flowtime'] = np.median(out_flowtime)
            featureDict['out_10per_flowtime'] = np.percentile(out_flowtime, 10)
            featureDict['out_25per_flowtime'] = np.percentile(out_flowtime, 25)
            featureDict['out_75per_flowtime'] = np.percentile(out_flowtime, 75)
            featureDict['out_90per_flowtime'] = np.percentile(out_flowtime, 90)
            featureDict['out_std_flowtime'] = np.std(out_flowtime)
            featureDict['out_max_flowtime'] = np.max(out_flowtime)
            featureDict['out_min_flowtime'] = np.min(out_flowtime)
        
        if in_flowtime.size:
            featureDict['in_mean_flowtime'] = np.mean(in_flowtime)
            featureDict['in_median_flowtime'] = np.median(in_flowtime)
            featureDict['in_10per_flowtime'] = np.percentile(in_flowtime, 10)
            featureDict['in_25per_flowtime'] = np.percentile(in_flowtime, 25)
            featureDict['in_75per_flowtime'] = np.percentile(in_flowtime, 75)
            featureDict['in_90per_flowtime'] = np.percentile(in_flowtime, 90)
            featureDict['in_std_flowtime'] = np.std(in_flowtime)
            featureDict['in_max_flowtime'] = np.max(in_flowtime)
            featureDict['in_min_flowtime'] = np.min(in_flowtime)
        return

# Aggregation Functions    
        
    def extractAllFeatures(self, allPackets):
        # Init
        featureDict = {}
        incomingPackets = allPackets[allPackets['direction'] == 'in']
        outgoingPackets = allPackets[allPackets['direction'] == 'out']
        
        bursts = self.groupBurstPackets(allPackets)
        outgoingBursts = bursts[bursts['direction'] == 'out']
        incomingBursts = bursts[bursts['direction'] == 'in']

        flows = self.groupFlowPackets(allPackets)
        outgoingFlows = flows[flows['direction'] == 'out']
        incomingFlows = flows[flows['direction'] == 'in']
    
        # Extract Simple Features 
        self.__extractTotalPkts(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.__extractTotalBytes(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.__extractUniqueLen(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.__extractLen(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.__extractPacketPercentage(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.__extractTCPFlags(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.__extractProtocols(allPackets, outgoingPackets, incomingPackets, featureDict)
        # self.__extractUniqueProtocols(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.__extractHostNameIP(allPackets, outgoingPackets, incomingPackets, featureDict)
        # self.__extractUniqueSrcDstPorts(allPackets, outgoingPackets, incomingPackets, featureDict)
        # self.__extract80and443Features(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.__extractInterPacketDelay(allPackets, outgoingPackets, incomingPackets, featureDict)
        # self.__extractProtocolBasedInterPacketDelay(allPackets, outgoingPackets, incomingPackets, featureDict)
    
        # Extract Burst Features 
        self.__extractInterBurstDelay(bursts, outgoingBursts, incomingBursts, featureDict)
        self.__extractBurstNumPackets(bursts, outgoingBursts, incomingBursts, featureDict)
        self.__extractBurstBytes(bursts, outgoingBursts, incomingBursts, featureDict)
        self.__extractBurstTime(bursts, outgoingBursts, incomingBursts, featureDict)

        # Extract Flow Features 
        # self.__extractInterFlowDelay(flows, outgoingFlows, incomingFlows, featureDict)
        self.__extractFlowNumPackets(flows, outgoingFlows, incomingFlows, featureDict)
        self.__extractFlowBytes(flows, outgoingFlows, incomingFlows, featureDict)
        self.__extractFlowTime(flows, outgoingFlows, incomingFlows, featureDict)

        # Multi-Valued Features
        self.extractExternalPortCount(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.extractContactedHostName(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.extractContactedIP(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.extractProtocols(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.extractPacketSizes(allPackets, outgoingPackets, incomingPackets, featureDict)
        self.extractRequestReplyLengths(allPackets, outgoingPackets, incomingPackets, featureDict)
    
        # Return Values
        return featureDict

    def run(self, packets):

        featureDict = self.extractAllFeatures(packets)
        featureData = pd.DataFrame({k: [v] for k, v in featureDict.items()})
    
        return featureData
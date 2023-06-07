import numpy as np
import pandas as pd
import os
import logging
from tqdm import tqdm
import json
from datetime import datetime
import argparse
import pathlib

from iotpackage.__vars import CSV_cols, GeneralConfig
from iotpackage.Utils import getPDPathFromIRPath, createParentDirectory, loadCaptureFromPath
from .DNSMapping import DNSMapper

l = logging.getLogger("PreProcessing")
conf = GeneralConfig()

class PreProcessor:

    def __init__(self, target_ips=['192.168.1.161', '192.168.1.125', '192.168.1.124'], protos=[6, 17], hostname_method='both'):
        self.targetIPs = target_ips
        self.protos = protos

        if hostname_method is not None and hostname_method not in ['live', 'post', 'both']: raise Exception(f"Unknown 'hostname_method={hostname_method}'")
        self.hostname_method = hostname_method
            
        return

    def __dropEmptyIP(self, packets):
        nonIPPackets = (packets[CSV_cols['SrcIP']].isna()) | (packets[CSV_cols['DstIP']].isna())
        IPPackets = ~nonIPPackets
        l.debug(f"Before dropEmptyIP Shape: {packets.shape}")
        packets = packets[IPPackets].reset_index(drop=True)
        l.debug(f"After dropEmptyIP Shape: {packets.shape}")
        return packets

    def __checkIP(self, ip):
        try:
            splited = ip.split(',')
            if (len(splited) == 2):
                return splited[0]
            else:
                return ip
        except AttributeError:
            return ip
    def __cleanICMP(self, packets):
        if packets.shape[0] > 0:
            ICMPPackets = packets['_ws.col.Protocol'] == 'ICMP'
            packets.loc[ICMPPackets, CSV_cols['SrcIP']] = packets.loc[ICMPPackets, CSV_cols['SrcIP']].apply(self.__checkIP)
            packets.loc[ICMPPackets, CSV_cols['DstIP']] = packets.loc[ICMPPackets, CSV_cols['DstIP']].apply(self.__checkIP)

        return packets
    def __dropExtraCols(self, packets):
        oldShape = packets.shape
        packets = packets.drop(columns=[CSV_cols['tcpSrcPort'],CSV_cols['tcpDstPort'],CSV_cols['udpSrcPort'],CSV_cols['udpDstPort'], CSV_cols['SrcIP'], CSV_cols['DstIP'], "SrcPort", "DstPort"])
        l.debug(f'Dropped Extra Columns, Old Shape: {oldShape}, New Shape, {packets.shape}')
        return packets

    def __getExternalPort(self, packet):
        if packet['direction'] == 'out':
            return packet['DstPort']
        elif packet['direction'] == 'in':
            return packet['SrcPort']
        else:
            return None

    def __getInternalPort(self, packet):
        if packet['direction'] == 'out':
            return packet['SrcPort']
        elif packet['direction'] == 'in':
            return packet['DstPort']
        else:
            return None

    def __combinePorts(self, packets):
        if packets.shape[0] > 0:
            packets.loc[:,'SrcPort'] = packets[CSV_cols['tcpSrcPort']].combine_first(packets[CSV_cols['udpSrcPort']])
            packets.loc[:,'DstPort'] = packets[CSV_cols['tcpDstPort']].combine_first(packets[CSV_cols['udpDstPort']])
            packets['ext.port'] = packets.apply(self.__getExternalPort, axis=1)
            packets['int.port'] = packets.apply(self.__getInternalPort, axis=1)
        else:
            packets['SrcPort'] = None
            packets['DstPort'] = None
            packets['ext.port'] = None
            packets['int.port'] = None
        return packets

    def __assignPacketTypeandIP(self, packets):
        l.debug(f'Before assignPacketTypeandIP shape: {packets.shape}')

        srcPackets = packets[CSV_cols['SrcIP']].isin(self.targetIPs)
        dstPackets = packets[CSV_cols['DstIP']].isin(self.targetIPs)
        
        if srcPackets.sum() > 0:
            packets.loc[srcPackets, 'direction'] = 'out'
        # except ValueError:
        #     l.exception(f'ValueError @ __assignPacketTypeandIP, srcPacketsShape: {packets[srcPackets].shape}')
        # try:
        if dstPackets.sum() > 0:
            packets.loc[dstPackets, 'direction'] = 'in'
        # except ValueError:
        #     l.exception(f'ValueError @ __assignPacketTypeandIP, dstPacketsShape: {packets[dstPackets].shape}')
        packets.loc[srcPackets, 'ip'] = packets.loc[srcPackets, CSV_cols['DstIP']]
        packets.loc[dstPackets, 'ip'] = packets.loc[dstPackets, CSV_cols['SrcIP']]
        
        localTraffic = srcPackets & dstPackets
        noiseTraffic = (~srcPackets) & (~dstPackets)
        unwantedTraffic = localTraffic | noiseTraffic
        packets = packets[~unwantedTraffic].reset_index(drop=True)
        
        l.debug(f"After assignPacketTypeandIP shape: {packets.shape}")
        return packets

    def __arrReplace(self, arr, orig, new):
        arr[arr.index(orig)] = new
        return

    def __replaceColNames(self, packets):
        cols = list(packets.columns)
        self.__arrReplace(cols, CSV_cols['Frame'], "Frame")
        self.__arrReplace(cols, CSV_cols['Time'], "Time")
        self.__arrReplace(cols, CSV_cols['tcpACK'], "tcpACK")
        self.__arrReplace(cols, CSV_cols['tcpSYN'], "tcpSYN")
        self.__arrReplace(cols, CSV_cols['tcpRST'], "tcpRST")
        self.__arrReplace(cols, CSV_cols['tcpFIN'], "tcpFIN")
        self.__arrReplace(cols, CSV_cols['tcpPSH'], "tcpPSH")
        self.__arrReplace(cols, CSV_cols['tcpURG'], "tcpURG")
        self.__arrReplace(cols, CSV_cols['Protocol'], 'protocol')
        self.__arrReplace(cols, CSV_cols['Length'], "Length")
        packets.columns = cols
        return packets

    def __cleanProtos(self, packets):
        def getProto(x):
            try:
                return int(x)
            except:
                return 0
        l.debug(f'Before __cleanProtos shape: {packets.shape}')
        packets['ip.proto'] = packets['ip.proto'].apply(getProto)
        if isinstance(self.protos, str) and self.protos == 'all':
            pass
        elif isinstance(self.protos, list):
            packets = packets[packets['ip.proto'].isin(self.protos)].reset_index(drop=True)
        else:
            print('WARNING: Missed clean protos')
        l.debug(f'After __cleanProtos shape: {packets.shape}')
        return packets

    def clean(self, packets):
        packets = self.__cleanProtos(packets)
        packets = self.__cleanICMP(packets)
        packets = self.__dropEmptyIP(packets)
        packets = self.__assignPacketTypeandIP(packets)
        packets = self.__combinePorts(packets)
        packets = self.__dropExtraCols(packets)
        # packets = self.__replaceColNames(packets)
        return packets

    def genPacketData(self, captures:str, pb=True):
        """Generates cleaned and pre-processed packet data from the captures.
        
        If the argument `captures` is a list that are treated as the only CSV files to consider.
        Directory structure must remain the same because the code relies on that.

        Parameters
        ----------
        captures : str, list[str]
            The directory or the list of files to clean and return
        pb: bool (default: True)
            Whether or not to show a progress bar. `pb=True` will display a progress bar.
            `pb=False` will not show a progress bar

        Raises
        ------
        ValueError
            If there are some errors with the directory structure
        FileNotFoundError
            If a file/directory that is expected to be there is not found
        NotImplementedError
            When a `hostname_method` value passed doesn't match an implemented case.

        Yields
        ------
        pandas.DataFrame : The cleaned dataframe of packet data
        """

        if isinstance(captures, (list, np.ndarray)):
            common_s = set([os.path.split(capture)[0] for capture in captures])
            if len(common_s) > 1: raise ValueError(f"Length of parent for capture files is more than 1. Case not handled")
            common = list(common_s)[0]
            base_dir = common.replace(conf.PACKETS_PATH(''), '')
            packet_csv_fps = captures
        elif isinstance(captures, (str, pathlib.Path)):
            base_dir = captures
            self.packet_dir = conf.PACKETS_PATH(base_dir)
            if not os.path.exists(self.packet_dir): raise FileNotFoundError(f'packet_csv directory not found: {self.packet_dir}')
            packet_csv_fps = loadCaptureFromPath(self.packet_dir)
                        
        # Validate and set DNS information


        if self.hostname_method not in ['live', 'both', 'post']: 
            print('WARNING: No hostname_method provided. Just cleaning packets')
            self.hostname_method = None
        else:
            self.dns_dir = conf.DNS_PATH(base_dir)
            if not os.path.exists(self.dns_dir): raise FileNotFoundError(f'dns_dir directory not found: {self.dns_dir}')
            post_dns_mapping_path = os.path.join(base_dir, 'dns_mapping.json')
            self.DNS_Mapper = DNSMapper(post_dns_mapping=post_dns_mapping_path)
        
        if pb: pbar = tqdm(total=len(packet_csv_fps), desc="Packet Data")
        for packet_csv_fp in packet_csv_fps:
            if pb: tqdm.write(f"Loading CSV: {packet_csv_fp}")
            pdata = pd.read_csv(packet_csv_fp, low_memory=False)
            pdata = self.clean(pdata)
            dns_fp = self.__getDNSNameFromCSVName(packet_csv_fp)
            if self.hostname_method is not None:
                pdata = self.DNS_Mapper.assignHostnames(pdata, dns_fp, method=self.hostname_method)
            
            if pb:
                tqdm.write(f'Cleaned & Hostnames assigned. Shape: {pdata.shape}')
                pbar.update(1)
            yield pdata


        if pb:
            tqdm.write(f"Completed genPacketData")
            pbar.close()

    def processWithMapping(self, packets:pd.DataFrame, dns_mapping:str) -> pd.DataFrame:
        packets = self.clean(packets)
        dns_mapper = DNSMapper(dns_mapping)
        packets = dns_mapper.assignHostnames(packets, method='post')
        return packets

    def __getDNSNameFromCSVName(self, csv_name):
        """
        Given a CSV path returns the corresponding dns path. The must have the same directory structure above the csv_dir and dns_dir.
        """
        relpath = os.path.relpath(csv_name, self.packet_dir)
        return os.path.join(self.dns_dir, relpath)

    def genPdata(self, captures, pb=True):
        """Generates packet data and stiches together two consecutive yeilds

        This function maintains continous data but depends on how much data is in each file.
        If the data is last file is less than what is required at max then you may want to 
        modify this function to ensure correct amount of data is available. For this case I
        only require 1-2 minutes of data at max and capture is 30 minutes by default so all
        is good.

        Parameters
        ----------
        captures: str, list[str]
            The capture directory or the list of captures themselves. It is passed to self.genPacketData
        pb: bool (default: True)
            Whether or not to display a progress bar. It is passed to self.genPacketData
        Yields
        ------
        tuple(
            pandas.DataFrame: The stiched together continous version of packet data,
            float: The start time of the pandas.DataFrame which would be the first packet,
            float: The end time of the pandas.DataFrame which would be the last packet
        )
        """
        pdgen = self.genPacketData(captures, pb)
        pdata = next(pdgen)
        lpdata = pdata.copy()
        while True:
            if pdata.shape[0]:
                pst = pdata['frame.time_epoch'].iloc[0]
                pet = pdata['frame.time_epoch'].iloc[-1]
                yield pdata, pst, pet
            try:
                cpdata = next(pdgen)
                data_arr = [lpdata, cpdata]
                pdata = pd.concat(data_arr, ignore_index=True)
                lpdata = cpdata.copy()
            except StopIteration:
                break
        return
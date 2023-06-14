import os
import logging
import pandas as pd

from iotpackage.Utils import getPDPathFromIRPath, createParentDirectory, genIR, getVAFromIRPath
from iotpackage.PreProcessing import PreProcessor
from iotpackage.__vars import fixedFlowIds_Alexa, fixedFlowIds_Google, fixedFlowIds_Siri

l = logging.getLogger('CSV2Windows')

class FlowFiltering:
    def __init__(self, new_flow_win_width:int, fixed_flows:dict, after_width:int=60, before_width:int=15):
        """
        Initializes the class
        
        :param new_flow_win_width: the width in which 'new' flows can start
        :param fixed_flows: a dict-like structure contained flows which have to be fixed. It can contain a value for typical 5-tuple wireshark style attributes to match
        :param after_width: The total width of the window after invocation (only this much data would be returned)
        :param before_width: the width to consider for any flows active before invocation
        """
        self.new_flow_win_width = new_flow_win_width
        self.fixed_flows = fixed_flows
        self.after_width = after_width
        self.before_width = before_width
    
    def transform(self, data:pd.DataFrame) -> pd.DataFrame:
        """
        Creates 'filtered' data based on new flows and fixed flows

        :param data: the data to filter
        :returns: the filtered data
        """
        if not self.new_flow_win_width: 
            l.info(f"FlowFiltering: new_flow_win_width={self.new_flow_win_width}. Not performing filtering and returning data")
            return data
        
        pass

class CSV2Windows:
    pp = None
    low_packet_threshold = None
    def __init__(self, target_ips:list=['192.168.1.161', '192.168.1.125', '192.168.1.124'], protos=[6, 17], hostname_method:str='both', inactive_flow_timeout=15, active_flow_timeout=60, new_flow_win_width=10, va=None, low_packet_threshold=100):
        """
        PARAMETERS
        ----------
        target_ips, list(str): The internal IPs to focus on. Only devices (routers or homes) with these IPs will be considered as target. Traffic from other IPs will dropped
        protos, list(int): The list of protocols to consider default is TCP, UDP, default=[6, 17]
        hostname_method, str: The method to use for hostname mapping, 'live' means only passive DNS which can miss initial values which might have DNS traffic before capturing started. 'post' means the mapping created at the end of capture which might mark some incorrectly due to changing IPs. 'both' does live first and uses post for the missing ones
        inactive_flow_timeout, int: The timeout to use when a flow is not active according to netflow definitiion
        active_flow_timeout, int: The timeout value to use when a flow is actively sending traffic according to netflow definition
        new_flow_win_width, int: The 'm' value or the new flow win width value (default=10)
        va, str: The hint as to which VA is being used

        """
        self.pp = PreProcessor(target_ips=target_ips,
                               protos=protos, hostname_method=hostname_method)
                               
        self.inactive_flow_timeout = inactive_flow_timeout
        self.active_flow_timeout = active_flow_timeout

        self.before_st = inactive_flow_timeout
        self.after_st = active_flow_timeout

        self.new_flow_win_width = new_flow_win_width

        self.flow_grouper = ['hostname', 'ip',
                             'ext.port', 'int.port', 'ip.proto']

        self.low_packet_threshold = low_packet_threshold
        self.va = va
        if self.va is not None:
            self.setFixedFlows()
        return


    def setFixedFlows(self):
        if self.va == "Alexa":
            self.fixed_flows = fixedFlowIds_Alexa
        elif self.va == "Google":
            self.fixed_flows = fixedFlowIds_Google
        elif self.va == "Siri":
            self.fixed_flows = fixedFlowIds_Siri
        else:
            raise NotImplementedError(f"va='{self.va}' is unknown")

    def __extractWindowData(self, data, window_start_time, window_end_time):
        invoke_pdata = data[(data['frame.time_epoch'] >= window_start_time) & (
            data['frame.time_epoch'] <= window_end_time)]
        return invoke_pdata

    def __saveInvokePacketData(self, invoke_pdata, ir_path):
        pd_path = getPDPathFromIRPath(
            ir_path, self.ir_base_path, self.output_path)
        createParentDirectory(pd_path)

        num_packets = invoke_pdata.shape[0]
        size_packets = invoke_pdata['frame.len'].sum()
        if num_packets < self.low_packet_threshold and size_packets:
            err_msg = f"Not saving IR too low data: {num_packets}, {size_packets}, {ir_path}"
            l.error(err_msg)
            print('ERROR: Some window data not saved. Check logs')
        else:
            invoke_pdata.to_csv(pd_path, index=False)

    def getFlowsinWindow(self, packets, wst, wet):
        win_idx = (packets['frame.time_epoch'] >= wst) & (
            packets['frame.time_epoch'] < wet)
        flows = packets[win_idx].groupby(self.flow_grouper).groups.keys()
        return set(flows)

    def isFixedFlow(self, x, fixed_flows):
        for fixed_flow in fixed_flows:
            all_attribute_match = True
            for idx, flow_attribute in enumerate(self.flow_grouper):
                if flow_attribute in fixed_flow and x[idx] != fixed_flow[flow_attribute]:
                    all_attribute_match = False
                    break
            if all_attribute_match:
                return True
        return False

    def getFixedFlows(self, all_flows):
        flow_list = [flow for flow in all_flows if self.isFixedFlow(
            flow, self.fixed_flows)]
        return set(flow_list)

    def getFlowsToTrack(self, packets, invoke_ts):
        delta_win_s_ts = invoke_ts
        delta_win_e_ts = invoke_ts + self.new_flow_win_width
        active_flows = self.getFlowsinWindow(
            packets, delta_win_s_ts - self.inactive_flow_timeout, delta_win_s_ts)
        all_flows = self.getFlowsinWindow(
            packets, delta_win_s_ts, delta_win_e_ts)
        new_flows = all_flows - active_flows
        fixed_flows = self.getFixedFlows(all_flows)
        tracked_flows = new_flows.union(fixed_flows)
        return tracked_flows

    def getTrackedTraffic(self, packets, invoke_ts):
        def addTrafficFromGroup(gdata):
            try:
                gname = gdata.name
            except:
                print('ERROR: gdata.name:', gdata.shape, gdata)
                return
            if gname not in tracked_flows:
                return
            last_pkt_time = gdata['frame.time_epoch'].iloc[0]
            for i, pkt in gdata.iterrows():
                pkt_time = pkt['frame.time_epoch']
                if (pkt_time > (invoke_ts + self.new_flow_win_width)) and (pkt_time > (last_pkt_time + self.inactive_flow_timeout)):
                    return
                if pkt_time > invoke_ts + self.active_flow_timeout:
                    return
                if pkt_time >= invoke_ts:
                    idxs.append(i)
                last_pkt_time = pkt_time

        idxs = []
        tracked_flows = self.getFlowsToTrack(packets, invoke_ts)
        packets.groupby(self.flow_grouper).apply(addTrafficFromGroup)
        return packets.loc[idxs, :].sort_index()

    def run(self, input_dir, ir_base_path, output_path):
        if self.va is None:
            self.va = getVAFromIRPath(ir_base_path)
            self.setFixedFlows()
        print(f"VA='{self.va}'")

        self.output_path = output_path
        self.ir_base_path = ir_base_path
        pdgen = self.pp.genPdata(input_dir)
        irgen = genIR(irs=ir_base_path, load_stop=False)
        pdata, pst, pet = next(pdgen)
        for ir_fp, ir_data, status in irgen:
            if status != 'V':
                continue
            st = ir_data['start_time']
            wst = st - self.before_st
            wet = st + self.after_st

            if wst < pst:
                err_msg = f'Not enough data for IR: {ir_fp}'
                l.warning(err_msg)
                print('WARNING:', err_msg)
            wpdata_arr = []
            while wst > pet:
                pdata, pst, pet = next(pdgen)
            while True:
                wpdata = self.__extractWindowData(pdata, wst, wet)
                wpdata_arr.append(wpdata.reset_index(drop=True))
                if pet < wet:
                    pdata, pst, pet = next(pdgen)
                else:
                    break

            wpdata = pd.concat(wpdata_arr, ignore_index=True)
            if self.new_flow_win_width: wpdata = self.getTrackedTraffic(wpdata, st)
            self.__saveInvokePacketData(wpdata, ir_fp)
        return

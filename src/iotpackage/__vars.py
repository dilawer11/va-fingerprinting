import os
import json

simpleFeatureGroups = {
    'Total Packets': {
        'suffix': '_totalpkts',
        'description': 'input and output total packet counts'
    },
    'Total Bytes': {
        'suffix': '_totalbytes',
        'description': 'incoming and outgoing total packet size'
    },
    'Unique Packet Length': {
        'suffix': '_uniquelen',
        'description': 'incoming and outgoing unique packet length distribution features'
    },
    'Packet Length': {
        'suffix': '_len',
        'description': 'incoming and outgoing all packet length distribution features'
    },
    'Total Percentage': {
        'suffix': '_percentage',
        'description': 'incoming and outgoing total packet ratio/percentage'
    },
    'External Counts': {
        'suffix': '_extcount',
        'description': 'external ip, hostname, port based counts',
    },
    'Inter-Burst Delays': {
        'suffix': '_interburstdelay',
        'description': 'distribution features of delay between end of one burst and start of another',
    },
    'Burst Length': {
        'suffix': '_burstbytes',
        'description': 'distribution features of the bytes in one burst',
    },
    'Burst Packet Count': {
        'suffix': '_burstnumpkts',
        'description': 'distribution features of the count of packets in one burst',
    },
    'Burst Time': {
        'suffix': '_bursttime',
        'description': 'distribution features of how long a burst lasts'
    },
    'Inter-Packet Delay': {
        'suffix': '_interpktdelay',
        'description': 'distribution features of delay between two packets',
    },
    'Flow Length': {
        'suffix': '_flowbytes',
        'description': 'distribution features of the bytes in one flow',
    },
    'Flow Packet Count': {
        'suffix': '_flownumpkts',
        'description': 'distribution features of the count of packets in one flow',
    },
    'Flow Time': {
        'suffix': '_flowtime',
        'description': 'distribution features of how long a flow lasts'
    },
}
dictFeatureGroups = {
    'External Port': {
        'suffix': '_dict_extport',
        'description': 'External ports contacted and their counts in a dict-like feature'
    },
    'IP': {
        'suffix': '_dict_ip',
        'description': 'IPs contacted and their counts in a dict-like feature'
    },
    'Hostname': {
        'suffix': '_dict_hostname',
        'description': 'Hostnames contacted and their counts in a dict-like feature'
    },
    'Packet Lengths': {
        'suffix': '_dict_packetlens',
        'description': 'Packet lengths and their counts in outgoing and incoming traffic in a dict-like feature'
    },
    'Ping Pong Pairs': {
        'suffix': '_dict_pingpong',
        'description': 'Ping pong pairs. individual packet req reply lengths and their counts in a dict-like feature'
    },
    'Req Reply Packet Lengths': {
        'suffix': '_dict_reqreplylens',
        'description': 'Request reply pair lens over multiple packets and their counts in a dict-like feature',
    },
    'Protocols': {
        'suffix': '_dict_protocols',
        'description': 'Protocols and their counts in a dict-like-feature',
    }
}

CSV_cols = {
    'SrcIP' : 'ip.src',
    'DstIP' : 'ip.dst',
    'Protocol' : '_ws.col.Protocol',
    'tcpSrcPort' : 'tcp.srcport',
    'tcpDstPort' : 'tcp.dstport',
    'udpSrcPort' : 'udp.srcport',
    'udpDstPort' : 'udp.dstport',
    'Proto' : 'ip.proto',
    'Frame' : 'frame.number',
    'Time' : 'frame.time_epoch',
    'tcpACK' : 'tcp.flags.ack',
    'tcpSYN' : 'tcp.flags.syn',
    'tcpRST' : 'tcp.flags.reset',
    'tcpFIN' : 'tcp.flags.fin',
    'tcpPSH' : 'tcp.flags.push',
    'tcpURG' : 'tcp.flags.urg',
    'Length' : 'frame.len'
}

# fixedFlowIds_##VA can be specified by using flow_grouper names from CSV2EventCSV
# `hostname` matches the hostname exactly
# `ip` matches the ip exactly
# `ext.port` matches the external port exactly
# `int.port` matches the internal port exactly
# `ip.proto` matches the protocol exactly
# absence of any key means (match with any/don't include in matching)
fixedFlowIds_Alexa = [
    { 'hostname': 'avs-alexa-4-na.amazon.com' },
    { 'hostname': 'api.amazonalexa.com'},
    { 'hostname': 'unagi-na.amazon.com'},
]

fixedFlowIds_Google = [
    { 'hostname': 'www.google.com', 'ip.proto': '17' }
]

fixedFlowIds_Siri = [
    { 'hostname': 'guzzoni-apple-com.v.aaplimg.com' },
    { 'hostname': 'guzzoni.apple.com' },
    { 'hostname': 'swallow-apple-com.v.aaplimg.com'},
    { 'hostname': 'swallow.apple.com'},
    { 'hostname': 'probe-siri-apple-com.v.aaplimg.com'},
    { 'hostname': 'probe.siri.apple.com'},
    { 'hostname': 'dejavu-apple-com.v.aaplimg.com'},
    { 'hostname': 'dejavu.apple.com'},
]

def READ_JSON(fp):
    with open(fp, 'r') as f:
        data = json.load(f)
    return data
def STORE_JSON(fp, data):
    with open(fp, 'w+') as f:
        json.dump(data, f, indent=4)
    return

# Configurations
class GeneralConfig:
    DNS_MAPPING_FNAME = "dns_mapping.json"
    CAPTURE_CSV_DIR_NAME = "captures_csv"
    PACKETS_DIR_NAME = "packets"
    DNS_DIR_NAME = "dns"
    IR_DIR_NAME = "invoke_records"
    EVENTWIN_DIR_NAME = "event-windows"

    def IR_PATH(self, input_dir:str) -> str: return os.path.join(input_dir, self.IR_DIR_NAME)
    def CAPTURES_CSV_PATH(self, input_dir:str) -> str: return os.path.join(input_dir, self.CAPTURE_CSV_DIR_NAME)
    def PACKETS_PATH(self, input_dir:str) -> str: return os.path.join(self.CAPTURES_CSV_PATH(input_dir), self.PACKETS_DIR_NAME)
    def DNS_PATH(self, input_dir:str) -> str: return os.path.join(self.CAPTURES_CSV_PATH(input_dir), self.DNS_DIR_NAME)
    def DNS_MAPPING_PATH(self, input_dir:str) -> str: return os.path.join(input_dir, self.DNS_MAPPING_FNAME)

class DetectionConfig(GeneralConfig):
    MODEL_DIR_NAME = "classifiers"
    RESULT_DIR_NAME = "results"
    
    METADATA_FNAME = "METADATA.json"

    # Models
    MODEL_AML = "AutoMLClassifier"
    MODEL_KMN = "KMeansClassifier"
    MODEL_RFR = "RandomForestClassifier"
    MODEL_ADB = "AdaBoostClassifier"
    MODEL_KNN = "KNeighborsClassifier"
    MODEL_XGB = "XGBClassifier"
    MODEL_AD_DEFAULT = MODEL_AML
    MODEL_ID_DEFAULT = MODEL_RFR

    def CLASSIFIER_PATH(self, setup_dir:str) -> str: return os.path.join(setup_dir, self.MODEL_DIR_NAME)
    def RESULTS_PATH(self, setup_dir:str) -> str: return os.path.join(setup_dir, self.RESULT_DIR_NAME)
    def SETUP_PATH(self, det_dir_path:str, setup_name:str): return os.path.join(det_dir_path, setup_name)
    def METADATA_PATH(self, setup_dir:str) -> str: return os.path.join(setup_dir, self.METADATA_FNAME)
    def storeMetadata(self, setup_dir, metadata_obj):
        metadata_path = self.METADATA_PATH(setup_dir)

        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                existing_data = json.load(f)
            existing_data.update(metadata_obj)
            metadata_obj = existing_data
        with open(metadata_path, 'w+') as f:
            json.dump(metadata_obj, f, indent=4)
        return
    def loadMetadata(self, setup_dir):
        metadata_path = self.METADATA_PATH(setup_dir)
        if not os.path.exists(metadata_path):
            raise FileNotFoundError(f"metadata_path='{metadata_path}' not found.")
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        return metadata

class InvocationDetectionConfig(DetectionConfig):
    WSIZE = None
    WSTEP = None
    MARK_TRUE_IN = None

    INVDET_BASE_NAME = "invocation-detection"
    SLIDINGWIN_DIR_NAME = "sliding-windows"
    SETUP_NAME = None
    def __init__(self, wsize:int=4, wstep:int=2, mark_true_in:int=2):
        self.WSIZE = wsize
        self.WSTEP = wstep
        self.MARK_TRUE_IN = mark_true_in
        return
    def INVOCATIONDETECTION_PATH(self, input_dir:str) -> str: return os.path.join(input_dir, self.INVDET_BASE_NAME)
    def SLIDINGWIN_PATH(self, setup_dir:str) -> str: return os.path.join(setup_dir, self.SLIDINGWIN_DIR_NAME)
    def GET_SETUP_NAME(self): return f"{self.WSIZE}_{self.WSTEP}_{self.MARK_TRUE_IN}"
    def PARSE_SETUP_NAME(self, setup_name):
        wsize, wstep, mark_true_in = setup_name.split('_')
        self.WSIZE = int(wsize)
        self.WSTEP = int(wstep)
        self.MARK_TRUE_IN = int(mark_true_in)


class FeatureSelectorConfig:
    N_ALL = None
    N_TCP = None
    N_UDP = None
    N_PROTO = None
    SIMPLE_GROUPS = None
    DICT_GROUPS = None
    ONE_HOT_ENCODE = None
    def __init__(self, n_all=0, n_tcp=100, n_udp=50, n_proto=10, simple_groups="all", dict_groups="all", one_hot_encode=True):
        self.N_ALL = n_all
        self.N_TCP = n_tcp
        self.N_UDP = n_udp
        self.N_PROTO = n_proto
        self.SIMPLE_GROUPS = simple_groups
        self.DICT_GROUPS = dict_groups
        self.ONE_HOT_ENCODE = one_hot_encode
    def parseFromConfig(self, fs_config:str):
        data = READ_JSON(fs_config)
        if 'n_all' in data: self.N_ALL = data['n_all']
        if 'n_tcp' in data: self.N_TCP = data['n_tcp']
        if 'n_udp' in data: self.N_UDP = data['n_udp']
        if 'n_proto' in data: self.N_PROTO = data['n_proto']
        if 'simple_groups' in data: self.SIMPLE_GROUPS = data['simple_groups']
        if 'dict_groups' in data: self.DICT_GROUPS = data['dict_groups']
        if 'one_hot_encode' in data: self.ONE_HOT_ENCODE = data['one_hot_encode']
        return

class ModelTrainConfig:
    RUNS = None
    PLOT_CM = None
    ERRORS = None
    LABEL_COL = None
    FEATURES = None
    CV = None
    def __init__(self, runs=1, plot_cm=True, errors=True, label_col="label", features=True, cv=0):
        self.RUNS = runs
        self.PLOT_CM = plot_cm
        self.ERRORS = errors
        self.LABEL_COL = label_col
        self.FEATURES = features
        self.CV = cv
        return
    def parseFromConfig(self, mt_config:str):
        data = READ_JSON(mt_config)
        if 'runs' in data: self.RUNS = data['runs']
        if 'plot_cm' in data: self.PLOT_CM = data['plot_cm']
        if 'errors' in data: self.ERRORS = data['errors']
        if 'label_col' in data: self.LABEL_COL = data['label_col']
        if 'features' in data: self.FEATURES = data['features']
        if 'cv' in data: self.CV = data['cv']
        return
    
class ActivityDetectionConfig(DetectionConfig):
    ACTDET_BASE_NAME = "activity-detection"
    # Other default values
    NEW_FLOW_WIN_WIDTH= None
    HOSTNAME_METHOD = None
    INACTIVE_FLOW_TIMEOUT = None
    ACTIVE_FLOW_TIMEOUT = None
    TARGET_IPS = None
    PROTOS = None
    FS = None
    MT = None

    def __init__(self, fdata_name:str="fdata.pkl", new_flow_win_width:int=10, hostname_method:str='both', inactive_flow_timeout:int=15, active_flow_timeout:int=60, target_ips:list=['192.168.1.161', '192.168.1.125', '192.168.1.124'], protos:list=[6, 17], fs_config=FeatureSelectorConfig(), mt_config=ModelTrainConfig()):
        self.FDATA_NAME = fdata_name
        self.NEW_FLOW_WIN_WIDTH = new_flow_win_width
        self.HOSTNAME_METHOD = hostname_method
        self.INACTIVE_FLOW_TIMEOUT = inactive_flow_timeout
        self.ACTIVE_FLOW_TIMEOUT = active_flow_timeout
        self.TARGET_IPS = target_ips
        self.PROTOS = protos
        self.FS = fs_config
        self.MT = mt_config
        return
    def ACTIVITYDETECTION_PATH(self, input_dir:str) -> str: return os.path.join(input_dir, self.ACTDET_BASE_NAME)
    def EVENTWIN_PATH(self, setup_dir:str) -> str: return os.path.join(setup_dir, self.EVENTWIN_DIR_NAME)
    def FEATUREDATA_PATH(self, setup_dir:str) -> str: return os.path.join(setup_dir, self.FDATA_NAME)
    def CLASSIFIER_RESULT_PATH(self, clf_dir:str, classifier:str) -> str: return os.path.join(clf_dir, classifier)
    def GET_SETUP_NAME(self):
        setup_name = f'{self.HOSTNAME_METHOD}_{self.NEW_FLOW_WIN_WIDTH}_{self.INACTIVE_FLOW_TIMEOUT}_{self.ACTIVE_FLOW_TIMEOUT}'
        return setup_name
    def PARSE_SETUP_NAME(self, setup_name):
        hostname_method, new_flow_win_width, inactive_flow_timeout, active_flow_timeout = setup_name.split('_')

        self.HOSTNAME_METHOD = hostname_method
        self.NEW_FLOW_WIN_WIDTH = int(new_flow_win_width)
        self.INACTIVE_FLOW_TIMEOUT = int(inactive_flow_timeout)
        self.ACTIVE_FLOW_TIMEOUT = int(active_flow_timeout)
        return

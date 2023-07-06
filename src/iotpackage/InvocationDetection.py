import pandas as pd
from time import time
from datetime import datetime
from tqdm import tqdm
import os
import json
import pickle

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import AdaBoostClassifier
from xgboost import XGBClassifier

from iotpackage.PreProcessing import PreProcessor
from iotpackage.Utils import loadInvokeRecords, loadCaptureFromPath, computeMetrics, getVAFromIRPath
from iotpackage.__vars import InvocationDetectionConfig

class WindowGeneration:
    def __init__(self, input_dir: str, wsize: int, wstep: int, mark_true_in: int, idle: bool = False):
        self.config = InvocationDetectionConfig(wsize=wsize, wstep=wstep, mark_true_in=mark_true_in)
        if not os.path.exists(input_dir) or not os.path.isdir(input_dir):
            raise FileNotFoundError(
                f"input_dir='{input_dir}' not found or isn't a directory")
        if mark_true_in > wsize:
            raise ValueError(
                f"mark_true_in='{mark_true_in}' cannot be greater than wsize='{wsize}'")

        self.input_dir_ = input_dir
        # Create a path to input packet directory and make sure it exists
        self.packets_dir_ = self.config.PACKETS_PATH(self.input_dir_)
        if not os.path.isdir(self.packets_dir_):
            raise FileNotFoundError(
                f"packets_dir='{self.packets_dir_}' not found. Have you extracted CSVs from PCAPS?")

        # Load the DNS data.
        self.dns_data = self.loadDNSData(
            dns_mapping=self.config.DNS_MAPPING_PATH(self.input_dir_))

        # Create a path to invoke records directory and make sure it exists. Don't need this if idle windows are being generated
        self.ir_dir_ = self.config.IR_PATH(self.input_dir_)
        if not os.path.isdir(self.ir_dir_) and not idle:
            raise FileNotFoundError(f'No such directory: {self.ir_dir_}')

        self.idle_ = idle

        self.output_dir = self.setupOutputDir()
        return

    def loadDNSData(self, dns_mapping):
        if not os.path.exists(dns_mapping):
            raise FileNotFoundError(f"dns_mapping='{dns_mapping}' not found")
        with open(dns_mapping, 'r') as f:
            dns_data = json.load(f)
        return dns_data

    def setupOutputDir(self):
        self.base_output_dir = self.config.INVOCATIONDETECTION_PATH(self.input_dir_)
        if not os.path.isdir(self.base_output_dir):
            os.mkdir(self.base_output_dir)

        setup_dir_name = self.config.GET_SETUP_NAME()
        print('Setup Name:', setup_dir_name)
        self.setup_dir_path = os.path.join(
            self.base_output_dir, setup_dir_name)
        if os.path.exists(self.setup_dir_path):
            raise FileExistsError(
                f"setup_dir='{self.setup_dir_path}' already exists. Please remove to create windows")
        else:
            os.mkdir(self.setup_dir_path)

        output_dir = self.config.SLIDINGWIN_PATH(self.setup_dir_path)
        os.mkdir(output_dir)
        print('Created Output Directory:', output_dir)
        return output_dir

    @staticmethod
    def getActivityData(ir_data):
        if 'va_actvity_data' in ir_data:
            return ir_data['va_actvity_data']
        elif 'va_activity_data' in ir_data:
            return ir_data['va_activity_data']
        else:
            raise NotImplementedError(f'Case not implemented')

    def parseValidationTag(self, ir_data:dict, validation_tag:str):
        if len(validation_tag) != 1:
            raise Exception(f'validation_tag in name is supposed to be one letter')
        try:
            va_activity_data = self.getActivityData(ir_data)
            if validation_tag != 'V' and len(va_activity_data):
                validation_tag = 'O'
                for record in va_activity_data:
                    if record['utteranceType'] == 'FALSE_WAKE_WORD_1P':
                        validation_tag = 'F'
        except:
            validation_tag = 'O'
        return validation_tag
    def invokeRecordGen(self, ir_base_dir):
        irs = loadInvokeRecords(ir_base_dir, sort=True)
        for ir in irs:
            with open(ir, 'r') as f:
                ir_data = json.load(f)
            st = ir_data['start_time']
            fn = os.path.split(ir)[1]
            validation_tag = self.parseValidationTag(ir_data, fn.split('_')[1])
            yield st, validation_tag

    def slidingWindowGen(self, packets_dir, dns_data):
        capture_files = loadCaptureFromPath(packets_dir)
        if len(capture_files) < 1:
            raise Exception(f'No capture files found')

        pp = PreProcessor()

        wst = None
        prev_lo_data = pd.DataFrame([])

        for capture_file in tqdm(capture_files, position=0, leave=True):
            data = pd.read_csv(capture_file)
            data = pp.processWithMapping(data, dns_data)
            current_pkt_data = pd.concat(
                [prev_lo_data, data], ignore_index=True)
            # Will only go in this condition in first iteration
            if wst is None:
                wst = current_pkt_data['frame.time_epoch'].iloc[0]
            cf_last_pkt_time = current_pkt_data['frame.time_epoch'].iloc[-1]
            wet = wst + self.config.WSIZE
            while wet < cf_last_pkt_time:
                # Get the index and data for window traffic
                widx = (current_pkt_data['frame.time_epoch'] >= wst) & (
                    current_pkt_data['frame.time_epoch'] < wet)
                wdata = current_pkt_data[widx]
                yield wst, wet, wdata
                wst += self.config.WSTEP
                wet = wst + self.config.WSIZE
            prev_lo_data = current_pkt_data[current_pkt_data['frame.time_epoch'] >= wst].copy(
            ).reset_index(drop=True)
            current_pkt_data = None

    def generateNormalTrafficWindows(self):
        irg = self.invokeRecordGen(self.ir_dir_)
        swg = self.slidingWindowGen(
            packets_dir=self.packets_dir_, dns_data=self.dns_data)

        invoke_start_time, invoke_validation_tag = next(irg)
        last_invoke_time = 0
        for wst, _, wdata in swg:
            while wst > invoke_start_time:
                tqdm.write(f'Next IR, {invoke_start_time}, wst: {wst}')
                last_invoke_time = invoke_start_time
                try:
                    invoke_start_time, invoke_validation_tag = next(irg)
                except StopIteration:
                    invoke_start_time = float('inf')
                    invoke_validation_tag = 'N'
            if invoke_start_time >= wst and invoke_start_time <= (wst + self.config.MARK_TRUE_IN):
                label = f'1-{invoke_validation_tag}'
            elif wst < last_invoke_time + 30:
                # Ignore these next 30 seconds of windows because we just made a postive window
                continue
            else:
                label = f'0-N'
            output_fp = os.path.join(self.output_dir, f'{label}-{wst}.csv')
            wdata.to_csv(output_fp, index=False)

    def generateIdleTrafficWindows(self):
        swg = self.slidingWindowGen(
            packets_dir=self.packets_dir_, dns_data=self.dns_data)
        for wst, _, wdata in swg:
            output_fp = os.path.join(self.output_dir, f'0-N-{wst}.csv')
            wdata.to_csv(output_fp, index=False)
        return

    def saveMetadata(self):
        metadata = {
            'wsize': self.config.WSIZE,
            'wstep': self.config.WSTEP,
            'mark_true_in': self.config.MARK_TRUE_IN,
            'idle': self.idle_,
            'va': getVAFromIRPath(self.ir_dir_),
            'win_time': time(),
        }
        self.config.storeMetadata(self.setup_dir_path, metadata)
        return

    def start(self):
        if self.idle_:
            self.generateIdleTrafficWindows()
        else:
            self.generateNormalTrafficWindows()
        self.saveMetadata()
        print("Saved to:", self.output_dir)
        return


def getSWLabel(fn: str, va: str) -> int:
    fn_split = fn.split('-')
    label = fn_split[0]
    validation_tag = fn_split[1]
    # Alexa case is more complex because of false invocations categorization of Alexa. Might want to remove false invocations entirely
    if va == "Alexa":
        if label == '0':
            return 0
        elif label == '1':
            if validation_tag == 'O':
                return 1
            elif validation_tag == 'V':
                return 1
            else:
                return 0
    elif va == "Google":
        return int(label)
    elif va == "Siri":
        return int(label)
    elif va is None:
        return int(label)
    else:
        raise ValueError(
            f'''Unexpected label or validation tag: { label }, { validation_tag }''')


def loadSWs(sw_dir, va):
    sw_inventory = {'path': [], 'label': []}
    for root, _, files in os.walk(sw_dir):
        for fn in files:
            if os.path.splitext(fn)[1] != '.csv':
                continue
            path = os.path.join(root, fn)
            label = getSWLabel(fn, va)
            sw_inventory['path'].append(path)
            sw_inventory['label'].append(label)
    sw_inventory = pd.DataFrame(sw_inventory)
    return sw_inventory

class ClassifierBase:
    def __init__(self, va=None):
        self.va_ = va
        pass

    @staticmethod
    def minSample(sw_inventory):
        """Balances the classes in the data """
        min_val = sw_inventory['label'].value_counts().min()
        sw_sample = sw_inventory.groupby('label').apply(
            lambda x: x.sample(min_val)).reset_index(drop=True)
        return sw_sample

    @staticmethod
    def extractFeaturesSiri(data):
        res = {}
        res["hns_out"] = 0
        res["hns_in"] = 0

        if not data.shape[0]: return res

        hostnames = [
            'guzzoni-apple-com.v.aaplimg.com',
            'guzzoni.apple.com',
            'swallow-apple-com.v.aaplimg.com',
            'swallow.apple.com',
            'probe-siri-apple-com.v.aaplimg.com',
            'probe.siri.apple.com',
            'dejavu-apple-com.v.aaplimg.com',
            'dejavu.apple.com',
        ]

        idx_out = data['direction'] == 'out'
        idx_in = data['direction'] == 'in'
        idx_hns = data['hostname'].isin(hostnames)
        idx_filter = idx_hns

        res["hns_out"] = data.loc[idx_filter & idx_out, "frame.len"].sum()
        res["hns_in"] = data.loc[idx_filter & idx_in, "frame.len"].sum()

        return res
 
    @staticmethod
    def extractFeaturesGoogle(data):
        res = {}
        res["ggl_out"] = 0
        res["ggl_in"] = 0

        #If empty return 0 in all features
        if not data.shape[0]: return res

        idx_out = data['direction'] == 'out'
        idx_in = data['direction'] == 'in'
        idx_ggl = data['hostname'] == 'www.google.com'
        idx_filter = idx_ggl

        idx_udp = ((data['ip.proto'] == '17') | (data['ip.proto'] == 17))
        idx_filter = idx_filter & idx_udp

        res["ggl_out"] = data.loc[idx_filter & idx_out, "frame.len"].sum()
        res["ggl_in"] = data.loc[idx_filter & idx_in, "frame.len"].sum()

        return res

    @staticmethod
    def extractFeaturesAlexa(data):
        res = {}
        res["avs_out"] = 0
        res["avs_in"] = 0
        res["una_out"] = 0
        res["una_in"] = 0

        # If empty return 0 as all features
        if not data.shape[0]: return res

        idx_out = data['direction'] == 'out'
        idx_in = data['direction'] == 'in'
        idx_avs = data['hostname'] == 'avs-alexa-4-na.amazon.com'
        idx_una = data['hostname'] == 'unagi-na.amazon.com'

        res["avs_out"] = data.loc[idx_avs & idx_out, "frame.len"].sum()
        res["avs_in"] = data.loc[idx_avs & idx_in, "frame.len"].sum()
        res["una_out"] = data.loc[idx_una & idx_out, "frame.len"].sum()
        res["una_in"] = data.loc[idx_una & idx_in, "frame.len"].sum()

        return res

    def extractFeatures(self, data):
        if self.va_ == "Alexa":
            return self.extractFeaturesAlexa(data)
        elif self.va_ == "Google":
            return self.extractFeaturesGoogle(data)
        elif self.va_ == "Siri":
            return self.extractFeaturesSiri(data)
        else:
            raise NotImplementedError(f"extractFeatures not implemented for va={self.va_}")

    def extractFeaturesDF(self, sw_df, pb=True):
        if pb: pbar = tqdm(total=sw_df.shape[0], position=0, leave=True)
        res_arr = []
        for _, row in sw_df.iterrows():
            path = row['path']
            data = pd.read_csv(path)

            res = self.extractFeatures(data)
            res_arr.append(res)
            if pb: pbar.update(1)
        if pb: pbar.close()
        
        X = pd.DataFrame(res_arr)
        return X


class ClassifierTraining(ClassifierBase):
    def __init__(self, input_dir, setup_name, balance_samples: bool = True, plot_scatter: bool = True):
        self.config = InvocationDetectionConfig()
        self.config.PARSE_SETUP_NAME(setup_name)
        self.input_dir_ = input_dir
        self.balance_samples_ = balance_samples
        self.plot_scatter_ = plot_scatter
        self.invdet_dir_ = self.config.INVOCATIONDETECTION_PATH(self.input_dir_)
        self.setup_dir_ = os.path.join(self.invdet_dir_, setup_name)
        self.sw_dir_ = self.config.SLIDINGWIN_PATH(self.setup_dir_)
        if not os.path.isdir(self.sw_dir_):
            raise FileNotFoundError(
                f"Sliding Window Directory='{self.sw_dir_}' not found. Did you create sliding windows?")
        self.va_ = self.config.loadMetadata(self.setup_dir_)['va']

        self.model_dir_ = self.config.CLASSIFIER_PATH(self.setup_dir_)
        self.result_dir_ = self.config.RESULTS_PATH(self.setup_dir_)
        if not os.path.isdir(self.model_dir_):
            os.mkdir(self.model_dir_)
        if not os.path.isdir(self.result_dir_):
            os.mkdir(self.result_dir_)

   

    def scatterPlot(self, X, y, out_path=None):
        import plotly.express as px
        scatter_df = pd.DataFrame()
        if self.va_ == "Alexa":
            scatter_df['x'] = X['avs_out']
            scatter_df['y'] = X['una_out']
            scatter_df['color'] = y
        elif self.va_ == "Google":
            scatter_df['x'] = X['ggl_out']
            scatter_df['y'] = X['ggl_in']
            scatter_df['color'] = y
        elif self.va_ == "Siri":
            scatter_df['x'] = X['hns_out']
            scatter_df['y'] = X['hns_in']
            scatter_df['color'] = y
        else:
            raise ValueError(f"Unknown VA='{self.va_}'")

        fig = px.scatter(scatter_df, x='x', y='y', color='color')
        if out_path is not None:
            fig.write_html(os.path.join(out_path, 'scatter.html'))
        return

    def supervisedLearn(self, X_train, X_test, y_train, y_test, model_path=None, result_path=None):

        clf_name = self.config.MODEL_RFR
        print(f"Classifier={clf_name}")
        clf = RandomForestClassifier()
        clf.fit(X_train, y_train)
        if model_path is not None:
            # Save the model
            model_out_path = os.path.join(model_path, f'{clf_name}.pkl')
            with open(model_out_path, 'wb') as f:
                pickle.dump(clf, f)
        y_pred = clf.predict(X_test)
        res_path = None if result_path is None else os.path.join(
            result_path, clf_name)
        computeMetrics(y_test, y_pred, average='binary', result_path=res_path)

        clf_name = self.config.MODEL_ADB
        print(f"Classifier={clf_name}")
        clf = AdaBoostClassifier()
        clf.fit(X_train, y_train)
        if model_path is not None:
            # Save the model
            model_out_path = os.path.join(model_path, f'{clf_name}.pkl')
            with open(model_out_path, 'wb') as f:
                pickle.dump(clf, f)
        y_pred = clf.predict(X_test)
        res_path = None if result_path is None else os.path.join(
            result_path, clf_name)
        computeMetrics(y_test, y_pred, average='binary', result_path=res_path)

        clf_name = self.config.MODEL_KNN
        print(f"Classifier={clf_name}")
        clf = KNeighborsClassifier()
        clf.fit(X_train, y_train)
        if model_path is not None:
            # Save the model
            model_out_path = os.path.join(model_path, f'{clf_name}.pkl')
            with open(model_out_path, 'wb') as f:
                pickle.dump(clf, f)
        y_pred = clf.predict(X_test)
        res_path = None if result_path is None else os.path.join(
            result_path, clf_name)
        computeMetrics(y_test, y_pred, average='binary', result_path=res_path)

        clf_name = self.config.MODEL_XGB
        print(f"Classifier={clf_name}")
        clf = XGBClassifier()
        clf.fit(X_train, y_train)
        if model_path is not None:
            # Save the model
            model_out_path = os.path.join(model_path, f'{clf_name}.pkl')
            with open(model_out_path, 'wb') as f:
                pickle.dump(clf, f)
        y_pred = clf.predict(X_test)
        res_path = None if result_path is None else os.path.join(
            result_path, clf_name)
        computeMetrics(y_test, y_pred, average='binary', result_path=res_path)

    def saveMetadata(self):
        metadata_to_add = {
            'train_time': time()
        }
        self.config.storeMetadata(self.setup_dir_, metadata_to_add)
        return

    def run(self):
        sw_df = loadSWs(self.sw_dir_, self.va_)
        if self.balance_samples_:
            sw_df = self.minSample(sw_df)
        n_samples = sw_df.shape[0]
        print("# Samples:", n_samples)
        sw_df.reset_index(drop=True, inplace=True)
        y = sw_df['label']
        print("Extracting Features...")
        X = self.extractFeaturesDF(sw_df)

        if self.plot_scatter_:
            self.scatterPlot(X, y, out_path=self.model_dir_)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, stratify=y)

        self.supervisedLearn(X_train, X_test, y_train,
                             y_test, model_path=self.model_dir_, result_path=self.result_dir_)
        self.saveMetadata()
        print('Done')


class ClassifierInferring(ClassifierBase):
    config = None
    def __init__(self, data_input_dir, data_setup_name, balance_samples:bool=True, model_input_dir=None, model_setup_name=None):
        self.config = InvocationDetectionConfig()
        self.balance_samples = balance_samples
        self.config.PARSE_SETUP_NAME(data_setup_name)
        self.data_input_dir_ = data_input_dir
        self.data_invdet_dir_ = self.config.INVOCATIONDETECTION_PATH(self.data_input_dir_)
        self.data_setup_dir_ = os.path.join(
            self.data_invdet_dir_, data_setup_name)

        self.model_input_dir_ = model_input_dir
        self.model_invdet_dir_ = self.config.INVOCATIONDETECTION_PATH(
            self.model_input_dir_)
        self.model_setup_dir_ = os.path.join(
            self.model_invdet_dir_, model_setup_name)

        if not os.path.exists(self.data_setup_dir_):
            raise FileNotFoundError(
                f"DataSetupDirectory='{self.data_setup_dir_}' not found. Did you create sliding windows?")
        if not os.path.exists(self.model_setup_dir_):
            raise FileNotFoundError(
                f"ModelSetupDirectory='{self.model_setup_dir_}' not found. Did you train model?")

        self.model_dir_ = self.config.CLASSIFIER_PATH(self.model_setup_dir_)
        if not os.path.isdir(self.model_dir_):
            raise FileNotFoundError(f"model_dir='{self.model_dir_}' not found")

        self.sw_dir_ = self.config.SLIDINGWIN_PATH(self.data_setup_dir_)
        if not os.path.isdir(self.sw_dir_):
            raise FileNotFoundError(
                f"Sliding Window Directory='{self.sw_dir_}' not found. Did you create sliding windows?")

        self.infer_out_dir = os.path.join(self.data_setup_dir_, 'infer-results')
        self.current_out_uid = datetime.now().replace(microsecond=0).isoformat().replace(':', '')
        self.current_out_dir = os.path.join(self.infer_out_dir, self.current_out_uid)
        os.makedirs(self.current_out_dir)

        self.va_ = self.config.loadMetadata(self.data_setup_dir_)['va']

    def predict(self, X_test, y_test, out_base_path=None):
        clf_paths = list(filter(lambda x: "Classifier" in x, os.listdir(self.model_dir_)))
        for clf_fn in clf_paths:
            clf_name = os.path.splitext(clf_fn)[0]
            print(f"Classifier={clf_name}")
            clf_path = os.path.join(self.model_dir_, clf_fn)
            with open(clf_path, 'rb') as f:
                clf = pickle.load(f)
            y_pred = clf.predict(X_test)
            if out_base_path is not None:
                result_path = os.path.join(out_base_path, clf_name)
            else:
                result_path = None
            computeMetrics(y_test, y_pred, average='binary', result_path=result_path)

    def run(self):
        sw_df = loadSWs(self.sw_dir_, self.va_)
        print(self.balance_samples)
        if self.balance_samples: sw_df = self.minSample(sw_df)
        print("# Samples:", sw_df.shape[0])
        y = sw_df['label']
        print("Extracting Features...")
        X = self.extractFeaturesDF(sw_df)
        print('Saving results to:', self.current_out_dir)
        self.predict(X, y, out_base_path=self.current_out_dir)

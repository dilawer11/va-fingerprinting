import pandas as pd
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from iotpackage.__vars import dictFeatureGroups, simpleFeatureGroups
from iotpackage.Utils import isSimpleFeature, isDictFeature, getSuffixForGroups
from tqdm import tqdm
from multiprocessing import Pool, Process, Queue
import logging

l = logging.getLogger('FeatureSelection')

class FeatureSelector():
    selectedSimpleFeatureNames = None
    simple_groups = None
    dict_groups = None
    allowed_suffixes = None

    dv_dict_features = {}

    n_all_ = None
    n_tcp_ = None
    n_udp_ = None
    n_proto_ = None
    one_hot_encode = None

    def __init__(self, simple_groups='all', dict_groups='all', n_all=0, n_tcp=100, n_udp=50, n_proto=10, one_hot_encode=False, simple_features=[], dict_features=[], pb=True):
        l.info(f"Feature Selector Initialized: simple_groups: {simple_groups}, dict_groups: {dict_groups}")
        l.info(f"Serialization parameters: n_all: {n_all}, n_tcp: {n_tcp}, n_udp: {n_udp}, n_proto: {n_proto}, one_hot_encode: {one_hot_encode}")
        self.n_all_ = int(n_all)
        self.n_tcp_ = int(n_tcp)
        self.n_udp_ = int(n_udp)
        self.n_proto_ = int(n_proto)
        self.oneHotEncode = bool(one_hot_encode)
        
        self.pb = pb
        self.simple_groups = simple_groups
        self.dict_groups = dict_groups

        self.simple_features = simple_features
        self.dict_features = dict_features
        # if simple_groups == 'all':
        #     self.simple_groups = list(simpleFeatureGroups.keys())
        # else:
        #     self.simple_groups = simple_groups
        
        # if dict_groups == 'all':
        #     self.dict_groups = list(dictFeatureGroups.keys())
        # else:
        #     self.dict_groups = dict_groups

        # all_groups = self.simple_groups + self.dict_groups
        # self.allowed_suffixes = getSuffixForGroups(all_groups)

        self.dv_dict_features = dict()
        return
    
    def setupFeatureGroups(self):
        if self.simple_groups == 'all': 
            self.simple_groups = list(simpleFeatureGroups.keys())
        if self.dict_groups == 'all': 
            self.dict_groups = list(dictFeatureGroups.keys())

        all_groups = self.simple_groups + self.dict_groups
        self.allowed_suffixes = getSuffixForGroups(all_groups)
        return

    def setupIndividualFeatures(self, train_data_features):
        if self.simple_features == 'all':
            self.simple_features = list(filter(lambda x: isSimpleFeature(x), train_data_features))
        if self.dict_features == 'all':
            self.dict_features = list(filter(lambda x: isDictFeature(x), train_data_features))

        self.allowed_features = self.simple_features + self.dict_features
        return
    
    def getNumDictGroups(self):
        return len(self.dictgroups)

    def filterTopN(self, series:pd.Series, top_n:int=None)-> pd.Series:
        if top_n:
            return series.sort_values(ascending=False).iloc[:top_n]
        else:
            return series.sort_values(ascending=False)

    def reduceDicts(self, data_series):
        combined = {}
        def acc(d):
            for k in d:
                str_k = str(k)
                if str_k in combined:
                    combined[str_k] += np.int64(d[k])
                else:
                    combined[str_k] = np.int64(d[k])
        try:
            data_series.apply(acc)
        except:
            l.exception(f'reductDicts')
        finally:
            if not len(combined):
                return pd.Series(combined, dtype='int64')
            else:
                return pd.Series(combined)

    def setVectorizers_Parallel_Helper(self, data_series, top_n, feature, ret_queue):
        series = self.reduceDicts(data_series)
        series = self.filterTopN(series, top_n)
        dv = DictVectorizer(sparse=False)
        dv.fit([series])
        ret_queue.put((dv, feature))
        return

    def isFeatureAllowed(self, featureName):
        # Allow if a feature belongs to an allowed group or allowed feature
        for suffix in self.allowed_suffixes:
            if suffix in featureName:
                return True
        if featureName in self.allowed_features:
            return True
        return False

    def getNForFeature(self, feature):
        if '_dict_protocols' in feature:
            return self.n_proto_
        elif 'tcp_dict' in feature:
            return self.n_tcp_
        elif 'udp_dict' in feature:
            return self.n_udp_
        elif 'all_dict' in feature:
            return self.n_all_
        else:
            raise ValueError(f'No "n" value for feature: {feature}')

    def setVectorizers_Parallel(self, featureData):
        l.info("Setting Vectorizers")
        processes = []
        features = featureData.columns
        for feature in features:
            if self.isFeatureAllowed(feature) and isDictFeature(feature):
                n = self.getNForFeature(feature)
                if n > 0:
                    q = Queue()
                    p = Process(target=self.setVectorizers_Parallel_Helper, args=(featureData[feature], n, feature, q,))
                    processes.append((p,q))
        l.info(f"Dict Features n={len(processes)}")
        for p,_ in processes:
            p.start()

        if self.pb: it = tqdm(processes)
        else: it = processes
        for p,q in it:
            dv, feature = q.get()
            self.dv_dict_features[feature] = dv
            p.join()
            
    def fitSimpleFeatures(self, featureData):
        features = featureData.columns
        self.allowed_simple_features = []
        for feature in features:
            if self.isFeatureAllowed(feature) and isSimpleFeature(feature):
                self.allowed_simple_features.append(feature)
        l.info(f"Simple Features n={len(self.allowed_simple_features)}")
        return

    def transformDictFeatures(self, featureData):
        dicts = []
        features = featureData.columns
        for feature in features:
            if feature in self.dv_dict_features:
                feature_transformed = self.dv_dict_features[feature].transform(featureData[feature])
                if self.one_hot_encode:
                    feature_transformed = np.where(feature_transformed > 0, 1, 0)
                # cols = self.dv_dict_features[feature].get_feature_names_out()
                cols = self.dv_dict_features[feature].feature_names_
                cols = list(map(lambda x: str(feature) + '_' + str(x), cols))
                feature_transformed = pd.DataFrame(feature_transformed, index=featureData.index, columns=cols)
                dicts.append(feature_transformed)
        if len(dicts) == 0:
            return pd.DataFrame([])
        else:
            return pd.concat(dicts, axis=1)

    def transformSimpleFeatures(self, featureData):
        if not isinstance(featureData, pd.DataFrame):
            raise Exception('Expected featureData to be DataFrame given {}'.format(type(featureData)))

        return featureData[self.allowed_simple_features]

    def fit(self, trainFeatureData):
        # Setup Features
        self.setupFeatureGroups()
        self.setupIndividualFeatures(list(trainFeatureData.columns))

        l.info(f'Fitting Features')
        self.fitSimpleFeatures(trainFeatureData)
        self.setVectorizers_Parallel(trainFeatureData)
        

    def transform(self, featureData):
        # Transform the dict features
        l.info('Transforming Dict Features...')
        dictsFeatures = self.transformDictFeatures(featureData)
        l.info('Transforming Simple Features...')
        simpleFeatures = self.transformSimpleFeatures(featureData)
        dictsFeatures_shape = None
        simpleFeatures_shape = None
        if isinstance(dictsFeatures, pd.DataFrame) and isinstance(simpleFeatures, pd.DataFrame):
            dictsFeatures_shape = dictsFeatures.shape
            simpleFeatures_shape = simpleFeatures.shape
            if dictsFeatures_shape[0] == 0:
                allFeatures = simpleFeatures
            elif simpleFeatures_shape[0] == 0:
                allFeatures = dictsFeatures
            elif dictsFeatures_shape[0] == simpleFeatures_shape[0]:
                allFeatures = pd.concat([simpleFeatures, dictsFeatures], axis=1)
            else:
                raise Exception("Errors Unmatching Shapes {} and {}".format(dictsFeatures.shape[0], simpleFeatures.shape[0]))
                
        elif isinstance(dictsFeatures, pd.DataFrame):
            dictsFeatures_shape = dictsFeatures.shape
            allFeatures = dictsFeatures
        elif isinstance(simpleFeatures, pd.DataFrame):
            simpleFeatures_shape = simpleFeatures.shape
            allFeatures = simpleFeatures
        else:
            raise Exception('''No Features Selected Can't Transform Any Features''')    
        dictsFeatures = None
        simpleFeatures = None
        allFeatures.reset_index(drop=True, inplace=True)
        l.info(f'allFeaturesShape: {allFeatures.shape}, dictFeaturesShape: {dictsFeatures_shape}, simpleFeaturesShape: {simpleFeatures_shape}')

        return allFeatures
        
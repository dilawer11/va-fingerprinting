import pandas as pd
import numpy as np
import logging
import pickle
import os
from multiprocessing import cpu_count
from autogluon.tabular import TabularPredictor
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split, KFold, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_curve, roc_auc_score
from xgboost import XGBClassifier

from iotpackage.Utils import perLabelSample, loadFeatureData, getCommonLabelData, renameLabels, findOptimalThreshold, plotAUCCurve, plotCM, storeActualAndPredictVectors, computeMetrics
from iotpackage.FeatureSelection import FeatureSelector
from iotpackage.__vars import ActivityDetectionConfig, ModelTrainConfig


l = logging.getLogger("ModelTraining")

CPU_CORES = cpu_count()
DEFAULT_TEST_SIZE = 0.2

defaultADConf = ActivityDetectionConfig()
defaultMTConf = ModelTrainConfig()

class LabelEncoder:
    label_to_encoded = None
    encoded_to_label = None
    def __init__(self):
        self.label_to_encoded = {}
        self.encoded_to_label = {}
        return

    def fit(self, y):
        y_unique = None
        if isinstance(y, pd.Series):
            y_unique = list(y.unique())
        elif isinstance(y, np.ndarray) or isinstance(y, list):
            y_unique = list(set(y))
        else:
            raise TypeError(f'Unexpected type: {type(y)}')
        for i, label in enumerate(y_unique):
            self.label_to_encoded[label] = i
            self.encoded_to_label[i] = label
        return

    def transform(self, y):
        if isinstance(y, pd.Series):
            return y.apply(lambda x: self.label_to_encoded[x])
        if isinstance(y, np.ndarray) or isinstance(y, list):
            return [self.label_to_encoded[x] for x in y]
        else:
            raise TypeError(f'Unexpected type: {type(y)}')

    def reverse(self, y):
        if isinstance(y, pd.Series):
            return y.apply(lambda x: self.encoded_to_label[x])
        if isinstance(y, np.ndarray) or isinstance(y, list):
            return [self.encoded_to_label[x] for x in y]
        else:
            raise TypeError(f'Unexpected type: {type(y)}')
        
class AutoGluonTabular:
    path = None
    __predictor = None
    def __init__(self, path="auto-gluon"):
        self.path = path
        self.label_col = 'label'

    def fit(self, X, y):
        X['label'] = y
        self.__predictor = TabularPredictor(label=self.label_col, path=self.path)
        self.__predictor.fit(X)
        self.__predictor.delete_models(models_to_keep='best', dry_run=False)
        return

    def load(self):
        self.__predictor = TabularPredictor.load(self.path)
        self.__predictor.persist_models('best')
    
    def predict(self, X):
        return self.__predictor.predict(X)

    def predict_proba(self, X):
        return self.__predictor.predict_proba(X)
    
    def feature_importances(self):
        raise NotImplementedError()

class RFClassifier:
    path = None
    __predictor = None
    def __init__(self, path='random-forest'):
        self.path = path
        self.model_fp = os.path.join(self.path, 'model.pkl')
    
    def load(self):
        if not os.path.exists(self.model_fp): raise FileNotFoundError(f"No model file: {self.model_fp}")
        with open(self.model_fp, 'rb') as f:
            self.__predictor = pickle.load(f)
        return

    def save(self, verbose=True):
        if not os.path.isdir(self.path): os.makedirs(self.path)
        with open(self.model_fp, 'wb') as f:
            pickle.dump(self.__predictor, f)
        if verbose: print('Model saved to:', self.model_fp)
        return

    def fit(self, X, y):
        self.__predictor = RandomForestClassifier(n_estimators=100, n_jobs=CPU_CORES)
        self.__predictor.fit(X, y)
        self.save()
        return

    def predict(self, X):
        return self.__predictor.predict(X)

    def predict_proba(self, X):
        return self.__predictor.predict_proba(X)

    def feature_importances(self):
        if self.__predictor is None: raise Exception(f"Please call 'fit' or 'load' before calling feature importance")
        feature_importances = pd.DataFrame(self.__predictor.feature_importances_, index = list(self.__predictor.feature_names_in_), columns=['importance']).sort_values('importance', ascending=False)
        return feature_importances

class KNNClassifier:
    path = None
    __predictor = None
    def __init__(self, path='knn-classifier'):
        self.path = path
        self.model_fp = os.path.join(self.path, 'model.pkl')
    def load(self):
        if not os.path.exists(self.model_fp): raise FileNotFoundError(f"No model file: {self.model_fp}")
        with open(self.model_fp, 'rb') as f:
            self.__predictor = pickle.load(f)
        return

    def save(self, verbose=True):
        if not os.path.isdir(self.path): os.makedirs(self.path)
        with open(self.model_fp, 'wb') as f:
            pickle.dump(self.__predictor, f)
        if verbose: print('Model saved to:', self.model_fp)
        return

    def fit(self, X, y):
        self.__predictor = KNeighborsClassifier()
        self.__predictor.fit(X, y)
        self.save()
        return

    def predict(self, X):
        return self.__predictor.predict(X)

    def predict_proba(self, X):
        return self.__predictor.predict_proba(X)

    def feature_importances(self):
        raise NotImplementedError()

class XGBoost:
    __predictor = None
    __label_encoder_fn = 'label-encoder.pkl'
    __model_fn = 'model.pkl'
    def __init__(self, path='xgb-boost'):
        self.__label_encoder = LabelEncoder()
        self.path = path
        self.label_encoder_fp = os.path.join(self.path, self.__label_encoder_fn)
        self.model_fp = os.path.join(self.path, self.__model_fn)
        return 
    
    def save(self, verbose=True):
        if not os.path.isdir(self.path): os.makedirs(self.path)
        with open(self.label_encoder_fp, 'wb') as f:
            pickle.dump(self.__label_encoder, f)
            if verbose: print('Label Encoder saved to:', self.label_encoder_fp)
        with open(self.model_fp, 'wb') as f:
            pickle.dump(self.__predictor, f)
            if verbose: print('Model saved to:', self.model_fp)
        return
    
    def load(self, verbose=True):
        with open(self.label_encoder_fp, 'rb') as f:
            self.__label_encoder = pickle.load(f)
        if verbose: print('Label Encoder loaded from:', self.label_encoder_fp)
        with open(self.model_fp, 'rb') as f:
            self.__predictor = pickle.load(f)
        if verbose: print('Model loaded from:', self.model_fp)

    def fit(self, X, y):
        self.__predictor = XGBClassifier()
        self.__label_encoder.fit(y)
        y_encoded = self.__label_encoder.transform(y)
        self.__predictor.fit(X, y_encoded)
        self.save()
        return None

    def predict(self, X):
        y_encoded = self.__predictor.predict(X)
        y = self.__label_encoder.reverse(y_encoded)
        return y

    def predict_proba(self, X):
        return None

    def feature_importances(self):
        raise NotImplementedError()

class ModelTraining:
    mainClassifier = None
    fs = None
    label_col = None
    removeThreshold = 10
    classifier = None

    def __init__(self, fs, label_col='label', classifier=defaultADConf.MODEL_AD_DEFAULT):
        self.classifier = classifier
        self.label_col = label_col
        self.fs = fs

    def initMainClassifier(self, save_path):
        if self.classifier == defaultADConf.MODEL_RFR:
            self.mainClassifier = RFClassifier(save_path)
        elif self.classifier == defaultADConf.MODEL_XGB:
            self.mainClassifier = XGBoost(save_path)
        elif self.classifier == defaultADConf.MODEL_AML:
            self.mainClassifier = AutoGluonTabular(save_path)
        elif self.classifier == defaultADConf.MODEL_KNN:
            self.mainClassifier = KNNClassifier(save_path)
        else:
            raise NotImplementedError(f"Unknown classifier={self.classifier}")

    def removeLessThan(self, threshold, data):
        # Explicity set to device to ensure devices less than the threshold get removed
        vc = data[self.label_col].value_counts()
        return data[data[self.label_col].isin(list(vc[vc >= threshold].index))]
    
    def loadData(self, load_train=True, load_test=True):

        if load_train and self.trainDatasets:
            data_arr = []
            for dataset in self.trainDatasets:
                data = loadFeatureData(dataset)
                data = data[data[self.label_col] != 'stop'].reset_index(drop=True)
                data_arr.append(data)
            train_data = pd.concat(data_arr, ignore_index=True)
            train_data = self.removeLessThan(self.removeThreshold, train_data)
            if self.label_col not in list(train_data.columns):
                raise Exception(f'Label Col: {self.label_col}, not in train_data.columns {list(train_data.columns)}')
        else:
            train_data = None
        if load_test and self.testDatasets:
            data_arr = []
            for dataset in self.testDatasets:
                data = loadFeatureData(dataset)
                data = data[data[self.label_col] != 'stop'].reset_index(drop=True)
                data_arr.append(data)
            test_data = pd.concat(data_arr, ignore_index=True)
            test_data = self.removeLessThan(self.removeThreshold, test_data)
        else:
            test_data = None

        return train_data, test_data
    @staticmethod
    def getFeatureNames(clf, X, n=None, save_path=None, verbose=0):
        try:
            feature_importances = clf.feature_importances()
            if n:
                feature_importances = feature_importances.iloc[:n,:]
            if save_path is not None:
                feature_importances.reset_index(drop=False).to_csv(save_path + '.csv', index=False)
            if verbose:
                print(feature_importances)
            return
        except NotImplementedError:
            print("Feature Importance: Not Implemented")
        except Exception as e:
            l.exception(e)
            print("Feature Importance: Error. See logs")

    @staticmethod
    def getPerLabelMetrics(y_true, y_pred, save_path=None, verbose=0):
        per_label_metrics = pd.DataFrame()
        vc = y_true.value_counts()
        per_label_metrics.loc[:, 'Label'] = list(vc.index)
        precisions, recalls, _ ,_ = precision_recall_fscore_support(y_true, y_pred, labels=list(vc.index), average=None)
        per_label_metrics.loc[:, 'Precision'] = precisions
        per_label_metrics.loc[:, 'Recall'] = recalls
        per_label_metrics.loc[:, 'Count'] = list(vc)
        if save_path is not None:
            per_label_metrics.to_csv(save_path + '.csv', index=False)
        if verbose:
            print(per_label_metrics.to_string())

    @staticmethod
    def getTopErrors(y_true, y_pred, store_file=True, print_details=False, plot_cm=False, save_path=None):
        storeActualAndPredictVectors(y_true, y_pred, save_path=save_path)
        plotCM(y_true, y_pred, store_cm=save_path, plot_cm=plot_cm)
        y_true = np.array(y_true)
        y_pred = np.array(y_pred)
        error_tf = (y_true != y_pred)
        true_labels = y_true[error_tf]
        pred_labels = y_pred[error_tf]
        if true_labels.size != pred_labels.size:
            raise Exception(f'Sizes should be equal {true_labels.size} and {pred_labels.size}')
        counts = pd.DataFrame({
            'True Label': true_labels,
            'Pred Label': pred_labels,
        }).groupby(['True Label', 'Pred Label']).size()
        if print_details:
            print(counts)
        if store_file:
            with open(f'{save_path}.txt', 'a') as f:
                f.write('\n\n')
                f.write('---------------------------------' + '\n')
                f.write(datetime.now().strftime("%d %h %Y %H:%M:%S") + '\n')
                f.write(counts.to_string())
        return counts
        
    def saveFS(self, save_path):
        fs_fp = os.path.join(save_path, 'FeatureSelector.pkl')
        with open(fs_fp, 'wb') as f: pickle.dump(self.fs, f)
        return
        
    @staticmethod
    def getMetrics(y_train_true:pd.Series, y_train_pred:pd.Series, y_test_true:pd.Series, y_test_pred:pd.Series, average:str='macro') -> tuple: 
        if average is None:
            average = 'macro'
        if (y_train_true is not None) and (y_train_pred is not None):
            train_accuracy = accuracy_score(y_train_true, y_train_pred)
        else:
            train_accuracy = None
        if (y_test_true is not None) and (y_test_pred is not None):
            test_accuracy = accuracy_score(y_test_true, y_test_pred)
            [precision, recall, fscore, support] = precision_recall_fscore_support(y_test_true, y_test_pred, average=average)
        else:
            test_accuracy = None
            precision = None
            recall = None
            fscore = None
        return test_accuracy, train_accuracy, precision, recall, fscore
    def printConfig(self):
        print('-------------RUN CONFIG-------------')
        print('Train Datasets    ->', self.trainDatasets)
        print('Test Datasets     ->', self.testDatasets)
        print('Cross Validation  ->', self.cv)
        print('Label             ->', self.label_col)
        print('Run Type          ->', self.runType)
        print('-----------------------------------')

    def fitMainClassifier(self, X, y, features=False, save_path=None):
        X.fillna(0, inplace=True)
        X.reset_index(drop=True, inplace=True)
        y.reset_index(drop=True, inplace=True)
        clf_path = os.path.join(save_path, 'classifier')
        if not os.path.exists(clf_path): os.mkdir(clf_path)
        self.initMainClassifier(save_path=clf_path)
        
        self.mainClassifier.fit(X, y)
        if features: 
            feature_path = os.path.join(save_path, 'feature_importances')
            self.getFeatureNames(self.mainClassifier, X, save_path=feature_path)
        self.saveFS(save_path=save_path)

    def predict(self, X):
        X.reset_index(drop=True, inplace=True)
        return self.mainClassifier.predict(X)
    def predict_probs(self, X):
        preds = self.mainClassifier.predict_proba(X)
        return preds

    def main(self, train_data, test_data=None, print_metrics=True, errors=True, features=True, save_path=None, plot_cm=False, per_label_metrics=None, metric_average="macro"):
        if isinstance(train_data, pd.DataFrame):
            y_train = train_data[self.label_col]
            self.fs.fit(train_data)
            X_train = self.fs.transform(train_data)
            self.fitMainClassifier(X_train, y_train, features=features, save_path=save_path)
            y_train_pred = self.predict(X_train)
            computeMetrics(y_train, y_train_pred, average=metric_average, print_metrics=print_metrics, result_path=os.path.join(save_path, "TrainMetrics"))
        else:
            raise ValueError(f'train_data should be pd.DataFrame given {type(train_data)}')
        if isinstance(test_data, pd.DataFrame):
            X_test = self.fs.transform(test_data)
            y_test = test_data[self.label_col]
            y_test_pred = self.predict(X_test)
            computeMetrics(y_test, y_test_pred, average=metric_average, print_metrics=True, result_path=os.path.join(save_path, "TestMetrics"))
            if errors:
                self.getTopErrors(y_test, y_test_pred, plot_cm=plot_cm, save_path=os.path.join(save_path, 'top-errors'))
            if per_label_metrics and y_test_pred is not None:
                self.getPerLabelMetrics(y_test, y_test_pred, save_path=os.path.join(save_path, 'per_label'), verbose=0)
        else:
            X_test = None
            y_test = None
            y_test_pred = None
        

class SimpleClassifier(ModelTraining):
    cv = None
    metrics_per_label = None
    def __init__(self, train_datasets=None, test_datasets=None, classifier=defaultADConf.MODEL_AD_DEFAULT, fs=None, cv=defaultMTConf.CV, label_col=defaultMTConf.LABEL_COL, print_details=True, metrics_per_label=False, test_size=DEFAULT_TEST_SIZE):
        ModelTraining.__init__(self, fs=fs, label_col=label_col, classifier=classifier)
        if not train_datasets:
            raise ValueError(f'Atleast 1 dataset must be provided passed = {train_datasets}')
        else:
            self.trainDatasets = train_datasets
        self.cv = cv
        self.runType = 'Simple Classifer'
        self.testDatasets = None
        self._testSize = test_size

    def run(self, result_path=None, errors=defaultMTConf.ERRORS, runs=defaultMTConf.RUNS, sample_size=None, features=defaultMTConf.FEATURES, plot_cm=defaultMTConf.PLOT_CM):
        self.printConfig()
        data, _ = self.loadData(load_test=False)
                
        for r in range(runs):
            data = data.sample(frac=1).reset_index(drop=True)
            if self.cv > 0:
                cv_i = 0
                kf = StratifiedKFold(n_splits=self.cv)
                for train_index, test_index in kf.split(data, data[self.label_col]):
                    cv_i += 1
                    l.info(f"Run: {r}, 'CV_i: {cv_i}")
                    train_data = data.iloc[train_index]
                    test_data = data.iloc[test_index]
                    if sample_size is not None:
                        train_data = train_data.groupby(self.label_col, as_index=False).head(sample_size)
                    cur_save_path = os.path.join(result_path, f"{r}-{cv_i}")
                    if not os.path.isdir(cur_save_path): os.mkdir(cur_save_path)
                    self.main(train_data, test_data, features=features, print_metrics=False, errors=errors, per_label_metrics=self.metrics_per_label, plot_cm=plot_cm, save_path=cur_save_path)
                    
            else:
                if self._testSize > 0:
                    train_data, test_data = train_test_split(data, test_size=self._testSize)
                else:
                    train_data, test_data = data, None
                
                if sample_size is not None:
                    train_data = train_data.groupby(self.label_col, as_index=False).head(sample_size)
                    print(f'Sampled to Sample Size\n\tTotal Train Samples {train_data.shape[0]}\n\tUnique Labels {train_data[self.label_col].nunique()}\n\tSample Size{sample_size}')
                cur_save_path = os.path.join(result_path, f"{r}-R")
                if not os.path.isdir(cur_save_path): os.mkdir(cur_save_path)
                self.main(train_data, test_data, print_metrics=False, errors=errors, features=features, per_label_metrics=self.metrics_per_label, plot_cm=plot_cm, save_path=cur_save_path)
                
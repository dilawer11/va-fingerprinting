import os
from multiprocessing import Pool, cpu_count
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.ensemble import RandomForestClassifier
import argparse
from tqdm import tqdm
from sklearn.model_selection import train_test_split

from iotpackage.FeatureSelection import FeatureSelector
import iotpackage.Utils as utils
import iotpackage.__vars as ivar
from iotpackage.ModelTraining import AutoGluonTabular

class FFS:
    """
    Forward feature selection implementation
    """
    stop_depth = None
    clf = None
    def __init__(self, output_path=None, level='feature', stop_depth=None, common=True, label_col='label', clf='rf'):
        self.stop_depth = stop_depth
        self.common = common
        self.label_col = label_col
        self.level = level
        
        self.clf = clf

        if output_path is None: 
            output_path = 'ffs'
            if os.path.isdir(output_path): raise FileExistsError(f"Default output directory already exists")
            else: os.mkdir(output_path)
    
        if not os.path.isdir(output_path):
            raise FileNotFoundError(f"No directory found: {output_path}")

        self.output_path = os.path.join(output_path, f'ffs_feature-{utils.getDateTimeString()}')
        os.mkdir(self.output_path)

    def get_features(self, feature_names):
        simple_features = set(list(filter(lambda x: utils.isSimpleFeature(x), feature_names)))
        dict_features = set(list(filter(lambda x: utils.isDictFeature(x), feature_names)))
        return simple_features, dict_features
            
    def is_simple_group(self, group_name):
        return group_name in ivar.simpleFeatureGroups
    
    def is_dict_group(self, group_name):
        return group_name in ivar.dictFeatureGroups
    
    def get_groups(self, feature_names):
        self.group_feature_mapping = {}
        simple_groups = set()
        dict_groups = set()
        for feature in feature_names:
            if feature == 'label': continue
            group, group_type = utils.getFeatureGroup(feature, True)
            if group not in self.group_feature_mapping: self.group_feature_mapping[group] = []
            self.group_feature_mapping[group].append(feature)
            if group_type == 'simple':
                simple_groups.add(group)
            elif group_type == 'dict':
                dict_groups.add(group)
        return simple_groups, dict_groups

    def all_group_features(self, group_names):
        features = []
        for group_name in group_names:
            group_features = self.group_feature_mapping[group_name]
            features.extend(group_features)
        return features
    
    def stop_depth_reached(self, cntr):
        if self.stop_depth is None: return False
        elif cntr < self.stop_depth: return False
        else: return True

    def log_individual_feature_results(self, iv_result, cntr):
        output_path = os.path.join(self.output_path, f'ifr_{cntr}.csv')
        data = pd.DataFrame(iv_result)
        data.to_csv(output_path, index=False)
        return

    def get_clf(self):
        if self.clf == 'rf':
            return RandomForestClassifier()
        elif self.clf == 'automl':
            return AutoGluonTabular()
        
    def serializedFeatureFromFeatureName(self, feature_name):
        return list(filter(lambda x: feature_name in x, self.serialized_features))
    
    def allSerializedFeaturesFromFeatureNames(self, feature_names):
        ret = []
        for feature_name in feature_names:
            sf = self.serializedFeatureFromFeatureName(feature_name)
            ret.extend(sf)
        return ret
    
    def train_evaluate(self, feature):
        if self.level == 'feature':
            if utils.isSimpleFeature(feature):
                feature_type = 'simple'
            elif utils.isDictFeature(feature):
                feature_type = 'dict'
            else:
                raise Exception(f"Unknown feature={feature}")
                
        elif self.level == 'group':
            if self.is_simple_group(feature):
                feature_type = 'simple'
            elif self.is_dict_group(feature):
                feature_type = 'dict'
        
        fs_simple_features = list(self.selected_simple_features)
        fs_dict_features = list(self.selected_dict_features)
        
        if feature_type == 'simple': fs_simple_features.append(feature)
        elif feature_type == 'dict': fs_dict_features.append(feature)
        
        if self.level == 'feature':
            run_features = fs_simple_features + fs_dict_features
        elif self.level == 'group':
            run_features = self.all_group_features(fs_simple_features + fs_dict_features)
            
        current_features = self.allSerializedFeaturesFromFeatureNames(run_features)
        run_X_train = self.X_train.loc[:, current_features]
        run_X_val = self.X_val.loc[:, current_features]
        run_X_test = self.X_test.loc[:, current_features]
        
        clf = self.get_clf()
        if not run_X_train.shape[1]: return None
        clf.fit(run_X_train, self.y_train)
        y_val_pred = clf.predict(run_X_val)
        y_train_pred = clf.predict(run_X_train)
        y_test_pred = clf.predict(run_X_test)
        val_metrics = utils.computeMetrics(self.y_val, y_val_pred, print_metrics=False, more_metrics=False, average='macro', zero_division=0)
        test_metrics = utils.computeMetrics(self.y_test, y_test_pred, print_metrics=False, more_metrics=False, average='macro', zero_division=0)
        train_acc = accuracy_score(self.y_train, y_train_pred)
        
        return feature, feature_type, val_metrics, test_metrics, train_acc
    
    def common_data(self, train_data, val_data=None, test_data=None):
        # initially set to train labels
        common_labels = set(train_data[self.label_col].unique())
        
        if val_data is not None:
            val_labels = set(val_data[self.label_col].unique())
            common_labels = common_labels & val_labels

        if test_data is not None:
            test_labels = set(test_data[self.label_col].unique())
            common_labels = common_labels & test_labels

        train_data = train_data[train_data[self.label_col].isin(common_labels)].reset_index(drop=True)
        if val_data is not None: val_data = val_data[val_data[self.label_col].isin(common_labels)].reset_index(drop=True)
        if test_data is not None: test_data = test_data[test_data[self.label_col].isin(common_labels)].reset_index(drop=True)
        return train_data, val_data, test_data
    
    def fit(self, train_data, val_data, test_data):
        if self.common: train_data ,val_data, test_data = self.common_data(train_data=train_data, val_data=val_data, test_data=test_data)
        
        cntr = 0
        if self.level == 'feature':
            simple_features, dict_features = self.get_features(train_data.columns.to_list())
        elif self.level == 'group':
            simple_features, dict_features = self.get_groups(train_data.columns.to_list())
            
        self.selected_simple_features = set()
        self.selected_dict_features = set()
        

        fs = FeatureSelector(pb=False)
        fs.fit(train_data)

        self.X_train = fs.transform(train_data).fillna(0)
        self.X_val = fs.transform(val_data).fillna(0)
        self.X_test = fs.transform(test_data).fillna(0)
        self.y_train = train_data[self.label_col]
        self.y_val = val_data[self.label_col]
        self.y_test = test_data[self.label_col]
        
        # self.all_features = list(simple_features) + list(dict_features)
        self.serialized_features = list(self.X_train.columns)
        
        results = {
            'feature_name': [],
            'feature_type': [],
            'trn_acc': [],
            'val_acc': [],
            'tst_acc': [],
        }

        results_path = os.path.join(self.output_path, 'results.csv')

        if self.stop_depth is not None:
            total = self.stop_depth
        else:
            total = len(simple_features) + len(dict_features)
        pbar_runs = tqdm(total=total, position=0, leave=True)
        
        while (len(simple_features) or len(dict_features)) and not self.stop_depth_reached(cntr):
            pbar_runs.update(cntr - pbar_runs.n)
            cntr += 1
            individual_feature_results = {
                'feature_type': [],
                'feature': [],
                'val_acc': [],
                'val_prs': [],
                'val_rcl': [],
                'tst_acc': [],
                'tst_prs': [],
                'tst_rcl': [],
                'trn_acc': [],
                '#labels': [],
            }
                        
            max_feature_type = None
            max_feature_name = None
            max_feature_val_acc = 0
            max_feature_train_acc = 0
            max_feature_test_acc = 0
            all_features = list(simple_features) + list(dict_features)
            
            p = Pool(cpu_count())
            evaluations = p.imap_unordered(self.train_evaluate, all_features)
            for evaldata in tqdm(evaluations, total=len(all_features), leave=False, position=1):
                if evaldata is None: continue
                feature = evaldata[0]
                feature_type = evaldata[1]
                val_metrics = evaldata[2]
                test_metrics = evaldata[3]
                trn_acc = evaldata[4]
                individual_feature_results['feature_type'].append(feature_type)
                individual_feature_results['feature'].append(feature)
                individual_feature_results['val_acc'].append(val_metrics['Accuracy'])
                individual_feature_results['val_prs'].append(val_metrics['Precision'])
                individual_feature_results['val_rcl'].append(val_metrics['Recall'])
                individual_feature_results['tst_acc'].append(test_metrics['Accuracy'])
                individual_feature_results['tst_prs'].append(test_metrics['Precision'])
                individual_feature_results['tst_rcl'].append(test_metrics['Recall'])
                individual_feature_results['trn_acc'].append(trn_acc)
                individual_feature_results['#labels'].append(val_metrics['#Labels'])
                
                if val_metrics['Accuracy'] > max_feature_val_acc:
                    max_feature_val_acc = val_metrics['Accuracy']
                    max_feature_train_acc = trn_acc
                    max_feature_name = feature
                    max_feature_type = feature_type
                    max_feature_test_acc = test_metrics['Accuracy']
                          
            self.log_individual_feature_results(individual_feature_results, cntr=cntr)
            results['feature_name'].append(max_feature_name)
            results['feature_type'].append(max_feature_type)
            results['trn_acc'].append(max_feature_train_acc)
            results['val_acc'].append(max_feature_val_acc)
            results['tst_acc'].append(max_feature_test_acc)
            #tqdm.write(str(results))
            pd.DataFrame(results).to_csv(results_path, index=False)
            
            if max_feature_type == 'dict':
                dict_features.remove(max_feature_name)
                self.selected_dict_features.add(max_feature_name)
            elif max_feature_type == 'simple':
                simple_features.remove(max_feature_name)
                self.selected_simple_features.add(max_feature_name)
            else:
                raise Exception(f'Unknown max_feature_type={max_feature_type}')
            

def main(args):

    train_data = pd.read_pickle(args.train_data_path).fillna(0)
    if (args.val_data_path is not None):
        val_data = pd.read_pickle(args.val_data_path).fillna(0)
    else:
        train_data, val_data = train_test_split(train_data, test_size=0.1)
        train_data = train_data.reset_index(drop=True)
        val_data = val_data.reset_index(drop=True)

    if (args.test_data_path is not None):
        test_data = pd.read_pickle(args.test_data_path).fillna(0)
    else:
        test_data = val_data.copy()

    ffs = FFS(output_path=args.output_path, level=args.level, stop_depth=None, common=True)
    ffs.fit(train_data=train_data, val_data=val_data, test_data=test_data)
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--train', dest='train_data_path', type=str, required=True, help='The path to train data pkl file (not the input directory)')
    parser.add_argument('--val', dest='val_data_path', required=False, type=str, help='the path to val data pkl (not the input directory). Uses the train data portion as val if not provided')
    parser.add_argument('--test', dest='test_data_path', required=False, type=str, help='the path to test data pkl (not the input directory). Uses the val data as test if not provided')
    parser.add_argument('-o', dest='output_path', required=False, type=str, help="The output path directory.")
    parser.add_argument('--level', dest='level', default='group', type=str, help="The level to perform the ffs at. 'group' incrementally adds groups, 'feature' incrementally adds features.")
    args = parser.parse_args()
    main(args)
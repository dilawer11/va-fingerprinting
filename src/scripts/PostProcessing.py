import os
import pandas as pd
import argparse

import iotpackage.__vars as ivars

default_ad_config = ivars.ActivityDetectionConfig()
default_id_config = ivars.InvocationDetectionConfig()

class ActivityDetectionTable:
    datasets_to_include = None
    data_dir_path = None
    ad_config = None

    def __init__(self, data_dir_path, datasets_to_include='all', ad_config=default_ad_config):
        self.data_dir_path = data_dir_path
        self.ad_config = ad_config


        if datasets_to_include == 'all':
            self.datasets_to_include = self.loadAllDatasetNames()
        else:
            self.datasets_to_include = datasets_to_include

    def loadAllDatasetNames(self):
        dataset_names = os.listdir(self.data_dir_path)
        return dataset_names
    
    def loadMetricsForDataset(self, dataset_name):
        input_dir = os.path.join(self.data_dir_path, dataset_name)
        act_dir_path = self.ad_config.ACTIVITYDETECTION_PATH(input_dir)
        if not os.path.exists(act_dir_path): raise FileNotFoundError(f"Activity Detection Dir not found, act_dir_path={act_dir_path}")

        # Check or create 'setup' directory
        setup_name = self.ad_config.GET_SETUP_NAME()
        setup_dir = self.ad_config.SETUP_PATH(act_dir_path, setup_name)
        if not os.path.isdir(setup_dir): raise FileNotFoundError(f"setup_dir={setup_dir} not found")

        clf_path = self.ad_config.CLASSIFIER_PATH(setup_dir)
        if not os.path.isdir(clf_path):
            raise FileNotFoundError(f"clf_path='{clf_path}' does not exist")

        model_clf_path = os.path.join(clf_path, self.ad_config.MODEL_AD_DEFAULT)
        if not os.path.isdir(model_clf_path):
            raise FileNotFoundError(f"model_clf_path='{model_clf_path}' does not exist")

        run_path = os.path.join(model_clf_path, '0-R')
        if not os.path.isdir(run_path):
            raise FileNotFoundError(f"run_path='{run_path}' does not exist")

        metrics_fp = os.path.join(run_path, 'TestMetrics.csv')
        if not os.path.exists(metrics_fp):
            raise FileNotFoundError(f"metrics_fp={metrics_fp} not found")
        
        metrics_data = pd.read_csv(metrics_fp)

        metrics_data = metrics_data.set_index('metric')['score'].to_dict()
        return metrics_data        

    def run(self, save_path=None):
        metric_keys = ['Accuracy', 'Precision', 'Recall', '#Labels']
        all_metric_data = {
            'Datasets': [],
        }

        for metric_key in metric_keys: all_metric_data[metric_key] = []
        for dataset_name in self.datasets_to_include:
            try:
                metrics_data = self.loadMetricsForDataset(dataset_name)
                for metric_key in metric_keys: all_metric_data[metric_key].append(metrics_data[metric_key])
                all_metric_data['Datasets'].append(dataset_name)
            except FileNotFoundError:
                print(f"No Activity Detection Results found for: {dataset_name}. Skipping this")

        data = pd.DataFrame(all_metric_data)
        print(f"\n{str(data)}")

        if save_path is not None:
            save_fp = os.path.join(save_path, 'ad-table.csv')
            data.to_csv(save_fp, index=False)
            print(f"Saved table to: {save_fp}")
        return

class InvocationDetectionTable:
    datasets_to_include = None
    data_dir_path = None
    id_config = None

    def __init__(self, data_dir_path, datasets_to_include='all', id_config=default_id_config):
        self.data_dir_path = data_dir_path
        self.id_config = id_config


        if datasets_to_include == 'all':
            self.datasets_to_include = self.loadAllDatasetNames()
        else:
            self.datasets_to_include = datasets_to_include

    def loadAllDatasetNames(self):
        dataset_names = os.listdir(self.data_dir_path)
        return dataset_names
    
    def loadMetricsForDataset(self, dataset_name):
        input_dir = os.path.join(self.data_dir_path, dataset_name)
        id_dir_path = self.id_config.INVOCATIONDETECTION_PATH(input_dir)
        if not os.path.exists(id_dir_path): raise FileNotFoundError(f"Invocation Detection Dir not found, id_dir_path={id_dir_path}")

        # Check or create 'setup' directory
        setup_name = self.id_config.GET_SETUP_NAME()
        setup_dir = self.id_config.SETUP_PATH(id_dir_path, setup_name)
        if not os.path.isdir(setup_dir): raise FileNotFoundError(f"setup_dir={setup_dir} not found")

        res_path = self.id_config.RESULTS_PATH(setup_dir)
        if not os.path.isdir(res_path):
            raise FileNotFoundError(f"res_path='{res_path}' does not exist")

        res_fns = os.listdir(res_path)
        for res_fn in res_fns:
            model_name = res_fn.replace('.csv', '')
            res_fp = os.path.join(res_path, res_fn)
            metrics_data = pd.read_csv(res_fp)
            metrics_data = metrics_data.set_index('metric')['score'].to_dict()
            for metric_key in self.metric_keys: self.all_metric_data[metric_key].append(metrics_data[metric_key])
            self.all_metric_data['Datasets'].append(dataset_name)
            self.all_metric_data['Models'].append(model_name)    

    def run(self, save_path=None):

        self.metric_keys = ['Accuracy', 'Precision', 'Recall', '#Labels']
        self.all_metric_data = {
            'Datasets': [],
            'Models': [],
        }

        for metric_key in self.metric_keys: self.all_metric_data[metric_key] = []

        for dataset_name in self.datasets_to_include:
            try:
                self.loadMetricsForDataset(dataset_name)
            except FileNotFoundError:
                print(f"No Invocation Detection Results found for: {dataset_name}. Skipping this")

        data = pd.DataFrame(self.all_metric_data)
        print(f"\n{str(data)}")

        if save_path is not None:
            save_fp = os.path.join(save_path, 'id-table.csv')
            data.to_csv(save_fp, index=False)
            print(f"Saved table to: {save_fp}")
        return

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="choose a command", required=True, dest='subcommand')

    ad_table_parser = subparsers.add_parser('ad-table', help="Creates an Activity Detection results table")
    ad_table_parser.add_argument("-o", dest="save_path", default=None, help="Provide the path of a root directory to save the resulting CSV table")
    ad_table_parser.add_argument("-d", dest="data_dir", type=str, required=True, help="Dataset directory")

    id_table_parser = subparsers.add_parser('id-table', help="Creates an Invocation Detection results table")
    id_table_parser.add_argument("-o", dest="save_path", default=None, help="Provide the path of a root directory to save the resulting CSV table")
    id_table_parser.add_argument("-d", dest="data_dir", type=str, required=True, help="Dataset directory")

    args = parser.parse_args()

    if args.subcommand == "ad-table":
        p = ActivityDetectionTable(data_dir_path=args.data_dir)
        p.run(args.save_path)
    elif args.subcommand == "id-table":
        p = InvocationDetectionTable(data_dir_path=args.data_dir)
        p.run(args.save_path)

if __name__ == "__main__":
    main()
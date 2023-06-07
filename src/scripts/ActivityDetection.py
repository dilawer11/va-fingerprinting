import os
import argparse
import json
import logging
from multiprocessing import Pool, cpu_count
import pandas as pd
from tqdm import tqdm

import iotpackage.ModelTraining as mt
from iotpackage.FeatureSelection import FeatureSelector
from iotpackage.FeatureExtraction import FeatureExtracter
from iotpackage.Utils import labelledCSVFileLoader, loadFeatureData, computeMetrics
from iotpackage.ActivityDetection.CSV2Windows import CSV2Windows
from iotpackage.__vars import ActivityDetectionConfig, FeatureSelectorConfig, ModelTrainConfig


def loadConfigFromPath(config_path):
    with open(config_path, 'r') as f:
        config_data = json.load(f)
    return config_data


def loadConfig(config_name, config_dir=None):
    if config_dir is None:
        IOTBASE = os.getenv('IOTBASE')
        if IOTBASE is None:
            raise ValueError(f"Environment Variable 'IOTBASE' not set")
        config_dir = os.path.join(IOTBASE, 'model_configs')
    config_path = os.path.join(config_dir, config_name)
    return loadConfigFromPath(config_path)


def getParentDir(path):
    return os.path.split(path)[0]


def parentDirExists(path):
    parentDir = getParentDir(path)
    return os.path.exists(parentDir)


def createParentDir(path):
    parentDir = getParentDir(path)
    os.makedirs(parentDir)
    return


def runClassifier(config=''):
    if config != '':
        config_data = loadConfigFromPath(config)
    else:
        config_data = loadConfig('SimpleClassifier.json')
    result_path = os.path.join(IOTBASE, config_data['output_path'])
    if not parentDirExists(result_path):
        createParentDir(result_path)

    print(f'Running SimpleClassifier')
    print(f"result_path: {result_path}", flush=True)
    fs = FeatureSelector(simple_groups=config_data['simple_groups'],
                              dict_groups=config_data['dict_groups'],
                              n_all=config_data['n_all'],
                              n_tcp=config_data['n_tcp'],
                              n_udp=config_data['n_udp'],
                              n_proto=config_data['n_proto'],
                              one_hot_encode=config_data['one_hot_encode'])
    model = mt.SimpleClassifier(fs=fs, train_datasets=config_data['train_dataset_paths'],
                                cv=config_data['cv'], label_col=config_data['label_col'], classifier=config_data['classifier'])
    model.run(result_path, errors=config_data['errors'], plot_cm=config_data['plot_cm'],
              runs=config_data['runs'], features=config_data['features'])

# def extractFeaturesFromCSV(label, csv_path):
#     # Sanity Checks
#     if not os.path.exists(csv_path):
#         raise FileNotFoundError(f'No such file found: {csv_path}')
#     print(f"Processing: {csv_path}, Label: {label}")
#
#     # Load the packets from csv file
#     packets = pd.read_csv(csv_path)
#
#     # Extract The Features
#     fe = FeatureExtracter()
#     feature_data = fe.run(packets)
#     feature_data['label'] = label
#     
#     return feature_data

def extractFeaturesFromCSV(args):
    label = args[0]
    csv_path = args[1]

    # Sanity Checks
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f'No such file found: {csv_path}')

    # Load the packets from csv file
    packets = pd.read_csv(csv_path)
    
    # Extract The Features
    fe = FeatureExtracter()
    feature_data = fe.run(packets)
    feature_data['label'] = label
    
    return feature_data

def CSV2FeatureData(csv_dir, ir_dir, feature_data_path, max_jobs):
    # Load the labelled CSV file list for feature extraction
    labelled_csv_list = labelledCSVFileLoader(csv_dir, ir_dir)

    print("Extracting Features from CSV files...")
    # Create a job pool for parralel feature extraction
    pool = Pool(max_jobs)
    # feature_data = pool.starmap(extractFeaturesFromCSV, labelled_csv_list)
    feature_data = list(tqdm(pool.imap(extractFeaturesFromCSV, labelled_csv_list), total=len(labelled_csv_list)))
    pool.close()
    pool.join()

    print("Saving features...")
    # Save the feature data to a file
    feature_data = pd.concat(feature_data, ignore_index=True)
    _, oext = os.path.splitext(feature_data_path)
    if oext == '.pkl':
        feature_data.to_pickle(feature_data_path)
    elif oext == '.json':
        feature_data.to_json(feature_data_path)

    print("Features saved to:", feature_data_path)
    return

def mainWindows(args):
    config = ActivityDetectionConfig(new_flow_win_width=args.new_flow_win_width, hostname_method=args.hostname_method, inactive_flow_timeout=args.inactive_flow_timeout, active_flow_timeout=args.active_flow_timeout)
    input_dir = args.input_dir
    if not os.path.isdir(args.input_dir): raise FileNotFoundError(f'input_dir not found: {args.input_dir}. Did you enter the correct path to the input base directory?')
    
    csv_input_dir = config.CAPTURES_CSV_PATH(input_dir)
    if not os.path.isdir(csv_input_dir): raise FileNotFoundError(f'csv_input_dir not found: {csv_input_dir}. Did you run PCAP2CSV script on this input directory')

    ir_base_path = config.IR_PATH(input_dir)
    if not os.path.exists(ir_base_path): raise FileNotFoundError(f'ir_base_path not found: {ir_base_path}. It seems like invoke records are missing/not where expected')

    act_dir_path = config.ACTIVITYDETECTION_PATH(input_dir)
    if not os.path.exists(act_dir_path): os.mkdir(act_dir_path)

    # Check or create 'setup' directory
    setup_name = config.GET_SETUP_NAME()
    setup_dir = config.SETUP_PATH(act_dir_path, setup_name)
    if os.path.exists(setup_dir): raise FileExistsError(f"setup_dir={setup_dir} already exists. Change or remove before continuing.")
    else: os.makedirs(setup_dir)

    output_path = config.EVENTWIN_PATH(setup_dir)
    if os.path.exists(output_path): raise FileExistsError(f"output_path={output_path} already exists. Change or remove before proceeding.")
    else: os.mkdir(output_path)

    l_path = os.path.join(setup_dir, 'ActivityDetection_windows.log')
    print('logging_path:', l_path)
    logging.basicConfig(filename=l_path, filemode='w+',
                        level=logging.INFO, force=True)
    l = logging.getLogger("CSV2Windows")
    l.info("Starting...")

    e = CSV2Windows(target_ips=config.TARGET_IPS, protos=config.PROTOS, hostname_method=config.HOSTNAME_METHOD, inactive_flow_timeout=config.INACTIVE_FLOW_TIMEOUT, active_flow_timeout=config.ACTIVE_FLOW_TIMEOUT, new_flow_win_width=config.NEW_FLOW_WIN_WIDTH)
    e.run(input_dir=args.input_dir, ir_base_path=ir_base_path, output_path=output_path)

def mainFeatures(args):
    config = ActivityDetectionConfig()
    if not os.path.isdir(args.input_dir):
        raise FileNotFoundError(f"input_dir={args.input_dir} not found.")

    actdet_dir = config.ACTIVITYDETECTION_PATH(args.input_dir)
    if not os.path.isdir(actdet_dir):
        raise FileNotFoundError(f"actdet_dir={actdet_dir} not found. Did you create windows?")

    setup_dir = config.SETUP_PATH(actdet_dir, args.setup_name)
    if not os.path.isdir(setup_dir):
        raise FileNotFoundError(f"setup_dir={setup_dir} not found. Did you create windows with this setup?")

    csv_dir = config.EVENTWIN_PATH(setup_dir)
    if not os.path.isdir(csv_dir):
        raise FileNotFoundError(f"csv_dir={csv_dir} not found. Did you create windows with this setup?")

    ir_dir = config.IR_PATH(args.input_dir)
    if not os.path.isdir(ir_dir):
        raise FileNotFoundError(f"ir_dir={ir_dir} not found. Did you enter the correct path?")

    feature_data_path = config.FEATUREDATA_PATH(setup_dir)

    # Extract features and combine feature files
    CSV2FeatureData(csv_dir=csv_dir, ir_dir=ir_dir, feature_data_path=feature_data_path, max_jobs=args.max_jobs)

def mainTrain(args):
    if not os.path.isdir(args.input_dir):
        raise FileNotFoundError(f"input_dir='{args.input_dir}' does not exist")
    
    # Setup feature selector config
    fs_config = FeatureSelectorConfig()
    if args.fs_config != "":
        if not os.path.exists(args.fs_config): raise FileNotFoundError(f"fs_config='{args.fs_config}' does not exist")
        fs_config.parseFromConfig(args.fs_config)
    
    # Setup model training config
    mt_config = ModelTrainConfig()
    if args.mt_config != "":
        if not os.path.exists(args.mt_config): raise FileNotFoundError(f"mt_config='{args.mt_config}' does not exist")
        mt_config.parseFromConfig(args.mt_config)

    config = ActivityDetectionConfig()
    config.PARSE_SETUP_NAME(args.setup_name)

    actdet_path = config.ACTIVITYDETECTION_PATH(args.input_dir)
    if not os.path.isdir(actdet_path):
        raise FileNotFoundError(f"actdet_path='{actdet_path}' does not exist or is not a directory.")
    
    setup_path = config.SETUP_PATH(actdet_path, args.setup_name)
    if not os.path.isdir(setup_path):
        raise FileNotFoundError(f"setup_path='{setup_path}' does not exist or is not a directory.")
    

    clf_path = config.CLASSIFIER_PATH(setup_path)
    if os.path.isdir(clf_path):
        raise FileExistsError(f"clf_path='{clf_path}' already exists. Remove before continuing.")
    else:
        os.mkdir(clf_path)
    
    fdata_path = config.FEATUREDATA_PATH(setup_path)

    if args.test_size > 0.5 or args.test_size < 0:
        raise ValueError(f"test_size={args.test_size} is not correct. Should be between 0 and 0.5 inclusive")
   
    # Train using AutoML model (AutoGluon Tabular)
    model_name = config.MODEL_AML
    result_path = config.CLASSIFIER_RESULT_PATH(clf_path, model_name)
    if os.path.isdir(result_path): raise FileExistsError(f"result_path='{result_path}' exists already.")
    else: os.mkdir(result_path)
    fs = FeatureSelector(simple_groups=fs_config.SIMPLE_GROUPS,
                            dict_groups=fs_config.DICT_GROUPS,
                            n_all=fs_config.N_ALL,
                            n_tcp=fs_config.N_TCP,
                            n_udp=fs_config.N_UDP,
                            n_proto=fs_config.N_PROTO,
                            one_hot_encode=fs_config.ONE_HOT_ENCODE)
    model = mt.SimpleClassifier(fs=fs, train_datasets=[fdata_path],
                                cv=mt_config.CV, label_col=mt_config.LABEL_COL, classifier=model_name, test_size=args.test_size)
    model.run(result_path=result_path, errors=mt_config.ERRORS, plot_cm=mt_config.PLOT_CM,
            runs=mt_config.RUNS, features=mt_config.FEATURES)

def mainInfer(args):
    if not os.path.isdir(args.input_dir):
        raise FileNotFoundError(f"input_dir='{args.input_dir}' does not exist")
    
    if not os.path.isdir(args.model_input_dir):
        raise FileNotFoundError(f"input_dir='{args.model_input_dir}' does not exist")

    # Setup model training config
    mt_config = ModelTrainConfig()

    config = ActivityDetectionConfig()
    config.PARSE_SETUP_NAME(args.setup_name)

    actdet_path = config.ACTIVITYDETECTION_PATH(args.input_dir)
    if not os.path.isdir(actdet_path):
        raise FileNotFoundError(f"actdet_path='{actdet_path}' does not exist or is not a directory.")

    model_actdet_path = config.ACTIVITYDETECTION_PATH(args.model_input_dir)
    if not os.path.isdir(model_actdet_path):
        raise FileNotFoundError(f"actdet_path='{model_actdet_path}' does not exist or is not a directory.")
    
    setup_path = config.SETUP_PATH(actdet_path, args.setup_name)
    if not os.path.isdir(setup_path):
        raise FileNotFoundError(f"setup_path='{setup_path}' does not exist or is not a directory.")

    model_setup_path = config.SETUP_PATH(model_actdet_path, args.model_setup_name)
    if not os.path.isdir(model_setup_path):
        raise FileNotFoundError(f"setup_path='{model_setup_path}' does not exist or is not a directory.")
    
    clf_path = config.CLASSIFIER_PATH(setup_path)
    if not os.path.isdir(clf_path):
        os.mkdir(clf_path)

    model_clf_path = config.CLASSIFIER_PATH(model_setup_path)
    if not os.path.isdir(model_clf_path):
        raise FileNotFoundError(f"clf_path='{model_clf_path}' does not exist")
    
    fdata_path = config.FEATUREDATA_PATH(setup_path)

    clf = args.model_model_name
    result_path = config.CLASSIFIER_RESULT_PATH(clf_path, clf)
    if not os.path.isdir(result_path): os.mkdir(result_path)
    result_path = os.path.join(result_path, 'infer')
    print('model_setup_path:', model_setup_path)
    print('model_clf_path:', model_clf_path)
    fs_path = os.path.join(model_clf_path, clf, '0-R', 'FeatureSelector.pkl')
    fs = pd.read_pickle(fs_path)

    model_path = os.path.join(model_clf_path, clf, '0-R', 'classifier')

    if clf == config.MODEL_AML:
        model = mt.AutoGluonTabular(model_path)
        model.load()
    elif clf == config.MODEL_RFR:
        model = mt.RFClassifier(model_path)
        model.load()
    else:
        raise NotImplementedError()

    data = loadFeatureData(fdata_path)

    y_test = data[mt_config.LABEL_COL]
    X_test = fs.transform(data)

    y_pred = model.predict(X_test)

    computeMetrics(y_test, y_pred, average='macro', print_metrics=True, result_path=result_path)
    return

def mainAutoTrain(args):
    # Window args
    args.new_flow_win_width = defaultConfig.NEW_FLOW_WIN_WIDTH
    args.inactive_flow_timeout = defaultConfig.INACTIVE_FLOW_TIMEOUT
    args.active_flow_timeout = defaultConfig.ACTIVE_FLOW_TIMEOUT
    args.hostname_method = defaultConfig.HOSTNAME_METHOD

    # Features args
    args.setup_name = defaultConfig.GET_SETUP_NAME()
    args.max_jobs = cpu_count()

    # Train args
    args.fs_config = ""
    args.mt_config = ""
    args.test_size = 0.2

    mainWindows(args)
    mainFeatures(args)
    mainTrain(args)
    return

if __name__ == "__main__":
    defaultConfig = ActivityDetectionConfig()
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="choose a command", dest='command')
    window_parser = subparsers.add_parser('windows', help="'windows' help")
    window_parser.add_argument(
        '-i', dest='input_dir', required=True, help="The input directory")
    window_parser.add_argument('--new-flow-win-width', type=int, default=defaultConfig.NEW_FLOW_WIN_WIDTH,
                               help=f"The win_width for new flows to start in. (default={defaultConfig.NEW_FLOW_WIN_WIDTH}")
    window_parser.add_argument('--inactive-flow-timeout', type=int, default=defaultConfig.INACTIVE_FLOW_TIMEOUT,
                               help=f"The inactive flow timeout determines after how many seconds of no traffic is a flow considered over. (default={defaultConfig.INACTIVE_FLOW_TIMEOUT}")
    window_parser.add_argument('--active-flow-timeout', type=int, default=defaultConfig.ACTIVE_FLOW_TIMEOUT,
                               help=f"The active flow timeout determines after how many seconds of traffic (even continous) is a flow considered over. (default={defaultConfig.ACTIVE_FLOW_TIMEOUT}")
    window_parser.add_argument('--hostname-method', type=str, default=defaultConfig.HOSTNAME_METHOD,
                               help=f"Which hostname method to use. Options are 'live', 'post' or 'both'. (default='{defaultConfig.HOSTNAME_METHOD}')")

    feature_parser = subparsers.add_parser('features', help="'features' help")
    feature_parser.add_argument('-i', dest='input_dir',
                              required=True, help='The input directory')
    feature_parser.add_argument('-s', dest="setup_name", type=str, default=defaultConfig.GET_SETUP_NAME(),
                              help="The setup name to use")
    feature_parser.add_argument('--max-jobs', default=cpu_count(), type=int, help="The max number of processes to create in the pool")

    train_parser = subparsers.add_parser('train', help="'train' help")
    train_parser.add_argument('-i', dest='input_dir',
                              required=True, help='The input directory')
    train_parser.add_argument('-s', dest="setup_name", type=str, default=defaultConfig.GET_SETUP_NAME(),
                              help="The setup name to use")
    train_parser.add_argument('--fs-config', type=str, default="",
                              help="The feature selector config. Each default config field is overriden by the config provided here.")
    train_parser.add_argument('--mt-config', type=str, default="",
                              help="The model training config. Each default config field is overriden by the config provided here.")
    train_parser.add_argument('--test-size', type=float, default=0.2, help="The test size.")

    infer_parser = subparsers.add_parser('infer', help="'infer' help")
    infer_parser.add_argument('-i', dest='input_dir',
                              required=True, help="The input directory to use")
    infer_parser.add_argument('-s', dest='setup_name', type=str, default=defaultConfig.GET_SETUP_NAME(),
                              help="The setup name to use")
    infer_parser.add_argument('--mi', dest='model_input_dir', default=None,
                              help="The input directory for the model. By default uses the same as input")
    infer_parser.add_argument('--ms', dest="model_setup_name", type=str, default=defaultConfig.GET_SETUP_NAME(),
                              help="The setup name to use")
    infer_parser.add_argument('--mm', dest="model_model_name", type=str, default=defaultConfig.MODEL_AD_DEFAULT,
                              help=f"The model to use from the model directory. (default={defaultConfig.MODEL_AD_DEFAULT})")

    auto_train_parser = subparsers.add_parser('auto-train', help="'auto-train' help")
    auto_train_parser.add_argument('-i', dest='input_dir',
                              required=True, help="The input directory to use")
    args = parser.parse_args()

    if args.command == "windows":
        mainWindows(args)
    elif args.command == "features":
        mainFeatures(args)
    elif args.command == "train":
        mainTrain(args)
    elif args.command == "infer":
        mainInfer(args)
    elif args.command == "auto-train":
        mainAutoTrain(args)

    print("\nScript Completed Execution")

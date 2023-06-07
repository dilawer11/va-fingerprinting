import json
import os
import re
from datetime import datetime
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn import metrics
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from iotpackage.__vars import simpleFeatureGroups, dictFeatureGroups, ActivityDetectionConfig
import matplotlib.pyplot as plt
import pathlib
import pickle
from tqdm import tqdm

loadedCategories = None
storedFeatureGroups = None
devicecol = 'Device'
categorycol = 'Category'
CSVcols = ['Frame','Time','SrcIP','DstIP','Proto','tcpSrcPort','tcpDstPort','udpSrcPort','udpDstPort','Length','tcpACK','tcpSYN','tcpFIN','tcpRST','tcpPSH','tcpURG','Protocol', 'srcMAC', 'dstMAC']
# NON_IOT = ['iPhone', 'Android Tablet', 'HP Printer', 'Samsung Galaxy Tab', 'Laptop', 'IPhone', 'Android Phone', 'iPad', 'Ubuntu Desktop', 'MacBook', 'MacBook/Iphone', 'Nexus Tablet', 'Android Phone', 'Desktop', 'Motog phone', 'Router', 'Pixel 2 Phone']

def getMoreMetrics(y_true:pd.Series, y_pred:pd.Series):
    labels = list(set(y_true)).sort()
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    ax_0 = cm.sum(axis=0)
    ax_1 = cm.sum(axis=1)
    ax_all = cm.sum()
    diag = np.diag(cm)
    FP = ax_0 - diag
    FN = ax_1 - diag
    TP = diag
    TN = ax_all - (FP + FN + TP)
    
    # Sensitivity, hit rate, recall, or true positive rate
    TPR = TP/(TP+FN)
    # Specificity or true negative rate
    TNR = TN/(TN+FP) 
    # Precision or positive predictive value
    PPV = TP/(TP+FP)
    # Negative predictive value
    NPV = TN/(TN+FN)
    # Fall out or false positive rate
    FPR = FP/(FP+TN)
    # False negative rate
    FNR = FN/(TP+FN)
    # False discovery rate
    FDR = FP/(TP+FP)

    # Overall accuracy
    ACC = (TP+TN)/(TP+FP+FN+TN)

    TPR = np.mean(TPR)
    TNR = np.mean(TNR)
    PPV = np.mean(PPV)
    NPV = np.mean(NPV)
    FPR = np.mean(FPR)
    FNR = np.mean(FNR)
    FDR = np.mean(FDR)
    ACC = np.mean(ACC)

    return TPR, TNR, PPV, NPV, FPR, FNR, FDR, ACC

def strRound(val, dp=2):
    val_round = np.round(val, dp)
    val_round_str = str(val_round)
    d_idx = val_round_str.find('.')
    if d_idx >= 0: val_round_str =  val_round_str[:d_idx + 1 + dp]
    return val_round_str

def computeMetrics(y_true, y_pred, average=None, result_path=None, print_metrics=True, more_metrics=True, zero_division='warn'):
    def strMetric(metric_val):
        return "{:.2f}".format(np.round(metric_val * 100, 2))

    result_df = None
    results = {}

    unique_labels = set(list(y_true) + list(y_pred))
    average = 'macro'
    if len(unique_labels) == 2 and (unique_labels == set([1, 0]) or unique_labels == set(['1', '0'])): average = 'binary'
    
    # These metrics will be printed. Change the list with keys to print more or less
    metrics_to_print = ["Accuracy", "Precision", "Recall"]
    non_metrics = ['#Labels']

    # Compute simple metrics
    acc = accuracy_score(y_true, y_pred)
    prs, rcl, fsc, _ = precision_recall_fscore_support(y_true, y_pred, average=average, zero_division=zero_division)
    results['Accuracy'] =  acc
    results['Precision'] = prs
    results['Recall'] = rcl
    results['F1-Score'] = fsc
    results['#Labels'] = int(len(set(y_true)))

    if more_metrics:
        tpr, tnr, ppv, npv, fpr, fnr, fdr, acc = getMoreMetrics(y_true, y_pred)
        results['TPR'] = tpr
        results['TNR'] = tnr
        results['PPV'] = ppv
        results['NPV'] = npv
        results['FPR'] = fpr
        results['FNR'] = fnr
        results['FDR'] = fdr
        results['ACC'] = acc

    if (print_metrics == True) or (result_path is not None):
        result_df = pd.DataFrame(results, index=['score']).T.reset_index()
        result_df.columns=['metric', 'score']
        metrics_idx = ~(result_df['metric'].isin(non_metrics))
        result_df.loc[metrics_idx, 'score'] = result_df.loc[metrics_idx, 'score'].apply(lambda x: strMetric(x))

    if print_metrics:
        print_df = result_df[result_df['metric'].isin(metrics_to_print)]
        print("--- Test Metrics ---")
        for i, d in print_df.iterrows():
            if d['metric'] in metrics_to_print:
                print(f"{d['metric']:10s} ---> {d['score']:>6s}%")

    if result_path is not None:
        result_df.to_csv(f'{result_path}.csv', index=False)
    return results

def extractTimeFromIRName(ir_name):
        ir_name = os.path.split(ir_name)[1]
        if ir_name[0:3] != 'ir_':
            raise Exception("Unknown format expected file to start with 'ir_'")
        time_s = os.path.splitext(ir_name.split('_')[2])[0]
        ts = datetime.fromisoformat(time_s).timestamp()
        return ts

def loadInvokeRecords(ir_base_path, sort=True, load_stop=True):
    irs = []
    for root, _, files in os.walk(ir_base_path):
        if (os.path.split(root)[1] == 'stop') and not load_stop: continue
        for name in files:
            if 'ir_' in name:
                irs.append(os.path.join(root, name))
    if sort: irs.sort(key=extractTimeFromIRName)
    return irs

def extractTimeFromCaptureName(capture_name):
    capture_name = os.path.split(capture_name)[1]
    capture_name, capture_ext = os.path.splitext(capture_name)
    if capture_name[0:3] != "cap" and capture_ext not in ['.csv']:
        raise Exception(f"Unknown naming format: '{capture_name}'")
    capture_time = capture_name.split('_')[2]
    return int(capture_time)
def loadCaptureFromPath(dir_path, sort=True):
    file_paths = list(map(lambda x: os.path.join(dir_path, x), os.listdir(dir_path)))
    if sort:
        file_paths.sort(key=extractTimeFromCaptureName)
    return file_paths

def getIRPathFromPDPath(pd_path, pd_base_path, ir_base_path):
    relpath = os.path.relpath(pd_path, pd_base_path)
    fn_base, fn = os.path.split(relpath)
    fn = fn.replace('pd_', 'ir_').replace('.csv', '.json').replace('pdata_', 'ir_')
    return os.path.join(ir_base_path, fn_base, fn)

def getPDPathFromIRPath(ir_path, ir_base_path=None, pd_base_path=None):
    if ir_base_path == None and pd_base_path is None:
        idx_invoke_record = ir_path.find('invoke_records')
        if idx_invoke_record > 0:
            ad_config = ActivityDetectionConfig()
            bp = ir_path[:idx_invoke_record]
            ir_base_path = os.path.join(bp, 'invoke_records')
            act_det_path = ad_config.ACTIVITYDETECTION_PATH(bp)
            setup_name = ad_config.GET_SETUP_NAME()
            setup_path = ad_config.GET_SETUP_PATH(act_det_path, setup_name)
            pd_base_path = ad_config.EVENTWIN_PATH(setup_path)
    if ir_base_path is None or not os.path.exists(ir_base_path): raise ValueError('Require `ir_base_path` to exist')
    if pd_base_path is None or not os.path.exists(pd_base_path): raise ValueError('Require `pd_base_path` to exist')
    relpath = os.path.relpath(ir_path, ir_base_path)
    fn_base, fn = os.path.split(relpath)
    fn = fn.replace('ir_', 'pd_').replace('.json', '.csv')
    return os.path.join(pd_base_path, fn_base, fn)

def createParentDirectory(path):
    parent_path, _ = os.path.split(path)
    if os.path.isdir(parent_path):
        return
    elif os.path.exists(parent_path):
        raise Exception(f"parent_path already exists: {parent_path}")
    else:
        os.makedirs(parent_path)
        return

def getLabelForPD(pd_path, pd_base_path, ir_base_path):
    ir_path = getIRPathFromPDPath(pd_path, pd_base_path, ir_base_path)
    with open(ir_path, 'r') as f:
        ir_data = json.load(f)
    if 'label' in ir_data:
        return ir_data['label']
    else:
        return ir_data['invoke_phrase']

def labelledCSVFileLoader(pd_base_path, ir_base_path, file_exts=['.csv']):
    if not os.path.isdir(pd_base_path):
        raise ValueError(f'pd_base_path: {pd_base_path} is not a directory')
    if not os.path.isdir(ir_base_path):
        raise ValueError(f'ir_base_path: {ir_base_path} is not a directory')
    # Walks in the directory and gets all the files with file_exts
    file_list = []
    for root, _, files in os.walk(pd_base_path):
        for name in files:
            if os.path.splitext(name)[1] in file_exts:
                file_path = os.path.join(root, name)
                label = getLabelForPD(file_path, pd_base_path, ir_base_path)
                file_list.append((label, file_path))

    return file_list

def genIR(irs, load_stop=True, pb=True):
    """
    Generator for Invoke Records
    irs: Path|list of Path
        If a single path. Deals with it as base directory containing invoke records.
        If a list of paths. Deals with it as invoke records to process.
    pb: bool (default:False)
    """
    if isinstance(irs, (str, pathlib.Path)):
        ir_fps = loadInvokeRecords(ir_base_path=irs, sort=True, load_stop=load_stop)
    elif isinstance(irs, list):
        ir_fps = irs
    else:
        raise TypeError(f"Unknown type {type(irs)} for 'irs'")
    
    if pb: pbar = tqdm(total=len(ir_fps), desc="Invoke Records")
    for ir_fp in ir_fps:
        with open(ir_fp, 'r') as f:
            ir_data = json.load(f)
        ir_fn = os.path.split(ir_fp)[1]
        status = ir_fn.split('_')[1]
        if pb: pbar.update(1)
        yield ir_fp, ir_data, status
    if pb: pbar.close()



def getLabelForDeepVC(file_path):
    paths = file_path.split(os.path.sep)
    activity = paths[-3]
    voice = paths[-2]
    return activity.replace("_", " ")

def labelledCSVFileLoaderDeepVC(csv_base_path):
    # Walks in the directory and gets all the files with file_exts
    file_list = []
    for root, _, files in os.walk(csv_base_path):
        for name in files:
            if os.path.splitext(name)[1] == '.csv':
                file_path = os.path.join(root, name)
                label = getLabelForDeepVC(file_path)
                file_list.append((label, file_path))

    return file_list

def getFeatureGroup(featureName, ret_type=False):
    for featureGroupName, featureGroup in simpleFeatureGroups.items():
        if featureGroup['suffix'] in featureName:
            if ret_type:
                return featureGroupName, 'simple'
            else:
                return featureGroupName
    for featureGroupName, featureGroup in dictFeatureGroups.items():
        if featureGroup['suffix'] in featureName:
            if ret_type:
                return featureGroupName, 'dict'
            else:
                return featureGroupName
    return None

def isSimpleFeature(featureName):
    group = getFeatureGroup(featureName, ret_type=True)
    if group is not None:
        return group[1] == 'simple'
    else:
        return False

def isDictFeature(featureName):
    group = getFeatureGroup(featureName, ret_type=True)
    if group is not None:
        return group[1] == 'dict'
    else:
        return False

def getSuffixForGroups(groups):
    suffixes = []
    for group in groups:
        if group in dictFeatureGroups:
            suffixes.append(dictFeatureGroups[group]['suffix'])
        elif group in simpleFeatureGroups:
            suffixes.append(simpleFeatureGroups[group]['suffix'])
        else:
            raise ValueError(f'No type found for group: {group}')
    return suffixes

def getCommonLabels(data1, data2, label_col='Device', print_common=True):
    if isinstance(data1, pd.DataFrame) and isinstance(data2, pd.DataFrame):
        data1 = data1[label_col]
        data2 = data2[label_col]
    if not isinstance(data1, pd.Series):
        data1 = pd.Series(data1)
    if not isinstance(data2, pd.Series):
        data2 = pd.Series(data2)
    uniqueDevices_data1 = set(data1.unique())
    uniqueDevices_data2 = set(data2.unique())
    uniqueDevices_data1.discard('NoN-IoT')

    common_labels = list(uniqueDevices_data1.intersection(uniqueDevices_data2))
    if print_common:
        print('Common Labels:', common_labels)
    return common_labels

def findOptimalThreshold(fpr, tpr, thresholds):
    points = {}
    for i in range(0, len(thresholds)):
        points[thresholds[i]] = [fpr[i], tpr[i]]
    min = float('inf')
    threshold = None
    for k in points:
        try:
            [[i]] = metrics.pairwise.euclidean_distances([points[k]], [[0,1]])
        except:
            continue
        if i < min:
            min = i
            threshold = k
    return points[threshold][0], points[threshold][1], threshold

# Plots the Confusion Matrix. Also used to store the values to plot later
def plotCM(y_true, y_pred, store_cm=None, plot_cm=False):
    labels = list(y_true.unique())
    labels.sort()
    cm = metrics.confusion_matrix(y_true, y_pred, labels=labels)
    cmn = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    if isinstance(store_cm, str):
        #Path is provided to store cmn
        pd.DataFrame(cmn).to_csv(store_cm + '-CM.csv', index=False)
        pd.Series(labels).to_csv(store_cm + '-Labels.csv', index=False)
    if plot_cm:
        fig, ax = plt.subplots()
        sns.heatmap(cmn, annot=True, fmt='.2f', xticklabels=labels, yticklabels=labels, cmap="Blues", cbar=False)
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.show()

def storeActualAndPredictVectors(y_true, y_pred, save_path):
    fp = f'{save_path}-vectors.json'
    if isinstance(y_true, pd.Series):
        y_true_l = y_true.to_list()
    elif isinstance(y_pred, np.ndarray):
        y_pred_l = list(y_pred)
    elif isinstance(y_true, list):
        y_true_l = y_true
    else:
        raise TypeError(f'y_true: Expected type pd.Series|np.ndarray|list. Got {type(y_true)}')
    if isinstance(y_pred, pd.Series):
        y_pred_l = y_pred.to_list()
    elif isinstance(y_pred, np.ndarray):
        y_pred_l = list(y_pred)
    elif isinstance(y_pred, list):
        y_pred_l = y_pred
    else:
        raise TypeError(f'y_pred: Expected type pd.Series|np.ndarray|list. Got {type(y_pred)}')

    data = { 'y_true': y_true_l, 'y_pred': y_pred_l}
    with open(fp, 'w+') as f:
        json.dump(data, f)
    return

# Plots all the AUC curves used in the paper
def plotAUCCurve(fpr, tpr, roc_auc):
    plt.figure()
    lw = 2
    plt.plot(fpr, tpr, color='darkorange',
            lw=lw, label='ROC curve (AUC = %0.2f)' % roc_auc)
    plt.plot([0, 1], [0, 1], color='navy', lw=lw, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Unknown Devices')
    plt.legend(loc="lower right")
    plt.show()

def getCommonLabelData(X1, X2, y1=None, y2=None, label_col=None, common_both=True, print_common=True):
    if label_col:
        y1 = X1[label_col]
        y2 = X2[label_col]
    elif y1 is None or y2 is None:
        raise ValueError('Either y1, y2 or label_col must be defined')

    common_labels = getCommonLabels(y1, y2, print_common=print_common)
    common_loc2 = y2.isin(common_labels)
    try:
        X2 = X2[common_loc2]
        y2 = y2[common_loc2]
    except:
        print("ERROR, X2, y2")
        print(X2)
        print(common_loc2)
    if common_both:
        common_loc1 = y1.isin(common_labels)
        try:
            X1 = X1[common_loc1]
            y1 = y1[common_loc1]
        except:
            print("ERROR X1, y1")
            print(X1)
            print(common_loc1)

    return X1.reset_index(drop=True), y1.reset_index(drop=True), X2.reset_index(drop=True), y2.reset_index(drop=True)

def renameLabels(featureData, labelCol, destCol, mappings, error_raise=True):
    if not isinstance(featureData, pd.DataFrame):
        raise ValueError(f'featureData must be a Pandas DataFrame given {type(featureData)}')
    if not isinstance(labelCol, str):
        raise ValueError(f'labelCol must be a str given {type(labelCol)}')
    if not isinstance(destCol, str):
        raise ValueError(f'destCol must be a str given {type(destCol)}')
    if not isinstance(mappings, dict):
        raise ValueError(f'mappings must be of type dict given {type(mappings)}')

    for label in mappings:
        idx = featureData[labelCol].isin(mappings[label])
        featureData.loc[idx, destCol] = label
    if featureData[destCol].isna().sum() and error_raise:
        raise Exception(f'No Mappings For {featureData.loc[featureData[destCol].isna(), labelCol].unique()}')
    else:
        return featureData

def loadFeatureData(feature_data_path, shuffle=False, normalize=False, fillna=True, verbose=0):

    ext = os.path.splitext(feature_data_path)[1]
    if ext == '.pkl': feature_data = pd.read_pickle(feature_data_path)
    elif ext == '.json': feature_data = pd.read_json(feature_data_path)
    if verbose: print('Feature Data File Loaded', flush=True)
    # Performs post-loading operations
    if fillna:
        feature_data.fillna(0, inplace=True)

    if shuffle:
        if verbose: print('Shuffling Data...', flush=True)
        feature_data = feature_data.sample(frac=1).reset_index(drop=True)
    return feature_data

# A helper function to get latex style graphs from data
def DataFrame2LatexTable(df, bold_heading=True, index=False, return_string=False):
    latex_string = ""
    sep = " & "
    
    # Keep '\' in first so that it doens't get escaped twice when others are replaced in place
    special_characters = ["\\", '&', '%', '$', '#', '_', '{', '}', '~', '^']
    if index: df = df.copy().reset_index()
    def cleanText(val):
        for ch in special_characters: val = val.replace(ch, f'\{ch}')
        if val[:2] == "**" and val[-2:] == "**": val = makeBold(val[2:-2])
        elif val[:1] == '*' and val[-1:] == "*": val = makeItalic(val[1:-1])
        return val
    def makeBrace(val):
        return '{' + val + '}'
    def makeBold(val):
        return '\\textbf' + makeBrace(val)
    def makeItalic(val):
        return '\\textit' + makeBrace(val)
    
    for col in df.columns:
        if bold_heading: col_string = makeBold(cleanText(str(col)))
        else: col_string = makeBrace(cleanText(str(col)))
        latex_string += sep + col_string
    latex_string = latex_string.replace(sep, "", 1)
    latex_string += " \\\\\n"
    vals = df.values
    for i in vals:
        row_string = ""
        for idx, j in enumerate(i):
            row_string += sep
            col_val = cleanText(str(j))
            if idx == 0 and index and j is not None:
                row_string += makeBold(col_val)
            elif j is not None:
                row_string += col_val
        row_string = row_string.replace(sep, "", 1)
        latex_string += row_string + " \\\\\n"
    # if escape: latex_string = latex_string.replace('_','\_')

    if return_string: return latex_string
    else: print(latex_string)
DF2Latex = DataFrame2LatexTable

def perLabelSample(data, sample_size, label_col='Device'):
    labels = list(data[label_col].unique())
    data_array = []
    for label in labels:
        label_loc = data[label_col] == label
        sample = min(sample_size, data[label_loc].shape[0])
        data_array.append(data.loc[label_loc,:].sample(sample))
    return pd.concat(data_array, ignore_index=True).reset_index(drop=True)

# This function gets the largest latest run of an experiment and returns the number so next run can be stored as that number + 1 or the plotting files can use the latest run.
def getLargestRunNumber(exp_id, base_dir=os.path.join('Results', 'Experiments'), name_prefix="Exp"):
    exp_dir = os.path.join(base_dir, f'{name_prefix}{exp_id}')
    if not os.path.exists(exp_dir):
        os.makedirs(exp_dir)
        return 0
    files = os.listdir(exp_dir)
    r = 0
    for file_name in files:
        file_name = file_name.replace('.csv', '')
        run_number = int(file_name.split('-')[1]) #Exp##-{run_number}**
        r = max(run_number, r)
    return r

# This returns the base path to store the results of an experiment using the function above
def getResultPath(exp_id, exp_dir=os.path.join('Results', 'Experiments')):
    r = getLargestRunNumber(exp_id=exp_id, base_dir=exp_dir)
    r += 1
    file_name_template = f'Exp{exp_id}-{r}'
    resultPath = os.path.join(exp_dir, f'Exp{exp_id}',file_name_template)
    return resultPath

def slugify(s):
    if not isinstance(s, str):
        raise ValueError(f"Expected 's' to be a string got: {type(s)}")
    s = s.lower().strip()
    s = re.sub(r'[^\w\s-]', '', s)
    s = re.sub(r'[\s_-]+', '-', s)
    s = re.sub(r'^-+|-+$', '', s)
    return s

def getDateTimeString():
    return datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

def loadPickle(fp):
    with open(fp, 'rb') as f:
        data = pickle.load(f)
    return data

def printColor(text, color, **kargs):

    color_map = {
        "black": 30,
        "red": 31,
        "green": 32,
        "yellow": 33,
        "blue": 34,
        "magenta": 35,
        "cyan": 36,
        "white": 37
    }
    color_l = color.lower()
    if color_l not in color_map: raise NotImplementedError(f"Unknown color={color}")
    color_code = color_map[color_l]
    print(f"\033[1;{color_code}m{text}\033[1;0m", **kargs)
    return

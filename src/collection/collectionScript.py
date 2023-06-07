import os
import re
import time
from datetime import datetime
import subprocess
import signal
import logging
import random
import json
from tqdm import tqdm
from commandvalidate.default import NoValidate
import argparse
import shlex
from iotpackage.tts.gcpTTS import convertTextToSpeechForVA
from dotenv import load_dotenv

l = logging.getLogger('CollectionScript')

load_dotenv()

# Audio play command (change this if using another method)
AUDIO_PLAY_CMD = "/usr/bin/vlc --play-and-exit --no-interact --intf dummy {}"

CONFIG = None
CAPTURE_PROCESS = None
VALIDATOR = None

def slugify(s):
    if not isinstance(s, str):
        raise ValueError(f"Expected 's' to be a string got: {type(s)}")
    s = s.lower().strip()
    s = re.sub(r'[^\w\s-]', '', s)
    s = re.sub(r'[\s_-]+', '-', s)
    s = re.sub(r'^-+|-+$', '', s)
    return s

def loadConfig(config_fname="collectionConfig.json"):
    global CONFIG
    with open(config_fname, 'r') as f:
        CONFIG = json.load(f)
    return

def beginPacketCapture(capture_path:str) -> subprocess.Popen:
    """
    Given the destination to store the pcap_file and the capture_duration starts the packet capture from the network
    """
    global CAPTURE_PROCESS
    prefix = 'cap.pcap'
    if not os.path.isdir(capture_path):
        l.info(f"Making directory for captures: {capture_path}")
        os.makedirs(capture_path)
    capture_prefix = os.path.join(capture_path, prefix)
    l.info(f"Starting Packet Capture: {capture_path}. prefix: {prefix}")
    capture_cmd = f"./{CONFIG['capture_script_path']} {capture_prefix} {CONFIG['target_ip']}"
    CAPTURE_PROCESS = subprocess.Popen(capture_cmd, shell=True, preexec_fn=os.setsid)
    time.sleep(5)
    if CAPTURE_PROCESS.poll() is not None:
        print('Error')
    l.info("Packet Capture Online")
    return CAPTURE_PROCESS

def terminatePacketCapture(p):
    """
    Sends SIGTERM to the packet capture process group
    """
    l.info("Terminating Packet Capture...")
    pgid = os.getpgid(p.pid)
    os.killpg(pgid, signal.SIGTERM)
    l.info("Packet Capture Terminated")
    return

def convertTextToSpeech(wake_word:str, text:str) -> str:
    """
    Given a string text checks to see if it has been stored locally if not converts it to speech and stores locally for future use. 
    Returns the path in all cases
    """
    slug = slugify(f'{wake_word}-{text}')
    audio_fname = f"{slug}.mp3"
    audio_fp = os.path.join(CONFIG['audio_files_dir'], audio_fname)
    if not os.path.exists(audio_fp):
        convertTextToSpeechForVA(wake_word, text, audio_fp)
    return audio_fp

def speak(audio_fp:str):
    if not os.path.exists(audio_fp): raise FileNotFoundError(f"playAudio: File Not Found: {audio_fp}")

    l.info(f"Playing audio file: {audio_fp}")
    start_time = time.time()
    subprocess.run(shlex.split(AUDIO_PLAY_CMD.format(audio_fp)), shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end_time = time.time()
    return start_time, end_time

def getWakeWord():
    if CONFIG['va'] == 'Alexa':
        return CONFIG['alexa_wake_word']
    elif CONFIG['va'] == 'Google': 
        return CONFIG['google_wake_word']
    elif CONFIG['va'] == 'Siri':
        return CONFIG['siri_wake_word']
    else:
        raise Exception(f"Unknown getWakeWord case. va='{CONFIG['va']}'")

def invokeVA(activity:dict, invoke_record_path:str=None, verify:bool=True, retry:int=2, wait_before_retry:int=30, wait_before_verify:int=5)->tuple:
    """
    Given an activity dict invokes Alexa and then verifies to ensure it runs.
    """
    try_sub = 1
    is_ok = False
    if retry == 0:
        try_sub = 0
        retry = 1

    va = CONFIG['va']
    wake_word = getWakeWord()
    l.info(f"Invoking VA='{va}' with wake_word='{wake_word}': {activity['invokePhrase']}, retry: {retry}, verify: {verify}")
    invoke_record = {}
    invoke_record['va'] = va
    invoke_record['invoke_phrase'] = activity['invokePhrase']
    invoke_record['wake_word'] = wake_word
    invoke_record['audio_fp'] = convertTextToSpeech(wake_word, invoke_record['invoke_phrase'])
    if 'label' in activity:
        invoke_record['label'] = activity['label']
    else:
        invoke_record['label'] = invoke_record['invoke_phrase']

    while (not is_ok) and retry > 0:
        now = datetime.now().isoformat()
        invoke_record['start_time'], invoke_record['end_time'] = speak(invoke_record['audio_fp'])
        # The sleep below applies to both validate/verify=True and validate/verify=False cases for consistency since otherwise one data would be that much longer.
        time.sleep(wait_before_verify)
        if verify:
            l.info("Verifying voice activity...")
            is_ok, validate_record, va_activity_data = VALIDATOR.verify(utterance=activity['verifyPhrase'], reply=activity['expectedReply'])
            invoke_record['validate_record'] = validate_record
            invoke_record['va_activity_data'] = va_activity_data
            if is_ok:
                l.info("Verification OK")
                flabel = f'V_{now}'
                invoke_record_fp = getInvokeRecordName(invoke_record_path, flabel)
                saveInvokeRecord(invoke_record, invoke_record_fp)
                return True, invoke_record_fp
            else:
                l.info("Verification failed")
                flabel = f'F_{now}'
                invoke_record_fp = getInvokeRecordName(invoke_record_path, flabel)
                saveInvokeRecord(invoke_record, invoke_record_fp)
        else:
            flabel = f'U_{now}'
            invoke_record_fp = getInvokeRecordName(invoke_record_path, flabel)
            saveInvokeRecord(invoke_record, invoke_record_fp)
            return True, invoke_record_fp
        retry -= try_sub
        l.info(f"Waiting for {wait_before_retry} seconds before retrying...")
        time.sleep(wait_before_retry)
    return False, None

def stopVA(retry:int=0, wait_before_verify:int=5, wait_before_retry:int=0) -> bool:
    """
    Stops alexa. Tries 'retry' many times. 0 means keep trying until successful
    """
    va = CONFIG['va']
    activity = {
        "invokePhrase": "stop",
        "verifyPhrase": "stop",
        "expectedReply": None,
    }
    slug = slugify(activity['invokePhrase'])
    invoke_record_path = getInvokeRecordPath(va, slug)
    return invokeVA(activity, retry=retry, invoke_record_path=invoke_record_path, wait_before_verify=wait_before_verify, wait_before_retry=wait_before_retry)

def incrementLabel(labels, label):
    if label in labels:
        labels[label] += 1
    else:
        labels[label] = 1
    return labels
def getLabelCounts(ir_base_dir):
    labels = {}
    for root, _, files in os.walk(ir_base_dir):
        for fn in files:
            if os.path.splitext(fn)[1] == '.json' and 'ir_V' in fn:
                with open(os.path.join(root, fn), 'r') as f:
                    data = json.load(f)
                    if 'label' in data:
                        labels = incrementLabel(labels, data['label'])
                    else:
                        labels = incrementLabel(labels, os.path.split(root)[1])
    return labels

def loadActivities(shuffle:bool=False) -> list:
    """
    Given a fname (json file path of a activities file) loads it and optionalls shuffles before returning it
    """
    fname = CONFIG['activity_file']
    if fname is None: return None, None
    with open(fname, 'r') as f:
        activities = json.load(f)

    wake_word = getWakeWord()
    # Load labels from disk (already done in previous runs)
    ir_path = os.path.join(CONFIG['collection_base_dir'], CONFIG['invoke_records_dir'], wake_word)
    labels = getLabelCounts(ir_path)

    if shuffle: random.shuffle(activities)
    return activities, labels

def getInvokeRecordPath(va: str, slug:str) -> str:
    invoke_records_dir = CONFIG['invoke_records_dir']
    collection_base_dir = CONFIG['collection_base_dir']
    invoke_record_path = os.path.join(collection_base_dir, invoke_records_dir, va, slug)
    if not os.path.isdir(invoke_record_path):
        os.makedirs(invoke_record_path)
    return invoke_record_path

def getCapturePath() -> str:
    base_dir = CONFIG['collection_base_dir']
    capture_dir = os.path.join(base_dir, CONFIG['capture_dir'])
    return capture_dir

def getInvokeRecordName(invoke_record_path:str, id:str) -> str:
    fn = f'ir_{id}.json'
    return os.path.join(invoke_record_path, fn)

def saveInvokeRecord(invoke_record, invoke_record_fp):
    with open(invoke_record_fp, 'w+') as f:
        json.dump(invoke_record, f, indent=4)
    return

def markInvokeRecordComplete(invoke_record_fp:str):
    with open(invoke_record_fp, 'r+') as f:
        ir_data = json.load(f)
        f.seek(0)
        ir_data['complete'] = True
        json.dump(ir_data, f, indent=4)
    return

def runActivityAndWait(activity, wait_duration, retry=2):
    va = CONFIG['va']
    try:
        # Set Variables
        slug = slugify(activity['invokePhrase'])
        invoke_record_path = getInvokeRecordPath(va, slug)

        tqdm.write(f'Invoke Phrase: {activity["invokePhrase"]}')
        tqdm.write(f'Slug         : {slug}')
        tqdm.write(f'VA Device    : {va}')
        tqdm.write(f'Duration     : {wait_duration}')
        
        # Setting wait_before_verify. CONFIG has default value. But activities might have their own.
        wait_before_verify = CONFIG['wait_before_verify']
        if 'waitBeforeVerify' in activity: wait_before_verify = activity['waitBeforeVerify']
    
        # Invoke VA
        l.info(f'Invoking VA: {va}')
        activation_sucessful, invoke_record_fp = invokeVA(activity, retry=retry, wait_before_verify=wait_before_verify, wait_before_retry=CONFIG['wait_before_retry'], invoke_record_path=invoke_record_path)
        
        # Checking if all systems okay
        if not activation_sucessful: 
            l.warning(f"Retries exhausted: {activity}")
            return False

        wait_after_verify = wait_duration - wait_before_verify
        l.info(f"All checks okay. Waiting for activity capture {wait_after_verify} seconds")
        
        # Wait till capture_duration. Because we waited 'wait_before_verify' seconds before verifying
        time.sleep(wait_after_verify)
        
        l.info("Waiting complete")
        if activity['stop']:
            l.info("Stopping VA...")
            stopVA()
        
        l.info("Saving invoke record...")
        markInvokeRecordComplete(invoke_record_fp)
        return True
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except:
        l.exception('runActivityAndWait')
        print("Exception Occured. See logs")
    return False

def initialSetup():
    loadConfig()
    if not os.path.exists(CONFIG['audio_files_dir']):
        os.makedirs(CONFIG['audio_files_dir'])

def initValidator():
    global VALIDATOR
    if not CONFIG['validate']: 
        VALIDATOR = NoValidate()
        return
    else:
        raise Exception(f"Unknown VA Validator va='{CONFIG['va']}'")

def main(runs=10, pre_wait=0):
    initialSetup()
    initValidator()

    activities, labels = loadActivities()

    # Initiate Packet Capture

    try:
        print(activities)
        print(labels)
        print(CONFIG)
        global CAPTURE_PROCESS
        capture_dir = getCapturePath()
        beginPacketCapture(capture_dir)
        pre_wait_seconds = pre_wait * 60
        l.info(f"PreWait: {pre_wait}. Waiting for {pre_wait_seconds} seconds")
        time.sleep(pre_wait_seconds)
        l.info(f"Starting commands...")
        new_invoke = True
        while new_invoke:
            # Set to false. Loop breaks if no commands are invoked in this round
            new_invoke = False
            if activities is None or not len(activities): break
            for activity in activities:
                if 'label' in activity:
                    label = activity['label']
                else:
                    label = activity['invokePhrase']
                if label in labels and labels[label] >= runs: continue
                
                # Mark new_invoke as true to indicate still running
                new_invoke = True
                is_ok = runActivityAndWait(activity, CONFIG['capture_duration'])
                
                # Add one to run tracking if it was ok
                if is_ok: incrementLabel(labels, label)
                
                l.info(f"Activity Over. Waiting for {CONFIG['wait_between_iterations']} seconds")
                time.sleep(CONFIG['wait_between_iterations'])
        terminatePacketCapture(CAPTURE_PROCESS)
        CAPTURE_PROCESS = None
    except KeyboardInterrupt:
        if CAPTURE_PROCESS is not None:
            terminatePacketCapture(CAPTURE_PROCESS)
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', dest="collection_runs", default=125, type=int, help="The number of runs/repeats for the same activity to perform")
    parser.add_argument('--pre-wait', dest="pre_wait", default=0, type=int, help="Minutes to wait after starting collection and before saying the first command")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG, filename="collection.log")
    
    main(args.collection_runs, args.pre_wait)

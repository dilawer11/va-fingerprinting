#!/bin/sh
# This is a meta test script which calls other scripts to ensure everything runs without errors

# Define paths
ACTIVITY_DETECTION_SCRIPT_PATH=src/scripts/ActivityDetection.py
INVOCATION_DETECTION_SCRIPT_PATH=src/scripts/InvocationDetection.py
PCAP2CSV_SCRIPT_PATH=src/PCAP2CSV.py
TEST_DATASET_PATH=data/test_dataset

# Clean Up Commands (Uncomment to enable)
# rm -rf $TEST_DATASET_PATH/activity-detection
# rm -rf $TEST_DATASET_PATH/invocation-detection
# rm -rf $TEST_DATASET_PATH/captures_csv


# convert PCAP to CSV
python3 $PCAP2CSV_SCRIPT_PATH -i $TEST_DATASET_PATH && \

# Activity Detection
python3 $ACTIVITY_DETECTION_SCRIPT_PATH windows -i $TEST_DATASET_PATH && \
python3 $ACTIVITY_DETECTION_SCRIPT_PATH features -i $TEST_DATASET_PATH && \
python3 $ACTIVITY_DETECTION_SCRIPT_PATH train -i $TEST_DATASET_PATH && \
python3 $ACTIVITY_DETECTION_SCRIPT_PATH infer -i $TEST_DATASET_PATH --mi $TEST_DATASET_PATH && \

# Invocation Detection
python3 $INVOCATION_DETECTION_SCRIPT_PATH windows -i $TEST_DATASET_PATH && \
python3 $INVOCATION_DETECTION_SCRIPT_PATH train -i $TEST_DATASET_PATH && \
python3 $INVOCATION_DETECTION_SCRIPT_PATH infer -i $TEST_DATASET_PATH --mi $TEST_DATASET_PATH && \

# Final Message
echo "\n\n-->> Test Run Completed <<--"
# Data Collection

## Physical Setup

In our paper and evaluations we used a setup consisting of two routers (called Home Router and ISP Router), a Ubuntu desktop, A speaker and 3 Voice Assistant enabled smart speakers (Amazon Echo Plus, Google Nest Mini, and Apple HomePod Mini).

The smart speakers were connected to the Home router using WiFi and the home router was connected via LAN to the ISP router. The Ubuntu Desktop was also connected via LAN to the ISP router to dump traffic from it. The speaker was connected to the Ubuntu desktop to allow the desktop script to utter commands to the speaker. The ISP router was connected to the internet through our University network

The routers would need to be setup to advertise different DHCP ranges to avoid conflicts and you can also use a different controller to utter commands via a script and a seperate controller to dump/mirror traffic from the ISP router.

Both of our routers were OpenWRT powered routers and we enabled ssh on them to create an SSH tunnel to mirror the traffic. We also created a bridged VLAN on the ISP router to mirror all traffic.

## Software Setup

### Dependencies

To install the software dependencies for the software data collection controller you can use the `setup/requirements_collection.txt` file and use the command

```console
$ pip install -r requirements_collection.txt
```

### Traffic Capture Setup

To capture the traffic from the second router (ISP router) we need a working SSH connection to it and use tcp dump to tunnel traffic back to the "controller" machine.

Our routers were running OpenWRT and we used SSH config file to enable passwordless login to the router. We named the router as `router` so we could use the `ssh router` command to login to it. You can do a web search to see how to setup an SSH connection to your router and setup `tcpdump` on the router. Replace the `{user@router}` in the `capture.sh` script with the proper login method

We used the script `capture.sh` to capture the traffic from the router. The following lines are the one that captures the traffic and store it

```sh

PIPE=/tmp/capture_pipe
if [ -p "$PIPE" ]
then
	rm $PIPE
fi
mkfifo $PIPE -m777

dumpcap -i $PIPE -b interval:1800 -w $1 & ssh {user@router} "tcpdump -i br-lan -nn -s0 -U -w - host $2" > $PIPE
```

The `tcpdump` command runs on the router and captures traffic on bridged lan (`br-lan`) interface on the router and filters the traffic based on IP (`$2`). 

The traffic is piped to a FIFO pipe we created `/tmp/capture_pipe`.

Finally we use the dumpcap to create 30 minute PCAPs (1800 seconds) and store them in the output location (`$1`).

This setup should also work for you and incase you see any variation feel free to change the `capture.sh` script as needed or create an issue on the repo with suggestions and changes. Just make sure the first arg is the output path and second arg is the IP to filter by.


## Process

### Config Update

After you have installed the required packages. You can go ahead and edit the config file `collectionConfig.json` to prepare for the data collection. Following edits are required.

- Provide the path to store the pcap files and invoke records in `collection_base_dir` path. 
- Provide the activity file (the file that has the commands/skills) in the `activity_file`.
- Provide the target IP in `target_ip` field. This IP is used to filter the traffic on the second router and in our case this was the IP of the first router (not the VA device)
- Provide the voice assistant you want to collect for in `va` field.
- Check that the wake words in the config file is correct for your VA. We used the default values in our work

### Start Collection

After the config file is updated correctly you can initiate collection by using the following command from inside the `collection` directory

```console
python3 collectionScript.py
```

There are a few command line args that the script uses which can be checked by using the `-h` or `--help` flag. The include the config path and the number of iterations (runs) for each command to perform. The script will terminate automatically when the process is complete.

If you encounter any errors please let us know by creating an issue. Please also read the [Important Notices](#important-notes) below.

## Important Notices

- **Playing Audio**: We used VLC media player installed in ubuntu to play commands via a shell command. You can use any other method as well. Change the `AUDIO_PLAY_CMD` variable in the `collectionScript.py` file accordingly
- **Command Validation**: We used command validation in our setup. However, this this repo the code files are not provided and only `NoValidate` exists. This is due to how each platform requires a sizeable setup and hence we didn't provide the code and instructions for it. With a good speaker and quiet environment you can get >97% command accuracy. If you do want to setup the command validation we scraped Alexa's customer history records and Google's My Activity pages with a selenium script and a customer Google Chrome extension respectively
- **Text-to-speech**: We used the Google Cloud (GCP) TTS service to convert the text from text commands to audio mp3 files. The code is provided in the [src/iotpackage/tts/gcpTTS.py](/src/iotpackage/tts/gcpTTS.py) file. You will need to create your own account and store a key file in the same directory and name it `.gcp_key.json`. For more details on this you would need to search how GCP TTS works
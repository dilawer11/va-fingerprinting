#! /bin/bash
# Replace the {user@router} with login method. Easiest way is to setup using SSH config files
if [ ! $1 ]
then
	echo "Enter the output path as the first arg"
	exit 1;
fi

if [ ! $2 ]
then
	echo "Enter the target ip as the second arg"
	exit 1;
fi

echo "Starting Packet Capture..."
echo "Path:" $1

PIPE=/tmp/capture_pipe
if [ -p "$PIPE" ]
then
	rm $PIPE
fi
mkfifo $PIPE -m777

dumpcap -i $PIPE -b interval:1800 -w $1 & ssh {user@router} "tcpdump -i br-lan -nn -s0 -U -w - host $2" > $PIPE

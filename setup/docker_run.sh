#!/bin/sh

PC_BASEDIR=$('pwd')
DOCKER_BASEDIR=/va-fingerprinting
MOUNT_DIR=$PC_BASEDIR:$DOCKER_BASEDIR
CONTAINERNAME=vafingerprint
docker run --platform=linux/x86_64 -it -v $MOUNT_DIR $CONTAINERNAME

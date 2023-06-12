# Setup

There are multiple ways to setup the environment for this repo. We will provide guidelines for setting up via Docker and setting it up locally.

Important Points
- Some of the commands might **require administrator priviledges** to run depending on your machine and setup (e.g docker, apt-get). For Linux and macOS you can add `sudo` keyword behind these commands
- Our build and test platforms were a Ubuntu Linux server and an Apple Silicon MacBook Pro. Any other systems might require additional steps not outlined here for the setup so adopt accordingly. 
- For Docker on non x86_64 machines use the option `--platform=linux/x86_64` to use emulation. However, it might take longer

## Method 1: Docker image (Recommended)

### 1. Download the Docker image


We have provided a Docker image at this [link](https://privacy-datahub.csc.ncsu.edu/vafingerprinting/vafingerprint_di.tar.gz)

### 2. (Optional) Verify SHA checksum

Use the following command to create an MD5 checksum of the file and compare against the value provided on linux

```sh
$ md5sum path/to/vafingerprint_di.tar.gz
```
`MD5 (vafingerprint_di.tar.gz) = 06f59a248ff4b715113bea9c1a6e97dd`

On MacOS you can use `md5` command instead of `md5sum`

### 3. Load the Docker image

You can use the following command to load the compressed docker image

```sh
$ docker load < path/to/vafingerprint_di.tar.gz
```

### 4. Start the container

Now we can start the docker container and load our code and data files. If your terminal window is currently in the base github repo directory you can run the following command to start container and mount the current directory otherwise `cd` to the directory or change the command accordingly. (You will need to add an option `--platform=linux/x86_64` or `--platform=linux/amd64` to the command to support emulation on Apple Silicon Macs)

```sh
$ docker run -it -v $('pwd'):/va-fingerprinting vafingerprint
```

Alternatively, you can also refer to [`/setup/docker_run.sh`](docker_run.sh) to see the command to start the container and run it from the root directory using the following command

```sh
$ sh setup/docker_run.sh
```

Note: You will also need to populate the data directory with the datasets if you want to process them but you can do that at a later stage as well


## Method 2: Dockerfile 

Using this method you can create your own docker container using the Dockerfile provided. Creating the container might take some time as dependencies would need to be resolved

### 1. Clone and setup the Github repositiry

```sh
$ git clone https://github.com/dilawer11/va-fingerprinting
```

This command will download the git repo and create a new directory called "va-fingerprinting". You can then change the working directory to va-fingerprinting by running the following command

```sh
$ cd va-fingerprinting
```

### 2. Creating the Docker image from Dockerfile

You can build the Docker image by running the following command and providing the tag "va-fingerprinting" as such

```sh
$ docker build -t va-fingerprinting .
```

You might have to wait a few minutes for this step to complete. If you are emulating the platform (e.g Apple Silicon MacBook) it might take longer

### 3. Start the container

Now we can start the docker container and load our code and data files. If your terminal window is currently in the base github repo directory you can run the following command to start container and mount the current directory otherwise `cd` to the directory or change the command accordingly

```sh
$ docker start -it -v $('pwd'):/home/vauser/va-fingerprinting vafingerprint
```

Note: You will also need to populate the data directory with the datasets if you want to process them but you can do that at a later stage as well

## Method 3: Local setup

Using this method the environment will be setup on local system. This method is not recommended as it might mess up any existing enviroments you may have or may take longer to resolve all the dependencies. However this step can serve as a guide for all the other setup methods (e.g Pipenv, conda).

Note: This method also assumes that git installed. If not refer to internet on how to do that.

### 1. Clone and setup the Github repositiry

```console
$ git clone https://github.com/dilawer11/va-fingerprinting
```

This command will download the git repo and create a new directory called "va-fingerprinting". You can then change the working directory to va-fingerprinting by running the following command

```console
$ cd va-fingerprinting
```

### 2. Setup python, pip and tshark

You can skip this step if you already have a working python3, pip and tshark setup. We used python3.9 in our evaluations and recommend you use teh same which can be installed on Debian linux using the following commands. For other platforms refer to the internet.

```console
$ apt-get update && apt-get install python3.9 python3-pip tshark
```

Note: If you get permission warnings try adding `sudo` before both the commands

### 3. Install pip dependencies

The following commands install the pip dependencies. We recommend running them in order provided

```console
$ pip3 install autogluon.tabular[fastai,lightgbm,xgboost,ray]

$ pip3 install -r requirements_core.txt

$ pip3 install -r requirements_analysis.txt
```

### 4. Setup environment variables

The following command will add the 'src' to the python path for easy imports. Replace the `path/to/va-fingerprinting/src` with the path to the 'src' directory in the Github repo

```console
$ export PYTHONPATH=$PYTHONPATH:/path/to/va-fingerprinting/src
```
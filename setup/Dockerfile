FROM --platform=linux/x86_64 ubuntu:22.04

# Install python and tshark
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3.9 \
    python3-pip \
    tshark \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
RUN pip install autogluon.tabular[fastai,lightgbm,xgboost,ray]
ADD requirements_analysis.txt /tmp/requirements_analysis.txt
RUN pip install -r /tmp/requirements_analysis.txt

WORKDIR /va-fingerprinting

# Set the required env variables
ENV PYTHONPATH=/va-fingerprinting/src

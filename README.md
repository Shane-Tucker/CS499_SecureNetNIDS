# CS499_SecureNetNIDS

## Overview
SecureNet is a real-time Network Intrusion Detection System (NIDS) written in Python for the UAH CS499 Computer Science Senior Project. SecureNet monitors and analyzes network traffic to detect suspicious activities and malicious attacks. It leverages machine learning techniques to identify abnormal patterns and generates alerts for potential threats.

### Members:
Austin Allen: Front-End Developer\
Bradley Mitchell: Machine Learning Specialist\
Michael Hood: Back-End Developer\
Shane Tucker: Network Engineer

## Features
1. Real-time network traffic monitoring
2. Port Scan detection
3. ARP Poisoning detection
4. Distributed Denial of Service (DDoS) Attack detection
5. Implementation of supervised machine learning algorithms to identify abnormal network traffic
6. Implementation of unsupervised machine learning techniques to monitor changes in traffic patterns
7. Generation of ML datasets Using collected network traffic
8. GUI Dashboard used for controlling the program and monitoring alerts/machine learning results

## Installation
1: Install the python libraries listed in requirements.txt

2: Install Scapy and any operating specfic dependencies required to run scapy
- install instructions available at: https://scapy.readthedocs.io/en/latest/installation.html

## Running The Program
1. Run GUI_NET.py to start the program

2. On the first run of the program, press "start monitoring" without loading a dataset to run 
the program with the machine learning systems disabled. When machine learning systems are 
disabled the GUI will only display network alerts detected by the program.

3. Collected packets will be used to generate a raw dataset that is stored as 
dataset_CURRENTDATE.csv in the dataset/raw directory

4. Once a dataset is generated, it can be preprocessed by pressing the "preprocess dataset" 
button and selecting the dataset file. The preprocessed dataset will be saved as 
DATASETNAME_preprocessed.csv in the dataset/preprocessed directory

5. Once the dataset is preprocessed, it can be used to enable the machine learning systems by 
pressing the "load dataset" button and selecting the dataset file. Once the dataset is 
displayed as loaded in the GUI, machine learning algorithms will be run when monitoring is 
enabled. The GUI will display the results of using the machine learning models trained on the 
dataset to make predictions on the live data collected by the system, along with the network 
alert functionality the program has when machine learning systems are disabled.

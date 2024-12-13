# CS499_SecureNetNIDS

## Overview
SecureNet is a real-time Network Intrusion Detection System (NIDS) that monitors and analyzes network traffic to detect suspicious activities or malicious attacks. It leverages machine learning to identify abnormal patterns and generates alerts for potential threats such as unauthorized access, data exfiltration, or Distributed Denial of Service (DDoS) attacks. The system uses cybersecurity best practices, ensuring secure data transmission and a robust detection mechanism.

### Members:
Austin Allen: Front-End Developer\
Bradley Mitchell: Machine Learning Specialist\
Collin Flack: \
Michael Hood: Back-End Developer\
Shane Tucker: Network Engineer

## Goals
1. Real-Time Network Traffic Monitoring
2. Threat Detection with Signature and Anomaly-Based Methods
3. Intrusion Detection Alerts and Reporting
4. Response Automation and Mitigation
5. Vulnerability Scanning and Risk Assessment
6. Secure Data Transmission and Storage
7. Data Visualization Dashboard
8. Machine Learning for Threat Detection

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

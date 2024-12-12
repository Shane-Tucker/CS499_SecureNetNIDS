import pandas as pd # For accessing the dataset
import random
from dataclasses import dataclass
from os import path, makedirs
import time
from dataset_labeler import *



# Object used to store packet information
@dataclass
class dataset_entry():
    src_ip:str
    dst_ip:str
    src_port:int
    dst_port:int
    frame_length:int



# run_datagen_selector
#
def run_datagen_selector():
    user_input = input("Enter dataset file name (or 'random' to generate a random dataset): ")
    column_names = ['src_ip','dst_ip','src_port','dst_port','frame_length']

    if(user_input == 'random'):
        while(user_input.isdigit() == False or int(user_input) <= 0):
            user_input = input("Enter the number of entries to include in the random dataset: ")
        generate_random_dataset(int(user_input))
    elif(user_input == 'today'):
        user_input = './dataset/raw/dataset_' + time.strftime('%Y-%m-%d') + '.csv'
        dataset_preprocessing(user_input, column_names)
    elif path.exists(user_input):
        dataset_preprocessing(user_input, column_names)
    else:
        print('unable to locate file: ', user_input)



# Function to generate a dataset consisting of N randomly generated entries
def generate_random_dataset(N: int):

    file_name = 'dataset_random'
    file_path = './dataset/raw'
    file_format = '.csv'

    # Check if folder to store output files exist, if not create folder
    if not path.isdir(file_path):
        makedirs(file_path)

    output_file_name = file_path + '/' + file_name + file_format
    output_file = open(output_file_name, 'w')

    for i in range(0,N):
        src_ip = str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255))
        dst_ip = str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255))
        testEntry = dataset_entry(src_ip,dst_ip,random.randint(0,65535),random.randint(0,65535),random.randint(0,2000))
        output_file.write(write_dataset_entry(testEntry))

    output_file.close()



# Function to generate a string in dataset-compatable form using the information from a datasetEntry object 
def write_dataset_entry(entry: dataset_entry) -> str:

    # Create movement data string using the data passed to the function
    new_entry = ""
    new_entry += str(entry.src_ip) + ","
    new_entry += str(entry.dst_ip) + ","
    new_entry += str(entry.src_port) + ","
    new_entry += str(entry.dst_port) + ","
    new_entry += str(entry.frame_length) + "\n"

    return new_entry



# dataset_preprocessing
#
def dataset_preprocessing(file, columns):

    # Read in dataset
    data = pd.read_csv(file, header=None, names=columns)

    # Delete duplicate entries from the dataset
    data = data.drop_duplicates(ignore_index=True)

    # Add classification labels to the dataset
    data.insert(5, 'label', -1)
    data = labeler_demo(data)

    # Convert string IP addresses to floats
    for i in range(0, len(data)):
        data.loc[i, 'src_ip'] = ipv4_string_to_float(data.loc[i, 'src_ip'])
        data.loc[i, 'dst_ip'] = ipv4_string_to_float(data.loc[i, 'dst_ip'])

    # Save the preprocessed dataset to a .csv file
    file_name = path.basename(file)
    file_name, ext = path.splitext(file_name)
    file_path = './dataset/preprocessed'
    file_format = '.csv'
    file_name = file_path + '/' + file_name + '_preprocessed' + file_format

    # Check if folder to store output files exist, if not create folder
    if not path.isdir(file_path):
        makedirs(file_path)

    data.to_csv(file_name, sep=',', header=True, index=None)

    return



# ipv4_string_to_float
# Function to convert a string containing an IPv4 address into a float
def ipv4_string_to_float(ip: str):
    split_ip = ip.split('.')

    # Append leading 0's to any ip segment with a value of less than 100 to give every segment a 3-digit length
    for i in range(1, len(split_ip)):
        if len(split_ip[i]) == 2: split_ip[i] = '0' + split_ip[i]
        elif len(split_ip[i]) == 1: split_ip[i] = '00' + split_ip[i]

    float_ready_string = split_ip[0] + '.' + split_ip[1] + split_ip[2] + split_ip[3]
    return float_ready_string



# ipv4_float_to_string
# Function to convert a float containing an IPv4 address into a string
def ipv4_float_to_string(ip: float):
    str_ip = str(ip)

    split_ip = str_ip.split('.')

    full_str_ip = split_ip[0] + '.' + split_ip[1][0:3] + '.' + split_ip[1][3:6] + '.' + split_ip[1][6:9]

    return full_str_ip



# Program start
# Run dataset generation function if dataset_util.py is ran directly
if __name__ == "__main__":
    run_datagen_selector()

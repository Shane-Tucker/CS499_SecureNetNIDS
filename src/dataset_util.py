import pandas as pd # For accessing the dataset
import random
from dataclasses import dataclass
from os import path, makedirs



# Object used to store packet information
@dataclass
class dataset_entry():
    src_ip:str
    dst_ip:str
    src_port:int
    dst_port:int
    frame_length:int



def run_datagen_selector():
    user_input = input("Enter dataset file name (or 'random' to generate a random dataset): ")
    column_names = ['src_ip','dst_ip','src_port','dst_port','frame_length']

    if(user_input == 'random'):
        while(user_input.isdigit() == False or int(user_input) <= 0):
            user_input = input("Enter the number of entries to include in the random dataset: ")
        generate_random_dataset(int(user_input))
    elif path.exists(user_input):
        dataset_preprocessing(user_input, column_names)
    else:
        print('unable to locate file: ', user_input)



# Function to generate a dataset consisting of N randomly generated entries
def generate_random_dataset(N: int):

    fileName = 'dataset_random'
    filePath = './dataset/raw'
    fileFormat = '.csv'

    # Check if folder to store output files exist, if not create folder
    if not path.isdir(filePath):
        makedirs(filePath)

    outputFileName = filePath + '/' + fileName + fileFormat
    outputFile = open(outputFileName, 'w')

    for i in range(0,N):
        src_ip = str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255))
        dst_ip = str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255))
        testEntry = dataset_entry(src_ip,dst_ip,random.randint(0,65535),random.randint(0,65535),random.randint(0,2000))
        outputFile.write(write_dataset_entry(testEntry))

    outputFile.close()



# Function to generate a string in dataset-compatable form using the information from a datasetEntry object 
def write_dataset_entry(entry: dataset_entry) -> str:

    # Create movement data string using the data passed to the function
    newEntry = ""
    newEntry += str(entry.src_ip) + ","
    newEntry += str(entry.dst_ip) + ","
    newEntry += str(entry.src_port) + ","
    newEntry += str(entry.dst_port) + ","
    newEntry += str(entry.frame_length) + "\n"

    return newEntry



def dataset_preprocessing(file, columns):

    # Read in dataset
    data = pd.read_csv(file, header=None, names=columns)
    data.info()
    print(data)

    data.insert(5, 'label', -1)
    data = labeler_test1(data)
    data.info()
    print(data)

    # Convert dataset to purely numeric values
    data.insert(1, 'src_ip1', 0)
    data.insert(2, 'src_ip2', 0)
    data.insert(3, 'src_ip3', 0)
    data.insert(4, 'src_ip4', 0)
    data.insert(6, 'dst_ip1', 0)
    data.insert(7, 'dst_ip2', 0)
    data.insert(8, 'dst_ip3', 0)
    data.insert(9, 'dst_ip4', 0)

    for i in range(0, len(data)):
        ip1,ip2,ip3,ip4 = ipv4StringToInt(data.loc[i,'src_ip'])
        data.loc[i, 'src_ip1'] = ip1
        data.loc[i, 'src_ip2'] = ip2
        data.loc[i, 'src_ip3'] = ip3
        data.loc[i, 'src_ip4'] = ip4

        ip1,ip2,ip3,ip4 = ipv4StringToInt(data.loc[i,'dst_ip'])
        data.loc[i, 'dst_ip1'] = ip1
        data.loc[i, 'dst_ip2'] = ip2
        data.loc[i, 'dst_ip3'] = ip3
        data.loc[i, 'dst_ip4'] = ip4

    #data = data.replace({'label': {'Good': 0, 'Bad': 1}})

    data.info()
    print(data)

    file_name = path.basename(file)
    file_name, ext = path.splitext(file_name)
    filePath = './dataset/preprocessed'
    fileFormat = '.csv'
    file_name = filePath + '/' + file_name + '_preprocessed' + fileFormat

    # Check if folder to store output files exist, if not create folder
    if not path.isdir(filePath):
        makedirs(filePath)

    data.to_csv(file_name, sep=',', header=True, index=None)

    return



# Function to convert a string containing an IPv4 address into 4 integer values, one for each segment of the IP address
def ipv4StringToInt(ip: str):
    s1,s2,s3,s4 = 0,0,0,0
    split_ip = ip.split('.')

    #TODO: make sure input string can be coverted to an int
    s1 = int(split_ip[0])
    s2 = int(split_ip[1])
    s3 = int(split_ip[2])
    s4 = int(split_ip[3])

    return s1,s2,s3,s4



# Dataset labeler function: test 1
# Classification Criteria:
# 0: frame length <= 512
# 1: frame length > 512
def labeler_test1(dataset):

    for i in range(0, len(dataset)):
        if(dataset.loc[i,'frame_length'] > 512): dataset.loc[i, 'label'] = 1
        else: dataset.loc[i, 'label'] = 0

    return dataset



# Program start
if __name__ == "__main__":
    run_datagen_selector()

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



def generate_random_dataset():

    # Generate a dataset consisting of 100 randomly generated entries
    fileName = 'dataset_test_random'
    filePath = './dataset/raw'
    fileFormat = '.csv'

    # Check if folder to store output files exist, if not create folder
    if not path.isdir(filePath):
        makedirs(filePath)

    outputFileName = filePath + '/' + fileName + fileFormat
    outputFile = open(outputFileName, 'w')

    for i in range(0,100):
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


# Program start
if __name__ == "__main__":
    generate_random_dataset()
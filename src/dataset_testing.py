import pandas as pd # For accessing the dataset
import random

# constants
file_path = "dataset_test_random.data"
column_names = ['src_ip','dst_ip','src_port','dst_port','frame_length','label']


# Placeholder for object used to store packet information. Replace/modify to work with format provided by the packet collection method we use
class datasetEntry:
    def __init__(self, src_ip: str, dst_ip: str, frame_length: int, src_port: int, dst_port: int, label: str):
        self._src_ip = src_ip
        self._dst_ip = dst_ip
        self._frame_length = frame_length
        self._src_port = src_port
        self._dst_port = dst_port
        self._label = label

    def getSrcIP(self) -> str: return self._src_ip
    def getDstIP(self) -> str: return self._dst_ip
    def getFrameLength(self) -> int: return self._frame_length
    def getSrcPort(self) -> int: return self._src_port
    def getDstPort(self) -> int: return self._dst_port
    def getLabel(self) -> str: return self._label


def main():

    # Generate a dataset consisting of 100 randomly generated entries
    outputFile = open(file_path, 'w')
    for i in range(0,100):
        randLabel = random.randint(0,1)
        if randLabel == 0: testLabel = "Good"
        if randLabel == 1: testLabel = "Bad"

        src_ip = str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255))
        dst_ip = str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255)) + "." + str(random.randint(0,255))
        testEntry = datasetEntry(src_ip,dst_ip,random.randint(0,256),random.randint(0,65535),random.randint(0,65535), testLabel)
        outputFile.write(writeDatasetEntry(testEntry))
    outputFile.close()


    # Read in dataset
    data = pd.read_csv(file_path, header=None, names=column_names)
    data.info()
    print(data)


# Function to generate a string in dataset-compatable form using the information from a datasetEntry object 
def writeDatasetEntry(entry: datasetEntry) -> str:

    src_ip = entry.getSrcIP()
    dst_ip = entry.getDstIP()
    frame_length = entry.getFrameLength()
    src_port = entry.getSrcPort()
    dst_port = entry.getDstPort()
    label = entry.getLabel()

    # Create movement data string using the data passed to the function
    newEntry = ""
    newEntry += str(src_ip) + ","
    newEntry += str(dst_ip) + ","
    newEntry += str(src_port) + ","
    newEntry += str(dst_port) + ","
    newEntry += str(frame_length) + ","
    newEntry += str(label) + "\n"

    return newEntry


# Program start
if __name__ == "__main__":
    main()
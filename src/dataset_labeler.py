# List of defined labeler functions
# Labeler functions are used by the dataset preprocessor to attach classification labels to the dataset entries
#
# By internal standards, a classification of 0 represents a "normal" entry,
# and a classification of 1 represents an entry that has the "abnormal behavior" the labeler is looking for.
# Labels with more than 2 classification values are not formally supported by the system at this time and may encounter issues when visualizing results.
from os import path, makedirs
import pandas as pd # For accessing the dataset
from dataset_util import *



# Dataset labeler function: large frame length
# A simple labeler to use as an example for writing new labeler functions
# Classification Criteria:
# 0: Normal entry
# 1: Entry with frame length > 512
def labeler_large_frame(dataset: pd.DataFrame):

    for i in range(0, len(dataset)):
        if(dataset.loc[i,'frame_length'] > 512): dataset.loc[i, 'label'] = 1
        else: dataset.loc[i, 'label'] = 0

    return dataset



# Dataset labeler function: presentation demo
# A labeler for use in the presentation demo dataset
# Utilizes each category of dataset attributes stored in the current version of the system (IP, Port, Frame Length) while not requiring multiple machines to be setup for the demo
# Classification Criteria:
# 0: Normal entry
# 1: Packets transmitting webpage contents from an ip listed in the ip watchlist file
def labeler_demo(dataset: pd.DataFrame):

    if not path.isdir('./dataset/labeler_data'):
        makedirs('./dataset/labeler_data')

    # Read in file containing ip addresses to watch for
    ip_watchlist = pd.read_csv('./dataset/labeler_data/ip_list.csv', header=0, names=['ip'])

    # Check the source ip of every dataset entry to see if it is part of the watchlist
    ip_matches = dataset['src_ip'].isin(ip_watchlist['ip'])

    for i in range(0, len(dataset)):
        # Assign default classification of 0 to all entries
        dataset.loc[i, 'label'] = 0

        # Assign classification of 1 to entries that match the source ip, source port, and frame length criteria
        if(ip_matches[i] == True):
            if(dataset.loc[i,'src_port'] == 443):
                if(dataset.loc[i,'frame_length'] > 512): dataset.loc[i, 'label'] = 1

    return dataset

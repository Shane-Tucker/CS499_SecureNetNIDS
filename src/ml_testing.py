import random
import pandas as pd # For accessing the dataset
import numpy as np
from sklearn.cluster import KMeans

# constants
file_path = "dataset_test_random.data"
column_names = ['src_ip','dst_ip','src_port','dst_port','frame_length','label']



def main():

    # Read in dataset
    data = pd.read_csv(file_path, header=None, names=column_names)
    data.info()
    print(data)

    # Convert dataset to purely numeric values
    data_numeric = data.copy()
    data_numeric.insert(1, 'src_ip1', 0)
    data_numeric.insert(2, 'src_ip2', 0)
    data_numeric.insert(3, 'src_ip3', 0)
    data_numeric.insert(4, 'src_ip4', 0)
    data_numeric.insert(6, 'dst_ip1', 0)
    data_numeric.insert(7, 'dst_ip2', 0)
    data_numeric.insert(8, 'dst_ip3', 0)
    data_numeric.insert(9, 'dst_ip4', 0)

    for i in range(0, len(data_numeric)):
        ip1,ip2,ip3,ip4 = ipv4StringToInt(data_numeric.loc[i,'src_ip'])
        data_numeric.loc[i, 'src_ip1'] = ip1
        data_numeric.loc[i, 'src_ip2'] = ip2
        data_numeric.loc[i, 'src_ip3'] = ip3
        data_numeric.loc[i, 'src_ip4'] = ip4

        ip1,ip2,ip3,ip4 = ipv4StringToInt(data_numeric.loc[i,'dst_ip'])
        data_numeric.loc[i, 'dst_ip1'] = ip1
        data_numeric.loc[i, 'dst_ip2'] = ip2
        data_numeric.loc[i, 'dst_ip3'] = ip3
        data_numeric.loc[i, 'dst_ip4'] = ip4

    data_numeric = data_numeric.replace({'label': {'Good': 0, 'Bad': 1}})


    data_numeric.info()
    print(data_numeric)

    randomGuess(data_numeric)
    kmeans_test(data_numeric, ['src_ip1','src_ip2','src_ip3','src_ip4','dst_ip1','dst_ip2','dst_ip3','dst_ip4','src_port','dst_port','frame_length'])



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



# Just make a random prediction
# used to make sure a machine learning algorithm can at least perform better than a random guess
def randomGuess(dataset: pd.DataFrame):
    # Store count of correct/incorrect predictions
    predictions_correct = 0
    predictions_incorrect = 0
    
    # Predict the label of every item in the dataset using random prediction
    for i in range(0, len(dataset)):
        prediction = random.randint(0,1)
        query = dataset.iloc[i]

        if (prediction == query.label): predictions_correct += 1
        else: predictions_incorrect += 1

    # Output the results and accuracy of the predicted classification
    print('\nRandom Prediction Results:')
    print('Correct: ', predictions_correct)
    print('Incorrect: ', predictions_incorrect)
    accuracy = (predictions_correct/len(dataset)) * 100
    print('Accuracy: ', accuracy, '%')

    return



# kmeans_test
# Function to run kmeans clustering on the given dataset
# dataset: pandas DataFrame containing the preprocessed dataset
# testCase: list of strings to select the columns in the dataset that will be used as input variables for the kmeans algorithm
def kmeans_test(data: pd.DataFrame, testCase):

    # Run K-Means Clustering for 2 clusters
    kmeans_bin = KMeans(n_clusters=2, init='random', n_init='auto').fit(data[testCase])

    # Create result matrix
    result_matrix_bin = np.zeros((2,2), int)

    # Row = Dataset Label, Column = Predicted Cluster
    for i in range(0, data.shape[0]):
        row_pos = 0

        if (data.iloc[i].label == 0): row_pos = 0 # Good
        else: row_pos = 1                         # Bad

        result_matrix_bin[row_pos][kmeans_bin.labels_[i]] = result_matrix_bin[row_pos][kmeans_bin.labels_[i]] + 1

    result_dataframe_bin = pd.DataFrame(result_matrix_bin, columns=['C0', 'C1'], index=['Good', 'Bad'])

    # Output results
    print('\nK-Means Clustering Results (2 Clusters):')
    print(result_dataframe_bin)

    return



# Program start
if __name__ == "__main__":
    main()
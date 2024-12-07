import random
import pandas as pd # For accessing the dataset
import numpy as np
from sklearn.cluster import KMeans
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split

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

    # Split the dataset into a training set and a testing set
    data_train, data_test = train_test_split(data_numeric, test_size=0.2)

    # Run various machine learning algorithms and measure their prediction accuracy for the given dataset
    randomGuess(data_numeric)
    kmeans_test(data_numeric, ['src_ip1','src_ip2','src_ip3','src_ip4','dst_ip1','dst_ip2','dst_ip3','dst_ip4','src_port','dst_port','frame_length'], 4)
    knn_test(data_train, data_test, ['src_ip1','src_ip2','src_ip3','src_ip4','dst_ip1','dst_ip2','dst_ip3','dst_ip4','src_port','dst_port','frame_length'], 5)

    #data_labeler = data.copy()
    #data_labeler.insert(6, 'test', -1)
    #data_labeler = testLabeler(data_labeler)
    #print(data_labeler)

    return



def testLabeler(dframe):

    for i in range(0, len(dframe)):
        dframe.loc[i, 'test'] = dframe.loc[i, 'frame_length'] + 3

    return dframe



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
# Function to run k-means clustering on the given dataset
# dataset: pandas DataFrame containing the preprocessed dataset
# test_case: list of strings to select the columns in the dataset that will be used as input variables for the kmeans algorithm
# cluster_count: the number of clusters to form using k-means clustering
def kmeans_test(data: pd.DataFrame, test_case, cluster_count: int):

    # Run K-Means Clustering
    kmeans = KMeans(n_clusters=cluster_count, init='random', n_init='auto').fit(data[test_case])

    # Create result matrix
    result_matrix = np.zeros((2,cluster_count), int)

    # Row = Dataset Label, Column = Predicted Cluster
    for i in range(0, data.shape[0]):
        row_pos = 0

        if (data.iloc[i].label == 0): row_pos = 0 # Good
        else: row_pos = 1                         # Bad

        result_matrix[row_pos][kmeans.labels_[i]] = result_matrix[row_pos][kmeans.labels_[i]] + 1

    result_dataframe_bin = pd.DataFrame(result_matrix, index=['Good', 'Bad'])

    # Output results
    print('\nK-Means Clustering Results (', cluster_count, 'Clusters ):')
    print(result_dataframe_bin)

    return



# knn_test
# Function to run k-nearest neighbors (knn) algorithm on the given dataset
# data_train: pandas DataFrame containing the preprocessed training dataset
# data_test: pandas DataFrame containing the preprocessed testing dataset
# test_case: list of strings to select the columns in the dataset that will be used as input variables for the knn algorithm
# k: the value of k in the knn algorithm. the number of closest entries in dataset to use for making a prediction
def knn_test(data_train: pd.DataFrame, data_test: pd.DataFrame, test_case, k: int):

    # Split the feature columns and label columns of the training set into two different numpy arrays
    data_train_x = data_train[test_case]
    data_train_y = data_train['label']

    # Run knn on the dataset
    knn = KNeighborsClassifier(n_neighbors=k).fit(data_train_x, data_train_y)
    knn_result = knn.predict(data_test[test_case])

    # Store count of correct/incorrect predictions
    predictions_correct = 0
    predictions_incorrect = 0

    # Compare each prediction to its labeled value to determine prediction accuracy
    for i in range(0, len(data_test)):
        query = data_test.iloc[i]

        if (knn_result[i] == query.label): predictions_correct += 1
        else: predictions_incorrect += 1

    # Output the results and accuracy of the predicted classification
    print('\nKNN Results ( K = ', k, ')')
    print('Correct: ', predictions_correct)
    print('Incorrect: ', predictions_incorrect)
    accuracy = (predictions_correct/len(data_test)) * 100
    print('Accuracy: ', accuracy, '%\n\n')

    return



# Program start
if __name__ == "__main__":
    main()
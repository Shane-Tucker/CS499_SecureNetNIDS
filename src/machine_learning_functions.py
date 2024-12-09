import random
import pandas as pd # For accessing the dataset
import numpy as np
from sklearn.cluster import KMeans
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
#import matplotlib.pyplot as plt

# constants
#file_path = "./dataset/preprocessed/dataset_random_preprocessed.csv"
file_path = "./dataset/preprocessed/dataset_raw_2024-12-07_preprocessed.csv"
column_names = ['src_ip','dst_ip','src_port','dst_port','frame_length','label']



def run_test():

    # Read in dataset
    data = pd.read_csv(file_path, header=0, names=column_names)
    data.info()
    print(data)

    # Split the dataset into a training set and a testing set
    data_train, data_test = train_test_split(data, test_size=0.2)

    # Run various machine learning algorithms and measure their prediction accuracy for the given dataset
    randomGuess(data_test)
    
    knn_model = knn_train(data_train, ['src_ip','dst_ip','src_port','dst_port','frame_length'], 5)
    knn_test(knn_model, data_test, ['src_ip','dst_ip','src_port','dst_port','frame_length'], 5)

    kmeans_model = kmeans_train(data_train, ['src_ip','dst_ip','src_port','dst_port','frame_length'], 2)
    kmeans_test(kmeans_model, data_test, ['src_ip','dst_ip','src_port','dst_port','frame_length'], 2)

    return



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



# kmeans_train
# Function to train the model for k-means clustering on the given dataset
# data: pandas DataFrame containing the preprocessed training dataset
# test_case: list of strings to select the columns in the dataset that will be used as input variables for the kmeans algorithm
# cluster_count: the number of clusters to form using k-means clustering
def kmeans_train(data: pd.DataFrame, test_case, cluster_count: int):

    # Run K-Means Clustering on the dataset
    model = KMeans(n_clusters=cluster_count, init='random', n_init='auto').fit(data[test_case])

    return model



# kmeans_test
# Function to run the k-means clustering model to predict the given dataset
# data: pandas DataFrame containing the preprocessed testing dataset
# test_case: list of strings to select the columns in the dataset that will be used as input variables for the kmeans algorithm
# cluster_count: the number of clusters to form using k-means clustering
def kmeans_test(model, data: pd.DataFrame, test_case, cluster_count: int):

    # Run K-Means Clustering
    kmeans = model.predict(data[test_case])

    # Create result matrix
    result_matrix = np.zeros((2,cluster_count), int)

    # Row = Dataset Label, Column = Predicted Cluster
    for i in range(0, data.shape[0]):
        row_pos = 0

        if (data.iloc[i].label == 0): row_pos = 0 # Good
        else: row_pos = 1                         # Bad

        result_matrix[row_pos][kmeans[i]] = result_matrix[row_pos][kmeans[i]] + 1

    result_dataframe= pd.DataFrame(result_matrix, index=['Good', 'Bad'])

    # Output results
    print('\nK-Means Clustering Results (', cluster_count, 'Clusters ):')
    print(result_dataframe)

    return



# knn_train
# Function to train the model for the k-nearest neighbors (knn) algorithm on the given dataset
# data: pandas DataFrame containing the preprocessed training dataset
# test_case: list of strings to select the columns in the dataset that will be used as input variables for the knn algorithm
# k: the value of k in the knn algorithm. the number of closest entries in dataset to use for making a prediction
def knn_train(data: pd.DataFrame, test_case, k: int):

    # Split the feature columns and label columns of the training set into two different numpy arrays
    data_x = data[test_case]
    data_y = data['label']

    # Run knn on the dataset
    model = KNeighborsClassifier(n_neighbors=k).fit(data_x, data_y)
    
    return model



# knn_test
# Function to run the k-nearest neighbors model to predict the given dataset
# model: trained knn model used for making predictions
# data: pandas DataFrame containing the preprocessed testing dataset
# test_case: list of strings to select the columns in the dataset that will be used as input variables for the knn algorithm
# k: the value of k in the knn algorithm. the number of closest entries in dataset to use for making a prediction
def knn_test(model, data_test: pd.DataFrame, test_case, k: int):
    
    knn_result = model.predict(data_test[test_case])

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
    run_test()
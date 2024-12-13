# Internal classes
from dataset_util import *
# Python Standard Library
import random
# External Libraries
import pandas as pd # For accessing the dataset
import numpy as np
from sklearn.cluster import KMeans
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split

# run_test
# Test driver for machine learning functions
# only called if machine_learning_functions.py is ran directly
def run_test():

    file_path = "./dataset/preprocessed/dataset_random_preprocessed.csv"
    column_names = ['src_ip','dst_ip','src_port','dst_port','frame_length','label']

    # Read in dataset
    data = pd.read_csv(file_path, header=0, names=column_names)
    data.info()
    print(data)

    # Split the dataset into a training set and a testing set
    data_train, data_test = train_test_split(data, test_size=0.2)

    # Run various machine learning algorithms and measure their prediction accuracy for the given dataset    
    knn_model = knn_train(data_train, ['src_ip','dst_ip','src_port','dst_port','frame_length'], 5)
    knn_results = knn_test(knn_model, data_test, ['src_ip','dst_ip','src_port','dst_port','frame_length'])
    knn_visuals = knn_visualize(data_test, knn_results, 5)

    kmeans_model = kmeans_train(data_train, ['src_ip','dst_ip','src_port','dst_port','frame_length'], 5)
    kmeans_results = kmeans_test(kmeans_model, data_test, ['src_ip','dst_ip','src_port','dst_port','frame_length'])
    kmeans_visuals = kmeans_visualize(data_test, kmeans_results, 5)
    
    # Output results
    print('\nKNN Results ( K = ', 5, ')')
    for i in range(0, len(knn_visuals)):
                query = knn_visuals.iloc[i]
                print(ipv4_float_to_string(query['src_ip']), query['prediction'], query['size'])
    print('\nK-Means Clustering Results (', 5, 'Clusters ):')
    print(kmeans_visuals)

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
def kmeans_test(model, data: pd.DataFrame, test_case):
    # Run K-Means Clustering
    results = model.predict(data[test_case])
    return results

# kmeans_visualize
# Function to print results of running k-means clustering on the dataset
def kmeans_visualize(data: pd.DataFrame, results, cluster_count: int):
    # Print kmeans results
    result_dataframe = pd.DataFrame(data={'cluster_elements': np.zeros(cluster_count, np.int64), 'cluster_size_ratio': np.zeros(cluster_count, np.float64)})

    # Row = Dataset Label, Column = Predicted Cluster
    if (len(data) > 0):
        for i in range(0, len(data)):
            result_dataframe.loc[results[i], 'cluster_elements'] = result_dataframe.loc[results[i], 'cluster_elements'] + 1
        
        for i in range(0, cluster_count):
            result_dataframe.loc[i, 'cluster_size_ratio']  = result_dataframe.loc[i, 'cluster_elements'] / len(data)

    result_dataframe = result_dataframe.sort_values(by=['cluster_size_ratio'], ascending=False, ignore_index=True)

    return result_dataframe

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
def knn_test(model, data_test: pd.DataFrame, test_case):
    results = model.predict(data_test[test_case])
    return results

# knn_visualize
# Function to print results of running k-nearest neighbors on the dataset
def knn_visualize(data: pd.DataFrame, results):
    # Print knn results
    data.insert(5, 'prediction', results)

    groups = data.groupby(['src_ip','prediction'], sort=True, as_index=False)
    output = groups.size()

    return output

# Program start
# Run test driver function if machine_learning_functions.py is ran directly
if __name__ == "__main__":
    run_test()
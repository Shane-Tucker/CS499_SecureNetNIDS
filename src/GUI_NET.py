# Internal classes
from dataset_util import *
import network_functions
# Python Standard Libraries
import sys
import threading
from datetime import datetime
from queue import Queue
# External Libraries
import psutil
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QComboBox, QTableWidget, QTableWidgetItem, QWidget, QLineEdit, QDialog, QDialogButtonBox, QFileDialog
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QObject, QThread
import pandas as pd

stop_event = threading.Event()

class AlertHandler(QObject):
    new_alert = pyqtSignal(list)  # Signal to pass new alert to the main thread

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureNet Application")
        self.setGeometry(100, 100, 800, 600)

        # Store the selected dataset file name to pass to machine learning functions
        self.dataset_file_name = ''

        # Set central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Top Layout for buttons and dropdown
        self.top_layout = QHBoxLayout()
        self.main_layout.addLayout(self.top_layout)

        # Add Start and Stop buttons
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.top_layout.addWidget(self.start_button)
        self.top_layout.addWidget(self.stop_button)

        # Add buttons to load and preprocess datasets
        self.load_dataset_button = QPushButton("Load Dataset")
        self.preprocess_dataset_button = QPushButton("Preprocess Dataset")
        self.top_layout.addWidget(self.load_dataset_button)
        self.top_layout.addWidget(self.preprocess_dataset_button)

        # Add dropdown for IP selection
        self.dataset_label = QLabel("ML Dataset Loaded: None")
        self.top_layout.addWidget(self.dataset_label)

        # Add a label to display network information
        self.network_label = QLabel("Monitoring not started.")
        self.main_layout.addWidget(self.network_label)

        # Add a data grid (table) in the center for K-Nearest Neighbor classification results
        self.classification_table_label = QLabel("K-Nearest Neighbor Classification Results")
        self.main_layout.addWidget(self.classification_table_label)
        self.classification_table = QTableWidget(0, 4)  # Updated to 5 columns
        self.classification_table.setHorizontalHeaderLabels(["Time", "Source IP", "Predicted Classification", "Number of Occurences"])
        self.classification_table.setColumnWidth(0, 128)
        self.classification_table.setColumnWidth(1, 100) # IP fields
        self.classification_table.setColumnWidth(2, 192)
        self.classification_table.setColumnWidth(3, 192)
        self.main_layout.addWidget(self.classification_table)

        # Add a data grid (table) in the center for K-Means Clustering results
        self.clustering_result_table_label = QLabel("K-Means Clustering Results")
        self.main_layout.addWidget(self.clustering_result_table_label)
        self.clustering_result_table = QTableWidget(2, 5)  # Updated to 5 columns
        self.clustering_result_table.setHorizontalHeaderLabels(["c1", "c2", "c3", "c4", "c5"])
        self.clustering_result_table.setVerticalHeaderLabels(["Packets in Cluster", "Total Packet %"])
        self.clustering_result_table.setMinimumHeight(150)
        self.clustering_result_table.setMaximumHeight(150)
        self.main_layout.addWidget(self.clustering_result_table)

        # Add a data grid (table) in the center for detected alerts
        self.alert_table_label = QLabel("Detection Alerts")
        self.main_layout.addWidget(self.alert_table_label)
        self.network_table = QTableWidget(0, 5)  # Updated to 5 columns
        self.network_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Severity", "Flag"])
        self.main_layout.addWidget(self.network_table)

        # Connect buttons to start/stop methods
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)

        # Connect buttons to load/preprocess dataset methods
        self.load_dataset_button.clicked.connect(self.load_dataset)
        self.preprocess_dataset_button.clicked.connect(self.preprocess_dataset)
        
        # Create handler to update table with alert info
        self.alert_handler = AlertHandler()
        self.alert_handler.new_alert.connect(self.update_table)

        # Apply dark mode stylesheet
        self.apply_stylesheet()

    # Function to start network monitoring systems
    def start_monitoring(self):
        self.start_button.setEnabled(False) # Ensures monitoring isn't started multiple times
        alerts = Queue()
        classification_results = Queue()
        clustering_results = Queue()
        seen_alerts = []

        stop_event.clear()
        self.network_label.setText("Monitoring running.")
        start_monitoring_thread = threading.Thread(target=network_functions.start_network_monitoring, args=(alerts, stop_event, self.dataset_file_name, classification_results, clustering_results))
        start_monitoring_thread.daemon = True
        start_monitoring_thread.start()
        
        # Function to update the detected alerts table
        def process_alerts(alerts, stop_event, seen_alerts):
            while not stop_event.is_set():
                while not alerts.empty():
                    alert = alerts.get()
                    if len(seen_alerts) >= 100: #Keeps record of past 100 alerts
                        seen_alerts.pop(0)
                    if alert not in seen_alerts: #Removes duplicate alerts
                        seen_alerts.append(alert)
                        self.alert_handler.new_alert.emit(alert)  # Emit alert to main thread

        # Start new thread to update the detected alerts table
        start_alert_thread = threading.Thread(target=process_alerts, args=(alerts, stop_event, seen_alerts, ))
        start_alert_thread.daemon = True
        start_alert_thread.start()

        # Function to update the classification and clustering result tables
        def output_ml_results(classification_results, clustering_results, stop_event):
            while not stop_event.is_set():
                while not classification_results.empty():
                    classification_result = classification_results.get()
                    self.update_classification_result_table(classification_result)
                while not clustering_results.empty():
                    clustering_result = clustering_results.get()
                    self.update_clustering_result_table(clustering_result)
        
        # Start new thread to update the classification and clustering result tables
        start_ml_result_thread = threading.Thread(target=output_ml_results, args=(classification_results, clustering_results, stop_event))
        start_ml_result_thread.daemon = True
        start_ml_result_thread.start()

    # Function to stop network monitoring systems
    def stop_monitoring(self):
        stop_event.set()
        #self.timer.stop()
        self.network_label.setText("Monitoring stopped.")
        self.start_button.setEnabled(True) # Reenables the start button
        print("Sniffing Stopped")

    # Function to select the dataset file to use for the machine learning systems
    def load_dataset(self):
        file_name, file_extension = QFileDialog.getOpenFileName(self, "Select dataset file", "./dataset/preprocessed", "*.csv")
        if (file_name != ''): 
            self.dataset_file_name = file_name
            file_label = "ML Dataset Loaded: " + file_name
            self.dataset_label.setText(file_label)
        else: 
            self.dataset_label.setText("ML Dataset Loaded: None")
    
    # Function to select a dataset file to perform preprocessing on
    def preprocess_dataset(self):
        file_name, file_extension = QFileDialog.getOpenFileName(self, "Select dataset file", "./dataset/raw", "*.csv")
        if (file_name != ''): dataset_preprocessing(file_name, ['src_ip','dst_ip','src_port','dst_port','frame_length'])

    # Function to update the displayed information on the K-Nearest Neighbor classification result table
    def update_classification_result_table(self, data: pd.DataFrame):
        # Add new row to the top of the table to seperate sets of results
        self.classification_table.insertRow(0)

        # Add a row for each recorded address in the results dataframe
        for i in range(0, len(data)):
            self.classification_table.insertRow(0)
            query = data.iloc[i]
        
            # Get the current date and time
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.classification_table.setItem(0, 0, QTableWidgetItem(current_time))
            self.classification_table.setItem(0, 1, QTableWidgetItem(ipv4_float_to_string(query['src_ip'])))
            self.classification_table.setItem(0, 2, QTableWidgetItem(str(query['prediction'])))  # Placeholder for destination IP
            self.classification_table.setItem(0, 3, QTableWidgetItem(str(query['size'])))

        self.classification_table.update()
    
    # Function to update the displayed information on the K-Means Clustering result table
    def update_clustering_result_table(self, data: pd.DataFrame):
        # Clear previous entries
        self.clustering_result_table.setRowCount(0)
        self.clustering_result_table.insertRow(0)
        self.clustering_result_table.insertRow(1)
        self.clustering_result_table.setVerticalHeaderLabels(["Cluster Elements", "Cluster Size Ratio"])

        # Print the results from the dataframe
        for i in range(0, len(data)):
            self.clustering_result_table.setItem(0, i, QTableWidgetItem(str(data.loc[i,'cluster_elements'])))
            self.clustering_result_table.setItem(1, i, QTableWidgetItem(f"{data.loc[i,'cluster_size_ratio']:.2f}"))

        self.clustering_result_table.update()
    
    # Function to update the displayed information on the detected alerts table
    def update_table(self, alert):
        row_position = self.network_table.rowCount()
        self.network_table.insertRow(row_position) #Insert new row
        self.network_table.setItem(row_position, 0, QTableWidgetItem(alert[4])) # Enter time
        self.network_table.setItem(row_position, 1, QTableWidgetItem(alert[1])) # Enter source
        self.network_table.setItem(row_position, 2, QTableWidgetItem(alert[2])) # Enter destination
        self.network_table.setItem(row_position, 3, QTableWidgetItem(alert[3])) # Enter severity
        self.network_table.setItem(row_position, 4, QTableWidgetItem(alert[0])) # Enter reason for flag

        self.network_table.update()

    # Function to apply the stylesheet used by the GUI
    def apply_stylesheet(self):
        dark_mode_stylesheet = """
            QWidget {
                background-color: #2E2E2E;
                color: #E0E0E0;
            }
            QTableWidget {
                background-color: #3E3E3E;
                alternate-background-color: #454545;
                gridline-color: #555555;
            }
            QTableWidget::item {
                border: none;
                padding: 5px;
            }
            QTableView QTableCornerButton::section {
                background-color: #4E4E4E;
            }
            QHeaderView::section {
                background-color: #4E4E4E;
                color: #E0E0E0;
                padding: 5px;
                border: 1px solid #565656;
            }
            QPushButton {
                background-color: #5E5E5E;
                color: #FFFFFF;
                border: 1px solid #767676;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #6E6E6E;
            }
            QComboBox {
                background-color: #5E5E5E;
                color: #FFFFFF;
                border: 1px solid #767676;
                padding: 5px;
            }
            QComboBox QAbstractItemView {
                background-color: #5E5E5E;
                border: 1px solid #767676;
            }
        """
        self.setStyleSheet(dark_mode_stylesheet)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

import sys
import psutil
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QComboBox, QTableWidget, QTableWidgetItem, QWidget, QLineEdit, QDialog, QDialogButtonBox
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtWidgets import QTableWidgetItem
from datetime import datetime

class IPDialog(QDialog):
    def __init__(self, ip=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter IP Address")
        self.setGeometry(300, 300, 300, 150)

        self.layout = QVBoxLayout(self)

        self.label = QLabel("Enter IP Address:", self)
        self.layout.addWidget(self.label)

        self.ip_input = QLineEdit(self)
        if ip:
            self.ip_input.setText(ip)
        self.layout.addWidget(self.ip_input)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)

    def get_ip(self):
        return self.ip_input.text()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Net Application")
        self.setGeometry(100, 100, 800, 600)

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

        # Add dropdown for IP selection
        self.ip_dropdown = QComboBox()
        self.ip_dropdown.addItem("All IPs")
        self.ip_dropdown.addItem("Specific Incoming IP")
        self.top_layout.addWidget(self.ip_dropdown)

        # Add a label to display network information
        self.network_label = QLabel("Network Information")
        self.main_layout.addWidget(self.network_label)

        # Add a data grid (table) in the center for network traffic
        self.network_table = QTableWidget(0, 5)  # Updated to 5 columns
        self.network_table.setHorizontalHeaderLabels(["Time", "Source IP", "Destination IP", "Data Usage", "Flagged"])
        self.main_layout.addWidget(self.network_table)

        # Setup a timer to update the label
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_network_info)

        # Connect buttons to start/stop methods
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)

        # Connect table click event to handle IP selection
        self.network_table.cellDoubleClicked.connect(self.handle_cell_click)

        # Apply dark mode stylesheet
        self.apply_stylesheet()

    def start_monitoring(self):
        self.timer.start(1000)  # Update every second
        self.network_label.setText("Monitoring started...")

    def stop_monitoring(self):
        self.timer.stop()
        self.network_label.setText("Monitoring stopped.")

    def update_network_info(self):
        # Clear previous entries
        self.network_table.setRowCount(0)

        # Fetch network traffic data using psutil
        counters = psutil.net_io_counters(pernic=True)
        
        for nic, counter in counters.items():
            row_position = self.network_table.rowCount()
            self.network_table.insertRow(row_position)
            self.network_table.setItem(row_position, 0, QTableWidgetItem("Now"))  # Placeholder for time
            self.network_table.setItem(row_position, 1, QTableWidgetItem(nic))
            # Get the current date and time
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.network_table.setItem(row_position, 0, QTableWidgetItem(current_time))
            self.network_table.setItem(row_position, 3, QTableWidgetItem(f"{counter.bytes_sent} Bytes Sent, {counter.bytes_recv} Bytes Received"))
            self.network_table.setItem(row_position, 4, QTableWidgetItem("No"))  # Placeholder for flagged

    def handle_cell_click(self, row, column):
        if self.ip_dropdown.currentText() == "Specific Incoming IP":
            source_ip = self.network_table.item(row, 1).text()
            ip_dialog = IPDialog(ip=source_ip, parent=self)
            if ip_dialog.exec_():
                selected_ip = ip_dialog.get_ip()
                print("Selected IP:", selected_ip)  # Process the selected IP

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
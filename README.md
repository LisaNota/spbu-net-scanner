# Network Scanner

## Project Description
This project aims to develop a network scanner tool capable of scanning and analyzing network activity. The application provides functionalities for scanning network nodes and analyzing the results, including information about open ports, services running on those ports, and geographical details of the target IP address.

## Features
- **Port Scanning**: Scans specified ports on the target IP address to identify open ports.
- **Service Identification**: Identifies services running on open ports.
- **Geographical Information**: Retrieves geographical information about the target IP address using IPInfo.io API.
- **User Interface**: Provides a graphical user interface (GUI) built using Tkinter for easy interaction.

## Installation
1. Clone the repository: `git clone https://github.com/username/repository.git`
2. Install the required dependencies: `pip install -r requirements.txt`

## Usage
1. Run the Python script `network_scanner.py` to launch the application.
2. Enter the target IP address and specify the ports to scan (optional).
3. Click the "Scan" button to initiate the scanning process.
4. View the results, including host information, geographical details, open ports, and services running on those ports, displayed in the GUI.

## Dependencies
- tkinter
- requests


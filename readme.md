# ✨ SpectreEye Wi-Fi Security ✨

SpectreEye is a passive Wi-Fi security auditor built with **Python** and **PyQt6**. It's a simple, intuitive tool for scanning local wireless networks, analyzing their security, and generating professional reports.

***

### 🚀 Features

* **Wi-Fi Scanning**: Discover available networks and gather key information like SSID, authentication, and encryption methods.
* **Security Analysis**: The app analyzes network configurations, providing severity ratings (**High**, **Medium**, **Low**) and clear suggestions to improve your network security.
* **Dynamic UI**: Get real-time visual feedback with a loading indicator during scans, making the app feel responsive and modern.
* **Report Generation**: Easily export your scan results into a clean, formatted HTML report for sharing or record-keeping.
* **Dashboard**: A quick overview of all your scans, including a summary of total networks and identified vulnerabilities.

***

### 📋 Requirements

* Python 3.x
* PyQt6
* qtawesome
* jinja2 (for HTML reports)
* A Windows operating system (the scanner uses `netsh`)

***

### Installation

To get started, make sure you have Python 3.x installed. Then, install the necessary libraries with `pip`:

```bash
  pip install PyQt6 qtawesome jinja2    
```

***
### 💻 Usage

#### Run the Application

```bash
  python main.py
```

***

### Scan Networks

Go to the Scanner page and click "Scan Networks." The application will automatically find and analyze nearby Wi-Fi networks.

### Review Results

The scan results will appear in a table. Click any row to see detailed information and security suggestions in the pane below.

### Export a Report

Once the scan is finished, click "Export HTML Report" to save a professional summary of your findings.

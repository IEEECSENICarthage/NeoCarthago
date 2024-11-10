### Overview

#### 1. `model.ipynb`

This Jupyter notebook contains the steps for training and evaluating a machine learning model to detect network intrusions. It includes:

1. **Data Preprocessing**: Loads and cleans the UNSW-NB15 dataset, selecting and normalizing features relevant to network traffic classification.
2. **Feature Importance and Selection**: Analyzes feature importance to select the most impactful features for the model.
3. **Model Training and Evaluation**: Trains multiple machine learning models and evaluates their accuracy, precision, recall, and F1 score to identify the best-performing model.
4. **Exporting the Model**: Saves the trained model and scaler for use in real-time packet analysis.

#### 2. `app.py`

This Python script captures live network packets, extracts features, and utilizes the trained model to classify packets in real time. It operates as follows:

1. **Packet Capture**: Uses `pyshark` to capture live packets on the network interface, filtering for IP packets.
2. **Feature Extraction**: Extracts relevant features from each packet and preprocesses them to match the model’s requirements.
3. **Real-Time Classification**: Applies the model to classify packets, logging detected threats and blocking suspicious IPs using `iptables`.
4. **Logging for Monitoring**: Logs events to a Wazuh-compatible log file, enabling real-time monitoring on the Wazuh dashboard.

#### 3. `data/`

This folder contains the training and testing datasets used to develop and validate the model:

- `UNSW_NB15_training-set.csv`: The training dataset for model development.
- `UNSW_NB15_testing-set.csv`: The testing dataset for evaluating model accuracy.

---

This setup enables real-time network monitoring, traffic classification, and automated threat response based on machine learning analysis.

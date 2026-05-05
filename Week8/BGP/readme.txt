BGP Anomaly Detection System
Overview
The Border Gateway Protocol (BGP) is the core routing protocol of the Internet. It enables Autonomous Systems (AS) to exchange routing information and determine how data flows across networks.
BGP operates using two main message types:
Announcements (A): Advertise new routes
Withdrawals (W): Remove routes
Anomalies in BGP occur when routing behavior deviates from normal patterns. These anomalies can be caused by worm outbreaks, network failures, misconfigurations, or large-scale outages. Typical indicators include sudden spikes in announcements or withdrawals, unusual routing paths, and instability.
This project builds a complete pipeline to detect such anomalies using statistical methods and machine learning.
---
Pipeline Overview
The system follows a structured workflow from raw BGP data to anomaly detection.
---
Step 1 — Data Collection
File: `1_BGP_Data_Collection.py`
Collects BGP UPDATE messages from RIPE RIS collectors (RRC00 and RRC04)
Extracts data for both anomalous and normal periods
Stores raw data in:
data/raw/
Note: Raw data is not included in the repository due to its large size.
---
Step 2 — Preprocessing
File: `2_preprocess.py`
Converts raw BGP updates into structured data
Groups messages into 3-minute time windows
Extracts features such as:
Number of announcements
Number of withdrawals
AS path statistics
Routing instability metrics
Handles missing intervals using interpolation
Output:
data/processed/*_features.csv
---
Step 3 — Combine Features
File: `3_combine_features.py`
Merges all processed feature files into a single dataset
Output:
data/processed/all_features_combined.csv
---
Step 4 — MAD-Based Anomaly Detection
Files:
`4_mad_detection.py`
`4.2_mad_detection_per_event.py`
Uses Median Absolute Deviation (MAD) to identify abnormal behavior
Computes baseline using only normal data
Detects anomalies based on deviations in:
Announcements
Withdrawals
Applies persistence filtering to remove short-lived noise
This step produces refined labels:
`occurrence_label`: based on time windows (noisy)
`mad_label`: based on statistical behavior (refined)
Output:
data/processed/labelled_dataset.csv
---
Step 5 — Dataset Preparation
File: `5_dataset_prep.py`
Uses `mad_label` as the training target
Splits data into training (80%) and testing (20%)
Handles class imbalance by oversampling anomalies in the training set
Output:
data/processed/train.csv
data/processed/test.csv
---
Step 6 — Supervised Learning
Models used:
Random Forest
XGBoost
These models are chosen because:
They work well with structured tabular data
They capture non-linear relationships
They are robust to noise
The models learn patterns of abnormal routing behavior and are used for final anomaly detection.
---
Step 7 — Unsupervised Learning
File: `prepare_unsupervised_dataset.py`
Creates datasets using only normal data for training
Uses mixed data (normal + anomaly) for testing
Applies models such as:
Isolation Forest
One-Class SVM
Output:
train_unsupervised.csv
test_unsupervised.csv
This step is used to evaluate anomaly detection without labeled data.
---
Data Directory Structure
data/
├── raw/            # Raw BGP data (not included)
└── processed/
├── *_features.csv
├── all_features_combined.csv
├── labelled_dataset.csv
├── train.csv
├── test.csv
├── train_unsupervised.csv
└── test_unsupervised.csv
---
Key Concepts
Feature Engineering: Converts raw BGP messages into structured behavioral features
MAD (Median Absolute Deviation): Refines noisy labels using statistical deviation
Supervised Learning: Learns anomaly patterns using refined labels
Unsupervised Learning: Detects anomalies without labels for comparison
---
Final Pipeline
Raw BGP Data
↓
Preprocessing (3-minute windows)
↓
Feature Extraction
↓
MAD-Based Label Refinement
↓
Dataset Preparation
↓
Machine Learning Models
↓
Anomaly Detection
---
Conclusion
This project demonstrates a complete workflow for detecting BGP anomalies using real-world routing data. It combines statistical methods and machine learning to build a reliable and scalable anomaly detection system.
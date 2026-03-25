# Weekly Progress Report

## Week 1

### Action Items
- Set up a GitHub account where project progress can be uploaded.
- Identify the common types of anomalies in network packets.
- Research techniques used to detect these anomalies.
- Familiarize with AI/ML algorithms and methods commonly used for anomaly detection.
- Explore available data sources for training models.
- Identify open-source libraries and frameworks useful for implementation.


## Week 2

### Action Items

- Use the CICDS & UNSW datasets to train different models (autoencoder & isolation forest was preferred & would be tried first). Check anomaly detection accuracy on the training sample within the dataset.
- For the above trained model, test with a sample from the real world (sample outside the training set) & check accuracy.
- Following are some protocol/packet types for which you could start studying different kinds of anomalies & what techniques could be used to handle those. Again look at different ML algorithms & explore datasets available:
    1. Quality of Service (QoS)
    2. VoIP/RTP traffic
    3. Multicast traffic
    4. DHCP
    5. DNS

## Week 3

### Action Items

- Evaluate the Isolation Forest model trained on CICIDS dataset using external (real-world) anomaly samples.[Naga Phani]

- Train and evaluate an XGBoost model for anomaly detection similar tests can be performed.[Prakash]
  
- Demonstrate the autoencoders model trained on the UNSW dataset.[Yogendra]  

- Experiment with multiple models and datasets for protocol-specific anomaly detection:  
  - Quality of Service (QoS) anomalies [Naga Phani]
  - VoIP/RTP traffic anomalies [Yadunath]  
  - Multicast traffic anomalies [Prakash]  
  - DHCP anomalies [Yogendra]  
  - DNS anomalies [Pavan]  
  - Select relevant datasets for each protocol.  
  - Measure and compare prediction accuracy across models.

- Explore techniques to generate benign/malicious training data.  

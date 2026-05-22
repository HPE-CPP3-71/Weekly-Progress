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

## Week 4 & 5

### Action Items

- Create a datasets for the protocol that has been assigned to you and train and test the corresponding ML model to see if the accuracy is staying the same or the performance is decreasing.

## Week 6

### Action Items

- For protocols which did not have a good data set & where in-lab data generation was needed: try to generate a more voluminous dataset for robust training.
- For CICFlowMeter falures check if an AI tool can suggest any fixes for the failures on select packet types
- If the above is not feasible see if a tool can be written (again using AI) to generate flows & extract features from the pcaps. This may not be an easy task. Try this only if 2) doesn’t work.
- Other than the said protocol types the below were a few more you can start looking at.
    - ARP
    - ICMP
    - OSPF
    - BGP

## Week 7

- Test the generated data on already trained models and report the metrics.

## Week 11

### Action Items

- find the set of new protocols that we can start looking at.
    - TLS/SSL
    - HTTP/HTTPS
    - STP/RSTP/MSTP
    - LLDP/CDP
    - QoS – I know we already had this in our earlier list. We dropped this as we did not have any open source data set. Wanted to revisit this &                 check if a synthetic data set can be generated for this. We will discuss in our next meeting

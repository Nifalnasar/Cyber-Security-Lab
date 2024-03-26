# Usage of SIEM Tool:
* Log Analysis.
* Security Investigation
* Log Monitoring and perform Incident Response
* Customized Dashboards can be created to analysis and investigate Logs
* Analyze data through patterns in a Analytical Manner

# Components of SIEM Tool:
* Forwarders: Collect Data from various sources and send it to Splunk Indexer
* Indexers: Store and Index the data for fast search and monitoring purpose
* Search Head: Interface for users to search, visualize, and analyze data.
* Splunk Apps/ Add-on: Plugin can be added for specific task
* Deployment Server: Manages configurations and updates across multiple Splunk Instances

# Architecture of SIEM Tool:
* Forwarders - collect data from sources.
* Indexers - store and index the data.
* Search Heads - provide the interface for users to interact with and analyze the indexed data.

# Advantages:
* Real-time Monitoring: Enables real-time monitoring and analysis of machine-generated data.
* Scalability: Distributed architecture allows horizontal scaling to handle increasing data volumes.
* Can add multiple Plug-ins so we can create our own customized dashboards
* Search Capabilities - Powerful search language (SPL) for complex queries and analytics.
* Large community support and numerous pre-built apps and integrations.

# Disadvantages:
* Licensing costs can be significant for large-scale deployments.
* Setting up and maintaining Splunk in a distributed environment can be complex.
* Requires significant hardware resources, especially for large deployments.
* There should be enough knowledge to work with search queries and other apps so effectively one can resolve the security breaches

# Features:
* Search Processing Language (SPL): Allows complex querying and analysis.
* Customized Dashboards: Enables creation of customizable visualizations and dashboards.
* Machine Learning Toolkit: Allows predictive analytics and anomaly detection.
* Data Ingestion: Supports various data sources and formats (logs, metrics, etc.).
* Security and Compliance: Provides features for securing data and meeting compliance requirements.

# Steps to Install and Configure Splunk:

1. First of all install Splunk Enterprise on your host OS can be windows, kali Linux , Mac
2. After Installing setup with Username and Password in Splunk Enterprise

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/d36e5575-1653-4a5e-ae0c-6a11566481bd)

3,into Settings and Configure the universal forwarder to send data to the Splunk Enterprise indexer by adding a new recieving port as 9997

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/12ce2667-40bc-499a-a0b0-a624f002436a)

4.Now Start Installing Universal Forwarder in the system where you usually attack in my case i have done in kali linux.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/b05b98df-2571-4b4f-a1b5-5063e6e2481a)

5. Now start with accepting license and set up username and Password.

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/742454fc-8d54-4816-b21e-578be7a4c884)

6. Now Configure with 2 parameters

./splunk add forward-server :9997

./splunk set deploy-poll : (This you have to enable on Universal Forwarder where host ipaddress will be of the system on which universal forwarder is downloaded and management port no. you have to specify)

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/e20d6855-676c-477d-9fc4-321cedd38963)

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/71cf916e-25f6-46dd-ab76-f48828afaae7)

7.We have to write a command what to monitor

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/25d3adb7-ba1d-4349-9040-c0cc7c15cac7)

8.Now restart the splunk

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/da9fda4a-7dc1-4b3c-af9d-708a61a803e6)

9. Realtime Logs on SIEM Tool:

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/99871cf6-a4b0-4f63-8363-c3fa5abe7102)


## What is Splunk ? 
Splunk's software can be used to examine, monitor, and search for machine generated big data through a browser-like interface.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/ee5d759c-108f-4f91-88b4-c392d8cabe1b)

## Using Splunk web
Splunk web is pre configured environment, there are three pre defined roles in Splunk enterprise
a. Admin - Full access b. Power - It will perform real time searches. c. User - user can access own knowledge object.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/5217885c-482b-46b5-9024-c658cb96b859)

## Splunk default launch environment
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/24468847-c586-4efc-bf90-53b9cef93c31)

## Using search
Search option is used to search the incident log with time span.

Limiting a search by time is a key to faster result and is a best practice. Eg. Installing cmatrix in remote VM (Kali) and we can see the installation logs in Splunk enterprises.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/4dedf5e8-231c-4644-bbc4-0afc7c78bcbd)

Commands that create statics and visualization are called transforming commands. We can share the share job log with other user it will remain active for 7 days, and every 10 min we need to refresh the log search. We can download the report in csv,xml,json.

## Exploring Events
If we search the objects in filters by default the event will turn the list, filtered keyword would be highlighted and we can examine the logs with timespan.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/24120753-fd26-4314-a9aa-30522f2e659a)

## Using search term in filters we can use terms of keywords. Eg. fail*, failed, FAILURE
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/e04bcffc-f925-4bfe-887f-9576223bafdb)

Search terms are not case sensitive and Booleans also we can use Boolean operations have an order of evaluation a. NOT b. OR c. AND Note: parenthesis () should be used.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/d88c16aa-528f-4d25-8508-02fc387066c3)
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/f26c348d-56f9-423a-ad54-dace8b2ec15e)
User can customize the filter as per the requirements.

6.What are commands? 
Search Splunk language contain 5 component’s a. search term - Foundation of search query. b. commands - Commands is used to customize the log as per the need like charts, statistics and formatting. c. functions - How we need to display the charts and evaluate the results. d. arguments - It is the variables which we want to apply in the functions. e. clauses - It will group the result as per the requirement.
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/5b38a457-cc8e-4a7d-98d0-6f40fd9a9d3e)

7.What are knowledge objects? 
It is tools that help you discover and analyze the data, will be grouped in 5 categories . 
a. Data Interpretation 
b. Data classifications 
c. Data Enrichment 
d. Denormalization
e. Data Model Knowledge object is use full for several reasons it can be create by one user and share with other user with permission granted. It is powerful tool for your deployment Data Interpretation - Fields

![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/3a538c7f-0853-4044-b62f-566033a7acb0)
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/aaffc1cc-27c0-45e1-acc4-9bc855c055af)

8. Creating Reports Customize the report using visualization trick and statistics charts
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/6076fd48-7d4a-482a-a829-66f05a860e82)

9. Creating Dashboards Creating new dashboard for User
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/1af6aa87-13a0-46f6-a903-22c84cccf742)

10. Dashboard Studio Classic Dashboard
![image](https://github.com/Nifalnasar/Cyber-Security-Lab/assets/141356053/6ff9f082-6a3f-48ef-a5fc-a11bbc84c324)




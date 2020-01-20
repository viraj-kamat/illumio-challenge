# illumio-challenge


Description of files :
1. generator.py : Run this file once to generate a csv file that contains some rules. This file is for test purposes only and could be used for stress-testing, etc.

2. firewall.py : The main file that processes our ipaddress rules and then performs a lookup. Usage :
  - python firewall.py path_to_csv_file.csv - This will run once and process the rules. 
  - python accept_packet --direction outbound/inbound --port 1-65135 --ipaddress 192.168.2.1 --protocol udp/tcp
  
  
 Note: Once the file is run with a csv file and queried for rule matches, it will continue to run to allow further processing of rules.
 Type exit to exit the console.
 
 
All processed python rules are stored in a python dictionary key:value pair. The memory footprint could be large but lookup time would be less. 
 
Testcases that could be look into :
1. Stress testing : A very large csv file with ~500k inputs could be generated to test the performance of the script. This script could simultaneiusly be called by multiple processes to perform a lookup - we want to identify how multiple incoming packets can be looked up without causing high latency

2. Sanity checks : Is the port/protocol/ip-address of a valid type.


3. Try multiple combinations of port/protocol/ip/ipaddress that are present/not-present in the rules domain. Verify if they are properly identified/looked-up.


Refinements :
1. If we try to store all ipaddress in a lookup table, we can assumne that the memory footprint could be as high as 4gb (rule per ip is a byte at least). What is the best way to store ips - search-tree/graphs, etc

2. Are there prexisting python modules that could be leveraged to help us with rule-storage and lookup.


I found this coding task both intriguing and challenging, I would still be thinking of how to better refine the code.


Team preferred : Data Team/Platform Team


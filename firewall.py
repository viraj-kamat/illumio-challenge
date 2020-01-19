'''
Author : #virajk
Processes an incoming csv files with rules
Performs a lookup of an incoming packet and outputs True or False
'''

from cmd import Cmd
import argparse
import csv
from ipaddress import ip_address
import json
from datetime import datetime
import sys


class Firewall(Cmd):

    def __init__(self):


        super(Firewall, self).__init__()

        if len(sys.argv) < 2 :
            print("Please input a rules file to process.")
            sys.exit(1)

        self.up_rules = [] #Default unprocessed rules
        self.hashmap = {} # A simple hashmap for an ip-address rule lookup

        #https://stackoverflow.com/questions/12750393/python-using-argparse-with-cmd
        #Arguments that will be used when performing a lookup
        self.__parser = argparse.ArgumentParser("Accepts a packet and performs a lookup.")
        self.__parser.add_argument('-dr','--direction', help='Direction of incoming packet',required=True)
        self.__parser.add_argument('-pc','--protocol', help='Could be udp/tcp',required=True)
        self.__parser.add_argument('-pt','--port', help='Any port in the range of 1-65535',required=True)
        self.__parser.add_argument('-ip','--ipaddress', help='An ip address',required=True)

        filename = sys.argv[1]
        self.process_rules(filename)

    def process_rules(self, file):
        '''
        Reads a csv file input and stores it into an array

        :param file:
        :return:
        '''
        print("Processing rules, this is a one-time job.Stand-by...")
        start = datetime.now()
        f_handle = open(file, 'r')
        try:
            f = open(file, 'r')
            reader = csv.DictReader(f)
            for row in reader:
                self.up_rules.append(row)
        except Exception as e:
            print("There was an error reading the file. Error : {0}".format(e))

        self.generate_map(self.up_rules)    #Generate the hashmap used for lookups
        print("Rules have been procssed, time taken {0}.You may now perform a lookup.".format(str(datetime.now() - start)))


    def generate_map(self, csv_rules):
        '''
        Create a hashmap that will be used for lookup of ip rules
        :param csv_rules: The contents read from the input rules csv file
        :return:
        '''
        hashmap = {}
        for ele in csv_rules:
            port = str(ele['port']).replace(' ', '')
            ip = str(ele['IP address']).replace(' ', '')
            direction = ele['direction'].replace(' ', '')
            protocol = ele['protocol'].replace(' ', '')



            if '-' in ip:       #If ipaddress is a range
                ip = ip.split('-')
                ip = [int(ip_address(ip[0])), int(ip_address(ip[1]))]
                #https://stackoverflow.com/questions/9590965/convert-an-ip-string-to-a-number-and-vice-versa
            else:
                ip = [int(ip_address(ip)), int(ip_address(ip))] # Regardless we always store ip as a range

            if '-' in port:         #if port is a range, for all possible ports generate a key
                port = port.split('-')
                for port in range(int(port[0]), int(port[1]) + 1):
                    key = direction + protocol + str(port)      #Hashmap key is concatenation of direction,protocol and port.
                    if key not in hashmap:
                        hashmap[key] = []
                    hashmap[key].append(ip)                     #Ipaddress ranges are appened to this key for lookup
            else:
                key = direction + protocol + port
                if key not in hashmap:
                    hashmap[key] = []
                hashmap[key].append(ip)

        self.hashmap = hashmap
        rules_store = open('rules.json', 'w')                   #Store these hashamp rules in json, could be simple read later for lookups
        json.dump(hashmap, rules_store)
        rules_store.close()
        return hashmap

    def do_accept_packet(self,line):

        starttime = datetime.now()
        try:
            parsed = self.__parser.parse_args(line.split())
        except SystemExit:
            self.__parser.print_help()
            return


        try :
            key = str(parsed.direction) + str(parsed.protocol) + str(parsed.port)       #Recreate the input key

            if key in self.hashmap:
                ip = int(ip_address(parsed.ipaddress))
                for ip_range in self.hashmap[key]:
                    if ip_range[0] <= ip <= ip_range[1]: #Perform a lookup, all we check is that for each ip-range in the hashmap-key the porvided ip matches
                        print('Rule corresponding to IP address found')
                        break
                else :
                    print('Rule corresponding to IP address not found')
        except Exception as e :
            print("An error eccured:- "+str(e))
        print("Lookup time {0}".format(str(datetime.now() - starttime)))




    def do_exit(self, line):
        return True

if __name__ == "__main__":
    Firewall().cmdloop()

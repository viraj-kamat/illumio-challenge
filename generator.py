'''
Author : #virajk
'''


import random
from random import getrandbits
from ipaddress import IPv4Address, IPv6Address
from datetime import datetime
import csv

class Generator () :

    def printer(self,task,secs) :
        print("The {0} took {1} seconds ".format(task,str(secs)))

    def gen_ip(count) :
        rangetype = random.choice([True,False])
        if rangetype :
            start = getrandbits(30)
            return [IPv4Address(start),IPv4Address(start+random.randint(0,5000))]
        else :
            return IPv4Address(getrandbits(32))


    def gen_ports(self) :
        rangetype = random.choice([True,False])
        if rangetype :
            start = random.randint(0,64000)
            return [start,start+random.randint(1,1000)]
        else :
            return random.randint(0,65000)


    def generator_records(self,count=100000) :
        protocol = [ random.choice(['udp','tcp']) for _ in range(0,count) ]
        ruletype = [ random.choice(['inbound','outbound']) for _ in range(0,count) ]
        ports = [ self.gen_ports() for _ in range(0,count) ]
        allow = [ random.choice([True,False]) for _ in range(0,count) ]
        ips = [ self.gen_ip() for _ in range(0,count) ]

        csv_rules = []
        file_handle = open("rules.csv","w",newline='')     #Referece : https://docs.python.org/3/library/csv.html
        writer = csv.DictWriter(file_handle, fieldnames=['direction', 'protocol', 'port', 'IP address'])
        writer.writeheader()
        for i in range(0,count) :

            if type(ports[i]) is list :
                port = str(ports[i][0])+"-"+str(ports[i][1])
            else :
                port = str(ports[i])

            if type(ips[i]) is list :
                ips[i] = str(ips[i][0])+"-"+str(ips[i][1])
            else :
                ips[i] = str(ips[i])
            csv_rules.append([protocol[i],ruletype[i],port,allow[i],ips[i]])


            writer.writerow({"direction": ruletype[i]  ,"protocol": protocol[i] , "port": port, "IP address" : ips[i] })

        file_handle.close()

        return csv_rules



gen = Generator()

starttime = datetime.now()
rules = gen.generator_records()
gen.printer("generator",str(datetime.now() - starttime))





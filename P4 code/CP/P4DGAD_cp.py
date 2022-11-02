import os
from re import sub
import time
from ipaddress import ip_address
import socket


#"""
p4 = bfrt.P4DGAD.pipe
p4_rules_fname = "/home/lubuntu/DNS_extension/p4_freq_rules_engDict.txt"


# clear table rules
print("Clearing table ...")
p4.SwitchIngress.static_bigrams1.clear()
p4.SwitchIngress.static_bigrams2.clear()
p4.SwitchIngress.static_bigrams3.clear()
p4.SwitchIngress.static_bigrams4.clear()
p4.SwitchIngress.static_bigrams5.clear()
p4.SwitchIngress.static_bigrams6.clear()
p4.SwitchIngress.static_bigrams7.clear()
p4.SwitchIngress.static_bigrams8.clear()
p4.SwitchIngress.ipv4_host.clear()
p4.SwitchIngress.is_valid_tld.clear()

with open(p4_rules_fname) as f:
    line_count = 0
    for rule in f:
        # get the string between the brakets (the actual rule)
        sub_rule = re.findall(r'\(.*?\)', rule)[0]

        # remove brakets
        sub_rule = sub_rule[1:len(rule) -1]

        # get the part (key) and the freq (value)
        key_value = re.findall(r'\".*?\"', sub_rule)
        key = key_value[0]
        key = key[1:len(key)-1]
        value = key_value[1]
        value = value[1:len(value)-1]
        key1 = ""
        key2 = ""
        
        if len(key) > 4:
            key1 = key[0:4]
            key2 = "0x" + key[4:]

        if "static_bigrams1" in rule:
            #print("p4.SwitchIngress.static_bigrams1.add_with_map_bigram_hdr(part=" + key + ", freq=" + value + ")")
            p4.SwitchIngress.static_bigrams1.add_with_map_bigram_hdr(part=key, freq=value)
        elif "static_bigrams2" in rule:
            #print("p4.SwitchIngress.static_bigrams2.add_with_map_bigram_hdr(part=" + key + ", freq=" + value + ")")
            p4.SwitchIngress.static_bigrams2.add_with_map_bigram_hdr(part=key, freq=value)
        elif "static_bigrams3" in rule:
            #print("p4.SwitchIngress.static_bigrams3.add_with_map_bigram_hdr(part_15_0_=" + key + ", freq=" + value + ")")
            p4.SwitchIngress.static_bigrams3.add_with_map_bigram_hdr(part_15_0_=key, freq=value)
        elif "static_bigrams4" in rule:
            #print("p4.SwitchIngress.static_bigrams4.add_with_map_bigram_hdr(part_23_8_=" + key + ", freq=" + value + ")")
            p4.SwitchIngress.static_bigrams4.add_with_map_bigram_hdr(part_23_8_=key, freq=value)
        elif "static_bigrams5" in rule:
            #print("p4.SwitchIngress.static_bigrams5.add_with_map_bigram_hdr(part_31_16_=" + key + ", freq=" + value + ")")
            p4.SwitchIngress.static_bigrams5.add_with_map_bigram_hdr(part_31_16_=key, freq=value)
        elif "static_bigrams6" in rule:
            #print("p4.SwitchIngress.static_bigrams6.add_with_map_bigram_hdr(part=" + key1 + ", part_15_8_=" + key2 + ", freq=" + value + ")")
            p4.SwitchIngress.static_bigrams6.add_with_map_bigram_hdr(part=key1, part_15_8_=key2, freq=value)
        elif "static_bigrams7" in rule:
            #print("p4.SwitchIngress.static_bigrams7.add_with_map_bigram_hdr(part_7_0_=" + key1 + ", part_31_24_=" + key2 + ", freq=" + value + ")")
            p4.SwitchIngress.static_bigrams7.add_with_map_bigram_hdr(part_7_0_=key1, part_31_24_=key2, freq=value)
        elif "static_bigrams8" in rule:
            #print("p4.SwitchIngress.static_bigrams8.add_with_map_bigram_hdr(part=" + key1 + ", part_7_0_=" + key2 + ", freq=" + value + ")")
            p4.SwitchIngress.static_bigrams8.add_with_map_bigram_hdr(part=key1, part_31_24_=key2, freq=value)
        
        # if line_count == 10:
        #     break
        line_count += 1
        #print(line_count)
print("DONE INSERTING FREQUENCIES")

# For basic forwarding and testing
p4.SwitchIngress.ipv4_host.add_with_send(dst="192.168.200.10", port=1)
p4.SwitchIngress.ipv4_host.add_with_send(dst="192.168.200.11", port=1)
# p4.SwitchIngress.static_bigrams1.add_with_map_bigram_hdr(part=)
#"""

# Table to check for valid TLDs
f_r = open("/home/lubuntu/DNS_extension2/CP/tlds_to_P4hex.txt")
tld_P4hex = []
for l in f_r:
    l = l.strip()
    l = l.split(",")
    tld_hash = "0x" + l[1]
    if tld_hash not in tld_P4hex:
        tld_P4hex.append(tld_hash)
        p4.SwitchIngress.is_valid_tld.add_with_is_valid_tld_act(hash_last_label=tld_hash)

def establish_connection():
    import socket
    import time

    s = socket.socket()
    host = socket.gethostname()
    port = 12397
    #s.bind(('', port))
    s.connect((host, port))

    return s

# establish connection
# s = establish_connection()

# IP to P4 hex dict:
ip_to_p4hex = {'3232286730': '0x971f', '3232286731': '0x873e', '3232286732': '0xf7d9'}

def create_client(s):
    import socket
    import time

    s = socket.socket()
    host = socket.gethostname()
    port = 12397
    s.connect((host, port))
    while True:
        s.send("Hello World".encode())
        time.sleep(5)
        break

    s.close()

def digest_event(dev_id, pipe_id, direction, parser_id, session, msg):
    global p4 # bfrt.P4DGAD.pipe
    global s # socket
    global ip_to_p4hex

    try:
        for digest in msg:
            ip_addr = digest['ip_addr']
            nxds = digest['nxds']
            rnd_nxds = digest['rnd_nxds']
            dns_reqs = digest['dns_reqs']
            ip_reqs = digest['ip_reqs']
            domain_name_length = digest["domain_name_length"];
            num_subdomains = digest["num_subdomains"];
            is_valid_tld = digest["is_valid_tld"];
            has_single_subd = digest["has_single_subd"];
            num_underscores = digest["num_underscores"];

            ip_addr = str(ip_addr)

            print("COMING ", ip_addr, nxds, rnd_nxds, dns_reqs, ip_reqs, 
                    domain_name_length, num_subdomains, is_valid_tld,has_single_subd, num_underscores)


            '''
            Since we are using python2 as the control plane for the current SDE, advanced ML models and libraries are not available.
            If you would like to test your data on ML models using python3, you can open a socket with python3 code to send the data and run them there. 
            Below is the code to send the data to python3 code, feel free to uncomment it and play with it.
            Also, the python3 server code is in P4DGAD_cp3.py. 
            send the data collected to python3 where you can ML models using scikit learn and other advanced tools 
            ''' 
            # data = ip_addr + "," + nb_nxds + "," + rnd_nxds + ',' + nb_unique_ips + ',' + nb_dns_reqs
            # print(data.encode())
            # s.send(data.encode())
    except Exception as e:
        print(e)

    return 0

try:
    p4.SwitchIngressDeparser.digest.callback_register(digest_event)
except:
    # deregister then register again
    p4.SwitchIngressDeparser.digest.callback_deregister()
    p4.SwitchIngressDeparser.digest.callback_register(digest_event)



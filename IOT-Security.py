import nmap
import subprocess
import re
import ipaddress

output = subprocess.check_output('ipconfig',text=True)
for line in output.splitlines():
    if 'IPv4' in line:
        ipv4 = re.search('\d+\.\d+\.\d+\.\d+',line).group(0)
    elif 'Subnet' in line:
        subnet = re.search('\d+\.\d+\.\d+\.\d+',line).group(0)

prefix = ipaddress.IPv4Network(f'0.0.0.0/{subnet}').prefixlen
network = f'{ipv4}/{prefix}'


nm = nmap.PortScanner()
nm.scan(hosts=network,arguments='-sn')
iot_devices = []
for host in nm.all_hosts():
    mac = nm[host].get('addresses').get('mac')
    ipv4 = nm[host].get('addresses').get('ipv4')
    vendor = nm[host].get('vendor')

    if mac and vendor:
        iot_devices.append(ipv4)
        print(ipv4,vendor)
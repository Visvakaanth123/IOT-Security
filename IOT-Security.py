import nmap
import subprocess
import re
import ipaddress

vendor_list = ['hikvision', 'dahua', 'axis', 'tp-link', 'tplink', 'sonoff', 'ti', 'bosch', 'xiaomi', 'xiaomi-inc', 
 'google', 'amazon', 'ring', 'arlo', 'nest', 'huawei', 'hisense', 'bosch', 'ieee', 'sony', 'lg',
 'samsung', 'shenzhen', 'tuya', 'espressif', 'realtek', 'rockchip', 'mediatek', 'd-link', 'netgear',
 'edimax', 'philip', 'philips', 'belkin', 'wyze', 'yeelight', 'sercomm', 'zhejiang dahua technology']

output = subprocess.check_output('ipconfig',text=True)
for line in output.splitlines():
    if 'IPv4' in line:
        ipv4 = re.search('\d+\.\d+\.\d+\.\d+',line).group(0)
    elif 'Subnet' in line:
        subnet = re.search('\d+\.\d+\.\d+\.\d+',line).group(0)

prefix = ipaddress.IPv4Network(f'0.0.0.0/{subnet}').prefixlen
network = f'{ipv4}/{prefix}'
print(f"Found Netowork: {network}")

nm = nmap.PortScanner()
nm.scan(hosts=network,arguments='-sn')
print("\n")
print("Connected IP's:")
potential_iot_devices = []
for host in nm.all_hosts():
    print(host)
    mac = nm[host]['addresses'].get('mac')
    vendor = nm[host].get('vendor')
    v = vendor.get(mac,"")
    if v.lower() in vendor_list and mac:
        potential_iot_devices.append((host,vendor.get(mac,"")))

print("\n")
print("Potential IOT Devices:")
iot_devices = []
for ip,v in potential_iot_devices:
    print(f"{ip} - {v}")
    iot_devices.append(ip)

print("\n")
print("[+] Starting IOT Device Scan")

tcp_args = "-sS -sV -p 21,22,23,80,443,554,8000,8080,8443,1883,8883 --version-intensity 2 -T4"
udp_args = "-sU -p 53,123,1900,5353,5683,161 -T3"

for h in iot_devices:
    print('='*40)
    print(f"Scanning Host: {h}")
    print("="*40)
    nm.scan(hosts=h,arguments=tcp_args)
    for proto in nm[h].all_protocols():
        print(f"Protocol: {proto}")
        for port in nm[h][proto]:
            name = nm[h][proto][port].get('name')
            state = nm[h][proto][port].get('state')
            version = nm[h][proto][port].get('version') or "N/A"
            print(f"   Port {port}: {name} | {state} | {version} ")
        print("\n")

for h in iot_devices:
    print('='*40)
    print(f"Scanning Host: {h}")
    print("="*40)
    nm.scan(hosts=h,arguments=udp_args)
    for proto in nm[h].all_protocols():
        print(f"Protocol: {proto}")
        for port in nm[h][proto]:
            name = nm[h][proto][port].get('name')
            state = nm[h][proto][port].get('state')
            version = nm[h][proto][port].get('version') or "N/A"
            print(f"   Port {port}: {name} | {state} | {version} ")
        print("\n")
import nmap

ip_addr = '127.0.0.1'

scanner = nmap.PortScanner()

print("---------- TCP Analysis ----------------------")
results = scanner.scan(ip_addr, '1-1024','-v -sS', sudo=True)
print(scanner.scaninfo())
print('IP Status: ', scanner[ip_addr].state())
print(scanner[ip_addr].all_protocols())
print('Open Ports: ', scanner[ip_addr]['tcp'].keys())

print("---------- UDP Analysis ----------------------")

results = scanner.scan(ip_addr, '1-1024','-v -sU', sudo=True)
print(scanner.scaninfo())
print('IP Status: ', scanner[ip_addr].state())
print(scanner[ip_addr].all_protocols())
print('Open Ports: ', scanner[ip_addr]['udp'].keys())
#!/usr/bin/env python3

import socket
import ipaddress
import netifaces as ni
import argparse
from concurrent.futures import ThreadPoolExecutor

def scan(ip, port, verbose=False):
    try:        
        if verbose:
            print(f"Scanning {ip}: Port {port}...")


        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.close()
        if verbose:
            print(f"{ip}: Port {port} is open")
        return True
    except:
        if verbose:
            print(f"{ip}: Port {port} is closed")
        return False

def scan_smb(ip, verbose=False):
    return scan(ip, 445, verbose)

def scan_ftp(ip, verbose=False):
    return scan(ip, 21, verbose)

def scan_range(network, scan_function, verbose=False):
    results = []
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(scan_function, str(ip), verbose=verbose): ip for ip in network.hosts()}
        for future in futures:
            ip = futures[future]
            results.append((ip, future.result()))

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan for open SMB shares or FTP sites on a local network')
    parser.add_argument('--interface', help='Network interface to use (default: first non-loopback interface)', default=None)
    parser.add_argument('--verbose', action='store_true', help='Display verbose output')
    args = parser.parse_args()

    # Determine the local network range
    if args.interface:
        interface = args.interface
    else:
        interfaces = ni.interfaces()
        for iface in interfaces:
            if iface.startswith('en') or iface.startswith('eth'):
                interface = iface
                break

    ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
    subnet = ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']
    network = ipaddress.IPv4Network(ip + '/' + subnet, strict=False)

    # Output the local network range
    print(f"Scanning Local Network Range: {network.network_address}/{network.prefixlen}")

    # Scan for SMB shares
    print("\nScanning for open SMB shares:")
    smb_results = scan_range(network, scan_smb, verbose=args.verbose)

    # Scan for FTP sites
    print("\nScanning for open FTP sites:")
    ftp_results = scan_range(network, scan_ftp, verbose=args.verbose)

    # Print summary of results
    print("\nScan Results:")
    for ip, result in smb_results + ftp_results:
        service = "SMB" if result and ip in [r[0] for r in smb_results] else "FTP"
        status = "open" if result else "closed"
        print(f"{ip}: {service} share is {status}")

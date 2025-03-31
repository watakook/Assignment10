
import requests
from requests.auth import HTTPBasicAuth
from dnac_config import DNAC
import urllib3
import sys

# Disable SSL warnings for sandbox
urllib3.disable_warnings()

class DNAC_Manager:
    def __init__(self):
        self.token = None
    
    def get_auth_token(self, display_token=False):
        """Authenticates to DNA Center and stores token"""
        try:
            url = f"https://{DNAC['host']}:{DNAC['port']}/dna/system/api/v1/auth/token"
            response = requests.post(
                url,
                auth=HTTPBasicAuth(DNAC['username'], DNAC['password']),
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            self.token = response.json()['Token']
            
            if display_token:
                print("\n🔑 Authentication Token:")
                print("-"*50)
                print(self.token)
                print("-"*50)
            return True
            
        except Exception as e:
            print(f"❌ Authentication failed: {str(e)}")
            return False

    def get_network_devices(self):
        """Retrieves all network devices"""
        if not self.token:
            print("⚠️ Please authenticate first!")
            return None
            
        try:
            url = f"https://{DNAC['host']}:{DNAC['port']}/api/v1/network-device"
            headers = {"X-Auth-Token": self.token}
            response = requests.get(
                url, 
                headers=headers, 
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            return response.json().get('response', [])
            
        except Exception as e:
            print(f"❌ Failed to get devices: {str(e)}")
            return None

    def display_devices(self, devices):
        """Formats device list output"""
        if not devices:
            print("No devices found!")
            return
            
        print("\n📡 Network Devices")
        print("="*80)
        print(f"{'Hostname':20}{'IP Address':15}{'Platform':20}{'Status':10}")
        print("-"*80)
        
        for device in devices:
            print(
                f"{device.get('hostname', 'N/A'):20}"
                f"{device.get('managementIpAddress', 'N/A'):15}"
                f"{device.get('platformId', 'N/A'):20}"
                f"{device.get('reachabilityStatus', 'N/A'):10}"
            )

    def get_device_interfaces(self, device_ip):
        """Retrieves interfaces for specific device"""
        if not self.token:
            print("⚠️ Please authenticate first!")
            return None
            
        try:
            # Find device by IP
            devices = self.get_network_devices()
            device = next(
                (d for d in devices if d.get('managementIpAddress') == device_ip), 
                None
            )
            if not device:
                print(f"❌ Device {device_ip} not found!")
                return None
                
            # Get interfaces
            url = f"https://{DNAC['host']}:{DNAC['port']}/api/v1/interface"
            headers = {"X-Auth-Token": self.token}
            params = {"deviceId": device['id']}
            response = requests.get(
                url,
                headers=headers,
                params=params,
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            return response.json().get('response', [])
            
        except Exception as e:
            print(f"❌ Failed to get interfaces: {str(e)}")
            return None

    def display_interfaces(self, interfaces):
        """Formats interface output"""
        if not interfaces:
            print("No interfaces found!")
            return
            
        print("\n🔌 Device Interfaces")
        print("="*80)
        print(f"{'Interface':20}{'Status':10}{'VLAN':10}{'Speed':10}")
        print("-"*80)
        
        for intf in interfaces:
            print(
                f"{intf.get('portName', 'N/A'):20}"
                f"{intf.get('status', 'N/A'):10}"
                f"{intf.get('vlanId', 'N/A'):10}"
                f"{intf.get('speed', 'N/A'):10}"
            )

def main():
    """Main program execution"""
    print("\n" + "="*50)
    print("Cisco DNA Center Network Automation")
    print("Canadian College of Technology and Business (CCTB)")
    print("="*50 + "\n")
    
    dnac = DNAC_Manager()
    
    while True:
        print("\n🔧 Main Menu")
        print("1. Authenticate & Show Token")
        print("2. List Network Devices")
        print("3. Show Device Interfaces")
        print("4. Exit")
        
        choice = input("Select option (1-4): ").strip()
        
        if choice == "1":
            if dnac.get_auth_token(display_token=True):
                print("✅ Authentication successful!")
                
        elif choice == "2":
            devices = dnac.get_network_devices()
            dnac.display_devices(devices)
            
        elif choice == "3":
            device_ip = input("Enter device IP address: ").strip()
            interfaces = dnac.get_device_interfaces(device_ip)
            dnac.display_interfaces(interfaces)
            
        elif choice == "4":
            print("Goodbye! 👋")
            sys.exit()
            
        else:
            print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()


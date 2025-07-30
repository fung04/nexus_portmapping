import re
import os
import csv
import logging
import traceback
import json
from datetime import datetime
from copy import deepcopy
from typing import Dict, Set, Optional, Any, List
from dataclasses import dataclass

# Constants
TEXT_FILE_EXTENSIONS = [".txt", ".log"]
OUTPUT_FOLDER = "output"
LOG_FILE_NAME = f"{OUTPUT_FOLDER}/switch_capture.log"

CSV_HEADERS = [
    "No", "Existing Switch Hostname", "Existing Switch Rack Location and Unit",
    "Existing Switch Port", "Existing Switch Port Description", "Existing Switch Port Status",
    "Existing Switch Port MTU", "Media RJ45/SFP", "SFP Type", "Speed", "Duplex",
    "Trunk/Access/PC/VPC/PVLAN", "Port-Channel", "Virtual Port-Channel", "Vlan/PVLAN",
    "Mac Address on Existing Switch Port", "Vlan Address on Existing Switch Port",
    "IP Address on Existing Switch Port", "End device hostname", "End device Model",
    "End device Port", "End device neighbors kind"
]

@dataclass
class MacEntry:
    """Represents a MAC address and IP address pair."""
    mac_address: str
    ip_address: Optional[str] = None
    
    def __hash__(self):
        return hash((self.mac_address, self.ip_address))
    
    def __eq__(self, other):
        if not isinstance(other, MacEntry):
            return False
        return self.mac_address == other.mac_address and self.ip_address == other.ip_address

class MacAddressTable:
    """Manages MAC address table entries organized by interface and VLAN."""
    
    def __init__(self):
        # Structure: Interface -> VLAN -> Set of MacEntry
        self.table: Dict[str, Dict[str, Set[MacEntry]]] = {}
    
    def add_entry(self, interface: str, vlan: str, mac_address: str, ip_address: Optional[str] = None):
        """Add a MAC address entry for a specific interface and VLAN."""
        if interface not in self.table:
            self.table[interface] = {}
        
        if vlan not in self.table[interface]:
            self.table[interface][vlan] = set()
        
        mac_entry = MacEntry(mac_address, ip_address)
        self.table[interface][vlan].add(mac_entry)
    
    def get_entries_by_interface(self, interface: str) -> Dict[str, Set[MacEntry]]:
        """Get all entries for a specific interface."""
        return self.table.get(interface, {})
    
    def save_to_json(self, hostname: str):
        """Save MAC address table to JSON file."""
        json_data = {}
        for interface, vlans in self.table.items():
            json_data[interface] = {}
            for vlan, entries in vlans.items():
                json_data[interface][vlan] = [
                    {'mac_address': entry.mac_address, 'ip_address': entry.ip_address}
                    for entry in entries
                ]
        
        with open(f"{OUTPUT_FOLDER}/{hostname}_mac_address_table.json", 'w') as f:
            json.dump(json_data, f, indent=2)

class InterfaceManager:
    """Manages network interface configurations."""
    """Stores interface configurations and provides methods to add or configure interfaces."""
   
    TEMPLATE = {
        "Interface Name": "N/A",
        "Description": "N/A",
        "Interface Status": "N/A",
        "Interface MTU": "N/A",
        "Bandwidth": "N/A",
        "Media RJ45/SFP": "N/A",
        "SFP Type": "N/A",
        "Speed": "N/A",
        "Duplex": "N/A",
        "Trunk/Access/PC/VPC/PVLAN": "N/A",
        "Port-Channel": "N/A",
        "Virtual Port-Channel": "N/A",
        "Vlan/PVLAN": "N/A",
        "Mac Address on Existing Switch Port": "N/A",
        "Vlan Address on Existing Switch Port": "N/A",
        "IP Address on Existing Switch Port": "N/A",
        "End device hostname": "N/A",
        "End device Model": "N/A",
        "End device Port": "N/A",
        "End device neighbors kind": "N/A"
    }
    
    def __init__(self):
        self.interfaces = {}
    
    def add_interface(self, port_name: str, **config) -> 'InterfaceManager':
        """Add an interface with configuration."""
        interface_config = deepcopy(self.TEMPLATE)
        interface_config.update(config)
        self.interfaces[port_name] = interface_config
        return self
    
    def configure_interface(self, port_name: str, **config) -> 'InterfaceManager':
        """Configure an existing interface or create if it doesn't exist."""
        if port_name in self.interfaces:
            self.interfaces[port_name].update(config)
        else:
            self.add_interface(port_name, **config)
        return self
    
    def get_all_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Get all interface configurations."""
        return self.interfaces

class NexusSwitch:
    """Processes Cisco Nexus switch configuration and status data."""
    
    def __init__(self, data: str, hostname: str):
        logging.debug(f"Processing NXOS Switch: {hostname}")
        self.hostname = hostname
        self.interface_manager = InterfaceManager()
        self.mac_address_table = MacAddressTable()

        # Extract command outputs
        commands = self._extract_command_outputs(data)
        
        # Process the extracted data
        self._process_interface_details(commands.get('show_interface'))
        self._process_interface_status(commands.get('show_interface_status'))
        self._process_running_config(commands.get('running_config'))
        self._process_mac_and_arp_tables(commands.get('show_mac_address_table'), 
                                       commands.get('show_ip_arp'))
        self._process_neighbors_details(commands.get('show_cdp_neighbors_detail'),
                                       commands.get('show_lldp_neighbors_detail'))
        self._populate_port_mapping()
        self._export_to_csv()
        
        # Save outputs
        self.mac_address_table.save_to_json(hostname)
        # print(f"First 10 interfaces for {hostname}:\n{json.dumps(dict(list(self.interface_manager.get_all_interfaces().items())[:10]), indent=2)}")
    
    def _extract_command_outputs(self, data: str) -> Dict[str, Optional[str]]:
        """Extract command outputs using regex patterns."""
        patterns = {
            'running_config': rf"{self.hostname}\#\s*show run(.+?){self.hostname}\#",
            'show_interface': rf"{self.hostname}\#\s*show\s+interface(.+?){self.hostname}\#",
            'show_interface_status': rf"{self.hostname}\#\s*show\s+int(?:erface)?\s+status(.+?){self.hostname}\#",
            'show_mac_address_table': rf"{self.hostname}\#\s*show\s+mac\s+address-table(.+?){self.hostname}\#",
            "show_cdp_neighbors_detail": rf"{self.hostname}\#\s*show\s+cdp\s+nei(?:ghbors)?\s+de(?:tail)?(.+?){self.hostname}\#",
            "show_lldp_neighbors_detail": rf"{self.hostname}\#\s*show\s+lldp\s+nei(?:ghbors)?\s+de(?:tail)?(.+?){self.hostname}\#",
            'show_ip_arp': rf"{self.hostname}\#\s*show\s+ip\s+arp(.+?){self.hostname}\#"
        }
        
        commands = {}
        for cmd_name, pattern in patterns.items():
            try:
                match = re.search(pattern, data, re.DOTALL)
                commands[cmd_name] = match.group(1) if match else None
                if not commands[cmd_name]:
                    logging.warning(f"No `{cmd_name.replace('_', ' ')}` command found")
            except Exception as e:
                logging.error(f"Error extracting {cmd_name}: {e}")
                commands[cmd_name] = None
        
        return commands
    
    # Helper methods for processing data
    def _extract_port_name(self, full_port_name: str) -> str:
        """Extract standardized port name from full interface name."""
        match = re.search(r"\d+/\d+(?:/\d+)*", full_port_name)
        return match.group() if match else full_port_name
    
    def _process_interface_details(self, show_interface_data: Optional[str]):
        """Process 'show interface' command output."""
        if not show_interface_data:
            return
        
        interface_pattern = r"(?P<port_name>\S+)\s+is\s+(?P<interface_status>down|up)(?P<interface>(?:.|\n)*?)(?=\n\S+\s+is\s+(down|up)|\Z)"
        
        for match in re.finditer(interface_pattern, show_interface_data):
            port_name = match.group("port_name")
            if "port-channel" in port_name or "Vlan" in port_name: # Skip port-channels and VLANs
                continue
            
            port_name = self._extract_port_name(port_name)
            interface_data = match.group("interface")
            interface_status = match.group("interface_status")
            
            # Extract interface details
            description = self._extract_regex_group(r"Description: (.+)", interface_data)
            mtu = self._extract_regex_group(r"MTU (\d+)", interface_data)
            bandwidth = self._extract_regex_group(r"BW (\d+) Kbit,", interface_data)
            
            self.interface_manager.add_interface(
                port_name=port_name,
                Description=description,
                **{"Interface Name": match.group("port_name")},
                # **{"Interface Status": interface_status},
                **{"Interface MTU": mtu},
                **{"Bandwidth": bandwidth}
            )
    
    def _process_interface_status(self, show_interface_status_data: Optional[str]):
        """Process 'show interface status' command output."""
        if not show_interface_status_data:
            return
        
        # interface_status_pattern = r"(?P<port_name>\S+)\s(?:\s+[\S\s\#\-]{1,18})\s([\S\s]{2,9})\s+(.+?)\s+(?P<port_duplex>.+?)\s+(?P<port_speed>.+?)\s+(?P<port_type>.+?)\n"
        interface_status_pattern = r"(?P<port_name>\S+)\s(?:\s+[\S\s\#\-]{1,18})\s(?P<port_status>[\S\s]{2,9})\s+(.+?)\s+(?P<port_duplex>.+?)\s+(?P<port_speed>.+?)\s(?P<port_type>.+?)\n"
        
        for match in re.finditer(interface_status_pattern, show_interface_status_data):
            port_name = match.group("port_name")
            if "Po" in port_name or "Vlan" in port_name: # Skip port-channels and VLANs
                continue
            
            port_name = self._extract_port_name(port_name)
            
            self.interface_manager.configure_interface(
                port_name=port_name,
                **{"Media RJ45/SFP": ""},
                **{"Interface Status": match.group("port_status").strip()},
                **{"SFP Type": match.group("port_type").strip() if match.group("port_type").strip() else "N/A" },
                **{"Speed": match.group("port_speed").strip()},
                **{"Duplex": match.group("port_duplex").strip()}
            )
    
    def _process_running_config(self, running_config: Optional[str]):
        """Process running configuration to extract port settings."""
        if not running_config:
            return
        
        port_config_pattern = re.compile(r"\ninterface\s+(?P<port_name>\S+)(?P<config>(?:.|\n)*?)(?=\ninterface\s|\n\n)")
        vpc_mapping = self._build_vpc_mapping(port_config_pattern.finditer(running_config))
        
        for match in port_config_pattern.finditer(running_config):
            port_name = match.group("port_name")
            if "port-channel" in port_name or "Vlan" in port_name: # Skip port-channels and VLANs
                continue
            
            port_name = self._extract_port_name(port_name)
            config_data = match.group("config")
            
            # Extract configuration details
            # trunk_access = self._extract_regex_group(r"switchport (?:mode )?(access|monitor|trunk|fex-fabric)", config_data, "N/A")
            # trunk_access = self._extract_regex_group(r"switchport (?:mode )?(.+?)(?: |\n)", config_data, "N/A")
            trunk_access = self._extract_regex_group(r"switchport (?:mode )?(.+?)(?: vlan|\n)", config_data, "N/A")
            # if trunk_access == "N/A":
            #     logging.warning(f"No switchport mode found for port {port_name} in configuration.")
            port_channel_info = self._extract_port_channel_info(config_data, vpc_mapping)
            vlan_pvlan = self._extract_vlan_info(config_data, trunk_access)
            
            self.interface_manager.configure_interface(
                port_name=port_name,
                **{"Trunk/Access/PC/VPC/PVLAN": trunk_access},
                **{"Port-Channel": port_channel_info['port_channel']},
                **{"Virtual Port-Channel": port_channel_info['vpc']},
                **{"Vlan/PVLAN": vlan_pvlan}
            )
    
    def _build_vpc_mapping(self, port_configs) -> Dict[str, List[str]]:
        """Build VPC mapping from port-channel configurations."""
        vpc_mapping = {}
        for match in port_configs:
            port_name = match.group("port_name")
            if "port-channel" in port_name:
                vpc_match = re.search(r"vpc\s+(.+)", match.group("config"))
                if vpc_match:
                    vpc_mapping[port_name] = [vpc_match.group(1)]
                # else:
                #     logging.warning(f"No VPC found for port-channel {port_name} in configuration.")
        return vpc_mapping
    
    def _extract_port_channel_info(self, config_data: str, vpc_mapping: Dict) -> Dict[str, str]:
        """Extract port-channel and VPC information."""
        port_channel_match = re.search(r"(channel-group (\d+)(?:.+|$))", config_data)
        if port_channel_match:
            port_channel = port_channel_match.group(1)
            port_channel_name = f"port-channel{port_channel_match.group(2)}"
            vpc = vpc_mapping.get(port_channel_name, ["N/A"])[0]
        else:
            port_channel = "N/A"
            vpc = "N/A"
        
        return {'port_channel': port_channel, 'vpc': vpc}
    
    def _extract_vlan_info(self, config_data: str, trunk_access: str) -> str:
        """Extract VLAN information based on switchport mode."""
        if trunk_access == "trunk":
            vlan_match = re.search(r"switchport trunk allowed vlan (.+)", config_data)
            return f"Trunk VLANs: {vlan_match.group(1)}" if vlan_match else "Trunk VLANs: All"
        elif "private-vlan" in trunk_access:
            # vlan_match = re.search(r"switchport private-vlan trunk allowed vlan (.+)", config_data)
            pvlan_match = re.findall(r"(switchport private-vlan (?:host-association|association trunk|mapping)?(?:trunk )?(?:native vlan|allowed vlan)? .+)", config_data)
            # result = f"Trunk VLANs: {vlan_match.group(1)}" if vlan_match else "Trunk VLANs: N/A"

            if pvlan_match: 
                pvlan = "\n".join(f"{vlan}" for vlan in pvlan_match)
                # if vlan_match:
                #     result += f"\n{pvlan}" 
                # else:
                #     return pvlan
            else:
                logging.warning(f"No private VLAN configuration found for\n{config_data}")
            
            return pvlan if pvlan_match else "N/A"
        else:
            vlan_match = re.search(r"switchport access vlan (\d+)", config_data)
            return f"VLAN: {vlan_match.group(1)}" if vlan_match else "N/A"
    
    def _process_mac_and_arp_tables(self, show_mac_address_table: Optional[str], 
                                  show_ip_arp: Optional[str]):
        """Process MAC address table and ARP table data."""
        if not show_mac_address_table or not show_ip_arp:
            return
        
        # Build MAC to IP mapping from ARP table
        vlan_to_ip_mac_mapping = self._parse_arp_table(show_ip_arp)
        
        # Process MAC address table
        self._parse_mac_address_table(show_mac_address_table, vlan_to_ip_mac_mapping)
    
    def _parse_arp_table(self, show_ip_arp: str) -> Dict[str, Dict[str, str]]:
        """Parse ARP table to create MAC to IP mapping."""
        mac_to_ip_mapping = {}
        vlan_to_ip_mac_mapping = {}

        if os.path.exists(f"ALL_IP_ARP_TABLE.csv"):
            logging.debug("Maping Using ALL_IP_ARP_TABLE")
            # read existing ARP table from CSV
            with open(f"ALL_IP_ARP_TABLE.csv", 'r') as csv_file:
                reader = csv.reader(csv_file)
                next(reader)  # Skip header row                
                for row in reader:
                    ip_address = row[2]
                    mac_address = row[1].lower()
                    mac_address = self.mac_to_4digit_format(str(mac_address))
                    vlan_id = row[0].replace('Vlan', '')

                    if vlan_id not in vlan_to_ip_mac_mapping:
                        vlan_to_ip_mac_mapping[vlan_id] = {}
                    
                    vlan_to_ip_mac_mapping[vlan_id][mac_address] = {
                        'mac': mac_address,
                        'ip': ip_address
                    }
                    
                    mac_to_ip_mapping[mac_address] = {
                        'ip': ip_address,
                        'vlan': vlan_id
                    }
        else:
            logging.debug("Maping Using `show ip arp`")

            arp_pattern = r'^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(Vlan\d+)'
            
            for line in show_ip_arp.strip().split('\n'):
                line = line.strip()
                if not line or any(keyword in line for keyword in ['Flags:', 'IP ARP', 'Total', 'Address']):
                    continue
                
                arp_match = re.match(arp_pattern, line)
                if arp_match:
                    ip_address = arp_match.group(1)
                    mac_address = arp_match.group(2).lower()
                    vlan_id = arp_match.group(3).replace('Vlan', '')
                    
                    if vlan_id not in vlan_to_ip_mac_mapping:
                        vlan_to_ip_mac_mapping[vlan_id] = {}
                    
                    vlan_to_ip_mac_mapping[vlan_id][mac_address] = {
                        'mac': mac_address,
                        'ip': ip_address
                    }
                    
                    mac_to_ip_mapping[mac_address] = {
                        'ip': ip_address,
                        'vlan': vlan_id
                    }
            
            # Save VLAN to IP/MAC mapping
        with open(f"{OUTPUT_FOLDER}/{self.hostname}_vlan_to_ip_mac_mapping.json", 'w') as f:
            json.dump(vlan_to_ip_mac_mapping, f, indent=2)
        
        return vlan_to_ip_mac_mapping
    
    def _parse_mac_address_table(self, show_mac_address_table: str, vlan_to_ip_mac_mapping: Dict):
        """Parse MAC address table and correlate with IP addresses."""
        main_pattern = r'^[*|G|+|O\s]*(\d+|-)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\w+)\s+(\d+|-|NA|~~~)\s+(\S+)\s+(\S+)\s+(.+)$'
        continuation_pattern = r'^\s+(.+)$'
        
        current_mac_address = None
        current_vlan = None
        
        for line in show_mac_address_table.strip().split('\n'):
            if not line.strip():
                continue
            
            main_match = re.match(main_pattern, line)
            if main_match:
                vlan_id = main_match.group(1)
                mac_address = main_match.group(2).lower()
                port_name = main_match.group(7).strip()
                
                current_mac_address = mac_address
                current_vlan = vlan_id
                # print(f"Processing MAC entry: {mac_address} on VLAN {vlan_id} for port {port_name}")
                
                ip_address = vlan_to_ip_mac_mapping.get(vlan_id, {}).get(mac_address, {}).get('ip')

                self._add_mac_entries(port_name, vlan_id, mac_address, ip_address)
            else:
                cont_match = re.match(continuation_pattern, line)
                if cont_match and current_mac_address and current_vlan:
                    additional_ports = cont_match.group(1).strip()
                    # ip_address = vlan_to_ip_mac_mapping.get(current_mac_address, {}).get('ip')
                    ip_address = vlan_to_ip_mac_mapping.get(vlan_id, {}).get(mac_address, {}).get('ip')

                    self._add_mac_entries(additional_ports, current_vlan, current_mac_address, ip_address)
            
            if not main_match and not cont_match:
                logging.warning(f"Unrecognized line in MAC address table: {line.strip()}")
    
    def _add_mac_entries(self, port_names: str, vlan_id: str, mac_address: str, ip_address: Optional[str]):
        """Add MAC entries for multiple ports."""
        if len(port_names.split()) > 1:
            for port in port_names.split():
                port = port.strip()
                if port:
                    self.mac_address_table.add_entry(port, vlan_id, mac_address, ip_address)
        else:
            port_name = self._extract_port_name(port_names)
            self.mac_address_table.add_entry(port_name, vlan_id, mac_address, ip_address)
    
    def _process_neighbors_details(self, show_cdp_neighbors_detail: Optional[str], show_lldp_neighbors_detail: Optional[str]):
        """Process CDP and LLDP neighbor details."""
        if not show_cdp_neighbors_detail and not show_lldp_neighbors_detail:
            return
        
        # Process LLDP neighbors
        if show_lldp_neighbors_detail:
            lldp_pattern = r"Chassis id: (?P<hostname>.*?)\nPort id: (?P<port>.*?)\nLocal Port id: (?P<interface>.*?)\nPort Description: (?P<port_desc>.*?)\nSystem Name: (?P<system_name>.*?)\nSystem Description: (?P<system_desc>.*?)\n"
            lldp_amount_pattern = r"Total entries displayed: (\d+)"

            lldp_amount = re.search(lldp_amount_pattern, show_lldp_neighbors_detail)
            if lldp_amount:
                lldp_amount = int(lldp_amount.group(1))
                lldp_find_amount = int(len(re.findall(lldp_pattern, show_lldp_neighbors_detail)))

                if lldp_amount != lldp_find_amount:
                    logging.error(f"Total LLDP neighbors: {lldp_amount}, but discovered {lldp_find_amount}.")
                else:
                   logging.debug(f"Total LLDP neighbors: {lldp_amount}")

            for match in re.finditer(lldp_pattern, show_lldp_neighbors_detail, re.DOTALL):
                
                system_name = match.group("system_name") if match.group("system_name") != "not advertised" else match.group("system_desc")
                
                port_desc = match.group("port_desc") if match.group("port_desc") != "not advertised" else ""
                port_info = f"{match.group('port')} - {port_desc}" if port_desc else match.group("port")
                
                # print(f"lldp Neighbor found: {system_name} on {port_info}")
                
                self.interface_manager.configure_interface(
                    port_name=self._extract_port_name(match.group("interface")),
                    **{"End device hostname": match.group("hostname")},
                    **{"End device Model": system_name},
                    **{"End device Port": port_info},
                    **{"End device neighbors kind": "lldp"}
                )
        
        # Process CDP neighbors
        if show_cdp_neighbors_detail:
            cdp_pattern = r"Device ID:(?P<device_id>\S+)\n.*?(?:System Name: (?P<hostname>\S+)\n)?\n.*?Interface address\(es\):(?:\n|.*?)Platform:\s(?P<model>.+?),.*?Interface:\s(?P<interface>\S+), Port ID \(outgoing port\): (?P<port>.*?)\n"
            cdp_amount_pattern = r"(Device ID:)"

            cdp_amount = re.findall(cdp_amount_pattern, show_cdp_neighbors_detail)
            if cdp_amount:
                cdp_amount = int(len(cdp_amount))
                cdp_find_amount = int(len(re.findall(cdp_pattern, show_cdp_neighbors_detail, re.DOTALL)))

                if cdp_amount != cdp_find_amount:
                    logging.error(f"Total CDP neighbors : {cdp_amount}, but discovered {cdp_find_amount}.")
                else:
                    logging.debug(f"Total CDP neighbors : {cdp_amount}")
            
            for match in re.finditer(cdp_pattern, show_cdp_neighbors_detail, re.DOTALL):

                hostname = match.group("device_id").split("(")[0] if match.group("hostname") else match.group("device_id")
                # print(f"CDP Neighbor found: {hostname} on {match.group('interface')}")

                self.interface_manager.configure_interface(
                    port_name=self._extract_port_name(match.group("interface")),
                    **{"End device hostname": hostname},
                    **{"End device Model": match.group("model")},
                    **{"End device Port": match.group("port")},
                    **{"End device neighbors kind": "CDP"}
                )
     
    def _populate_port_mapping(self):
        """Populate port mapping with MAC and IP addresses."""
        for port_name, config in list(self.interface_manager.get_all_interfaces().items()):
            # Determine interface type for MAC table lookup
            port_channel_num = re.sub(r"\D+", "", config['Port-Channel'])
            interface_type = f"Po{port_channel_num}" if port_channel_num else port_name
            
            vlan_mac_entries = self.mac_address_table.get_entries_by_interface(interface_type)
            
            if vlan_mac_entries:
                mac_addresses = []
                vlan_addresses = []
                ip_addresses = []
                
                for vlan, entries in vlan_mac_entries.items():
                    for entry in entries:
                        mac_addresses.append(entry.mac_address)
                        vlan_addresses.append(vlan)
                        ip_addresses.append(entry.ip_address or "N/A")
                
                self.interface_manager.configure_interface(
                    port_name=port_name,
                    **{"Mac Address on Existing Switch Port": mac_addresses},
                    **{"Vlan Address on Existing Switch Port": vlan_addresses},
                    **{"IP Address on Existing Switch Port": ip_addresses}
                )
    
    def _export_to_csv(self):
        """Export interface data to CSV file."""
        with open(f"{OUTPUT_FOLDER}/{self.hostname}_port_mapping.csv", 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(CSV_HEADERS)
            
            for i, (port_name, config) in enumerate(self.interface_manager.get_all_interfaces().items(), start=1):
                # Normalize list data
                mac_addresses = self._normalize_to_list(config.get("Mac Address on Existing Switch Port", []))
                vlan_addresses = self._normalize_to_list(config.get("Vlan Address on Existing Switch Port", []))
                ip_addresses = self._normalize_to_list(config.get("IP Address on Existing Switch Port", []))
                
                max_length = max(len(mac_addresses), len(vlan_addresses), len(ip_addresses))
                
                for j in range(max_length):
                    mac_addr = mac_addresses[j] if j < len(mac_addresses) else 'N/A'
                    vlan_addr = vlan_addresses[j] if j < len(vlan_addresses) else 'N/A'
                    ip_addr = ip_addresses[j] if j < len(ip_addresses) else 'N/A'
                    
                    if j == 0:  # First row with full port information
                        row = [
                            i, self.hostname, "N/A", 
                            config.get("Interface Name", "N/A"),
                            config.get("Description", "N/A"),
                            config.get("Interface Status", "N/A"),
                            config.get("Interface MTU", "N/A"),
                            config.get("Media RJ45/SFP", "N/A"),
                            config.get("SFP Type", "N/A"),
                            config.get("Speed", "N/A"),
                            config.get("Duplex", "N/A"),
                            config.get("Trunk/Access/PC/VPC/PVLAN", "N/A"),
                            config.get("Port-Channel", "N/A"),
                            config.get("Virtual Port-Channel", "N/A"),
                            config.get("Vlan/PVLAN", "N/A"),
                            mac_addr, vlan_addr, ip_addr,
                            config.get("End device hostname", "N/A"),
                            config.get("End device Model", "N/A"),
                            config.get("End device Port", "N/A"),
                            config.get("End device neighbors kind", "N/A")
                        ]
                    else:  # Continuation rows
                        row = [""] * 15 + [mac_addr, vlan_addr, ip_addr]
                    
                    writer.writerow(row)
    
    def _normalize_to_list(self, value) -> List[str]:
        """Normalize value to a list format."""
        if isinstance(value, str):
            return [value] if value != "N/A" else ['N/A']
        elif not value:
            return ['N/A']
        return value
    
    def _extract_regex_group(self, pattern: str, text: str, default: str = "N/A") -> str:
        """Extract regex group with default fallback."""
        match = re.search(pattern, text)
        return match.group(1) if match else default

    def mac_to_4digit_format(self, mac_address):
        """
        Convert MAC address from standard format to 4-digit separation format
        
        Args:
            mac_address (str): MAC address in format like "00:50:56:9d:95:d9"
        
        Returns:
            str: MAC address in 4-digit format like "0050:569d:95d9"
        """
        # Remove separators and convert to uppercase
        clean_mac = mac_address.replace(':', '').replace('-', '')
        
        # Validate MAC address length
        if len(clean_mac) != 12:
            return clean_mac
        
        # Group into 4-digit segments
        segments = [clean_mac[i:i+4] for i in range(0, 12, 4)]
        
        # Join with colons
        return '.'.join(segments)

class CustomFormatter(logging.Formatter):
    """Custom logging formatter."""
    
    def format(self, record):
        if record.levelno in (logging.ERROR, logging.WARNING):
            self._style = logging.PercentStyle('    %(levelname)s: %(message)s')
        else:
            self._style = logging.PercentStyle('%(message)s')
        return super().format(record)

def setup_logging():
    """Initialize logging configuration."""
    file_handler = logging.FileHandler(LOG_FILE_NAME, mode='w')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(CustomFormatter())
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(CustomFormatter())
    
    logging.basicConfig(level=logging.DEBUG, handlers=[file_handler, console_handler])

def get_text_files() -> List[str]:
    """Get sorted list of text files to process."""
    files = [f for f in os.listdir() if os.path.splitext(f)[1] in TEXT_FILE_EXTENSIONS]
    # Natural sort
    files.sort(key=lambda x: [int(c) if c.isdigit() else c.lower() for c in re.split('([0-9]+)', x)])
    return files

def process_switch_files():
    """Main function to process switch configuration files."""
    # Setup
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    setup_logging()
    
    files = get_text_files()
    processed_files = []
    unknown_files = []
    
    # Regex patterns
    nxos_switch_pattern = re.compile(r"!Command:")
    nxos_hostname_pattern = re.compile(r"(?:hostname|switchname)\s+(.+?)\n")
    unicode_escape_pattern = r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'
    
    for file in files:
        try:
            with open(file, "r", encoding='utf-8', errors='ignore') as f:
                data = f.read()
                data = re.sub(unicode_escape_pattern, '', data)
                
                if nxos_switch_pattern.search(data):
                    hostname_match = nxos_hostname_pattern.search(data)
                    if hostname_match:
                        hostname = hostname_match.group(1)
                        NexusSwitch(data, hostname)
                        processed_files.append(file)
                    else:
                        logging.warning(f"Hostname not found in file [{file}]")
                        unknown_files.append(file)
                else:
                    unknown_files.append(file)
                    
        except Exception as e:
            logging.error(f"Error processing file [{file}]: {e}")
            logging.error(traceback.format_exc())
            unknown_files.append(file)
    
    # Summary
    logging.debug("\n" + "-" * 50)
    for file in unknown_files:
        logging.debug(f"Unknown Switch or File [{file}]")
    if unknown_files:
        logging.debug("-" * 50)
    
    logging.debug(f"Total files: {len(files)}, Processed: {len(processed_files)}, Unknown: {len(unknown_files)}\n")
    logging.shutdown()

if __name__ == "__main__":
    process_switch_files()
    input("Press Enter to exit...")
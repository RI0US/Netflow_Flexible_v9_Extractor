import pyshark
from datetime import datetime, timedelta
import csv

def extract_netflow_info(pcap_file, output_csv):
    # Open the capture file
    capture = pyshark.FileCapture(pcap_file)

    # Open the CSV file for writing
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write CSV header
        writer.writerow(["time_start", "time_end", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "octets", "packets", "tcp_flags"])

        # Iterate over each packet in the capture
        for packet in capture:
            # Check if the packet has a CFLOW (NetFlow) layer
            if 'CFLOW' in packet:
                try:
                    # Get all field data for this CFLOW session
                    num_flows = len(packet.cflow.srcaddr.all_fields)
                    for session_idx in range(num_flows):

                        # Extract relevant CFLOW fields
                        abstimestart = packet.cflow.abstimestart.all_fields[session_idx].get_default_value()
                        abstimeend = packet.cflow.abstimeend.all_fields[session_idx].get_default_value()
                        srcaddr = packet.cflow.srcaddr.all_fields[session_idx].get_default_value()
                        dstaddr = packet.cflow.dstaddr.all_fields[session_idx].get_default_value()
                        protocol = packet.cflow.protocol.all_fields[session_idx].get_default_value()
                        srcport = packet.cflow.srcport.all_fields[session_idx].get_default_value()
                        dstport = packet.cflow.dstport.all_fields[session_idx].get_default_value()
                        octets = packet.cflow.octets.all_fields[session_idx].get_default_value()
                        packets = packet.cflow.packets.all_fields[session_idx].get_default_value()
                        tcp_flags_hex = ''

                        # Skip empty or missing values (i.e., if srcaddr, dstaddr, or protocol is None)
                        if not (srcaddr and dstaddr and protocol):
                            continue

                        # Convert protocol number to human-readable protocol name
                        if protocol == '6':
                            protocol_name = 'TCP'
                        elif protocol == '17':
                            protocol_name = 'UDP'
                        else:
                            protocol_name = protocol  # Use the protocol number if it is not TCP/UDP

                        # Parse abstimestart and abstimeend as datetime strings
                        if abstimestart and abstimeend:
                            # Truncate the timestamps to remove the extra decimals beyond 6 places
                            abstimestart_truncated = abstimestart[:26]  # Trim to keep 6 digits for microseconds
                            abstimeend_truncated = abstimeend[:26]

                            # Parse the truncated date string to a datetime object
                            abstimestart_dt = datetime.strptime(abstimestart_truncated, '%b %d, %Y %H:%M:%S.%f')
                            abstimeend_dt = datetime.strptime(abstimeend_truncated, '%b %d, %Y %H:%M:%S.%f')

                            # Subtract 8 hours from the datetime
                            start_time_minus_8 = abstimestart_dt + timedelta(hours=4)
                            end_time_minus_8 = abstimeend_dt + timedelta(hours=4)

                            # Format the result as a string
                            start_time_formatted = start_time_minus_8.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                            end_time_formatted = end_time_minus_8.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                        else:
                            start_time_formatted = ''
                            end_time_formatted = ''

                        # Helper function to handle boolean-like values for flags
                        def parse_flag(value):
                            if value == 'True':
                                return 1
                            elif value == 'False':
                                return 0
                            return int(value)

                        # If protocol is TCP, extract and convert TCP flags to a single hexadecimal value
                        if protocol == '6':  # Protocol number for TCP is 6
                            # Combine TCP flags into a single value, handling 'False' and 'True' values
                            tcp_flags_value = (
                                    (parse_flag(packet.cflow.tcpflags_urg.all_fields[session_idx].get_default_value()) << 5) |
                                    (parse_flag(packet.cflow.tcpflags_ack.all_fields[session_idx].get_default_value()) << 4) |
                                    (parse_flag(packet.cflow.tcpflags_psh.all_fields[session_idx].get_default_value()) << 3) |
                                    (parse_flag(packet.cflow.tcpflags_rst.all_fields[session_idx].get_default_value()) << 2) |
                                    (parse_flag(packet.cflow.tcpflags_syn.all_fields[session_idx].get_default_value()) << 1) |
                                    (parse_flag(packet.cflow.tcpflags_fin.all_fields[session_idx].get_default_value()) << 0)
                            )
                            tcp_flags_hex = f"0x{tcp_flags_value:02x}"

                        # Skip rows where srcport or dstport is 0
                        if srcport == '0' or dstport == '0':
                            continue

                        # Write the extracted values to the CSV file
                        writer.writerow([start_time_formatted, end_time_formatted, srcaddr, dstaddr, protocol_name, srcport, dstport, octets, packets, tcp_flags_hex])

                except (AttributeError, ValueError):
                    continue  # Skip any packets that raise exceptions
            else:
                continue  # Skip packets that do not have a CFLOW layer

if __name__ == "__main__":
    pcap_file = "tech6_netflow.pcap"  # Replace with the path to your PCAP file
    output_csv = "netflow_output.csv"  # Specify the output CSV file name
    extract_netflow_info(pcap_file, output_csv)

"""
Description:
 Generates various reports from a gateway log file.

Usage:
 python log_investigation.py log_path

Parameters:
 log_path = Path of the gateway log file
"""
import log_analysis_lib as la
import pandas as pd
import re


# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = la.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic()
    

    # Per step 9, generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report(log_path)
    

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    """Produces a dictionary of destination port numbers (key) that appear in a 
    specified log file and a count of how many times they appear (value)

    Returns:
        dict: Dictionary of destination port number counts
    """
    # TODO: Complete function body per step 7

    dpt_data = la.filter_log_by_regex(log_path, "DPT=(.*?) ")[1]
    dpt_tally = {}
    for dpt in dpt_data:
        dpt_tally[dpt[0]] = dpt_tally.get(dpt[0], 0) + 1

    return dpt_tally

def generate_port_traffic_report(port_number):
    """Produces a CSV report of all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    # TODO: Complete function body per step 8
    # Get data from records that contain the specified destination port
    regex = "^(.{6}) (.*) myth.* SRC=(.*?) DST=(.*?) .*SPT=(.*?) DPT=" + f"({port_number})"
    whatever, report_records = la.filter_log_by_regex(log_path, regex)
    
    # Generate the CSV report
    report_df = pd.DataFrame(report_records)
    report_header = ('Date', 'Time', 'Source IP Address', 'Destination IP Address', 'Source Port', 'Destination Port')
    report_filemame = f"destination_port_{port_number}_report.csv"
    report_csv = report_df.to_csv(report_filemame, header=report_header, index=False)
    return report_csv

def generate_invalid_user_report(log_path):
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    # TODO: Complete function body per step 10
    # Get data from records that show attempted invalid user login
    regex_filter = "^(.{6}) (.*) myth.* user (.*) from (.*)"
    whatever, inv_report_record = la.filter_log_by_regex(log_path, regex_filter)

    # Generate the CSV report
    inv_report_df = pd.DataFrame(inv_report_record)
    inv_report_header = ('Date', 'Time', 'Username', 'IP Address')
    inv_report_name = "invalid_users.csv"
    inv_report_csv = inv_report_df.to_csv(inv_report_name, header=inv_report_header, index=False)

    return inv_report_csv

def generate_source_ip_log(ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    # TODO: Complete function body per step 11
    # Get all records that have the specified source IP address
    regex_filter_2 = "^(.{6} .* SRC=" + f"{ip_address} .* )"
    ip_report_record = la.filter_log_by_regex(log_path, regex_filter_2)

    # Save all records to a plain text .txt file

    ip_report_df = pd.DataFrame(ip_report_record)
    ip_sub = re.sub('\\.', '_', ip_address)
    ip_report_name = f"source_ip_{ip_sub}.txt"
    ip_report_csv = ip_report_df.to_csv(ip_report_name, header=False, index=False)

    return ip_report_csv

if __name__ == '__main__':
    main()
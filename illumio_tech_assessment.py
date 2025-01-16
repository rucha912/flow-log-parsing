import csv
from collections import defaultdict

def load_lookup_table(file_path):
    """Load the lookup table from a CSV file."""
    lookup_table = {}
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (int(row['dstport']), row['protocol'].strip().lower())
            lookup_table[key] = row['tag'].strip()
    print(lookup_table)
    return lookup_table

def parse_flow_logs(flow_log_file_path, lookup_table):
    """Parse flow logs and count matches for tags and port/protocol combinations."""
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)
    untagged_count = 0

    with open(flow_log_file_path, 'r') as f:
        for line in f:
            # Extract relevant fields: dstport (7th column), protocol (8th column)
            log_line = line.split()
            # No data and skipped records must be skipped
            if len(log_line) < 8:
                continue  # Skip invalid lines
            if log_line[-1] == 'NODATA' or log_line[-1] == 'SKIPDATA':
                continue

            dstport = int(log_line[6])
            IANA_protocol_numbers = {'6':'tcp','17':'udp','1':'icmp'}
            protocol = IANA_protocol_numbers[log_line[7]] if log_line[7] in IANA_protocol_numbers else 'unknown'
            
            key = (dstport, protocol)
            # Check lookup table and get tag if key is present
            if key in lookup_table:
                tag_counts[lookup_table[key]] += 1
                print(str(log_line)+" ---> "+str(key)+" "+lookup_table[key])
            else:
                print(str(log_line)+" ---> "+str(key)+" untagged")
                untagged_count += 1

            # # Check lookup table
            # tag = lookup_table.get(key, None)
            # if tag:
            #     tag_counts[tag] += 1
            # else:
            #     untagged_count += 1

            # Count port/protocol combinations
            port_protocol_counts[key] += 1

    return tag_counts, port_protocol_counts, untagged_count

def write_output(tag_counts, port_protocol_counts, untagged_count, output_file):
    """Write the output to a file."""
    with open(output_file, 'w') as f:
        # Write tag counts
        f.write("Tag Counts:\n")
        f.write("Tag,Count\n")
        for tag, count in tag_counts.items():
            f.write(f"{tag},{count}\n")
        f.write(f"Untagged,{untagged_count}\n\n")

        # Write port/protocol combination counts
        f.write("Port/Protocol Combination Counts:\n")
        f.write("Port,Protocol,Count\n")
        for (port, protocol), count in port_protocol_counts.items():
            f.write(f"{port},{protocol},{count}\n")

def main():
    # Input files
    lookup_file = 'lookup_table.csv'
    flow_logs_file = 'flow_logs.txt'
    output_file = 'output.txt'

    # Load lookup table
    lookup_table = load_lookup_table(lookup_file)

    # Parse flow logs
    tag_counts, port_protocol_counts, untagged_count = parse_flow_logs(flow_logs_file, lookup_table)

    # Write output
    write_output(tag_counts, port_protocol_counts, untagged_count, output_file)

if __name__ == '__main__':
    main()
import unittest
from unittest.mock import mock_open, patch
from collections import defaultdict

class TestFlowLogParser(unittest.TestCase):

    def setUp(self):
        self.lookup_table_content = (
            "dstport,protocol,tag\n"
            "25,tcp,sv_P1\n"
            "68,udp,sv_P2\n"
            "23,tcp,sv_P1\n"
            "31,udp,SV_P3\n"
            "443,tcp,sv_P2\n"
            "22,tcp,sv_P4\n"
            "3389,tcp,sv_P5\n"
            "0,icmp,sv_P5\n"
            "110,tcp,email\n"
            "993,tcp,email\n"
            "143,tcp,email\n"
        )

        self.flow_logs_content = (
            "2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK\n"
            "2 123456789012 eni-4d3c2b1a 192.168.1.100 203.0.113.101 23 49154 6 15 12000 1620140761 1620140821 REJECT OK\n"
            "2 123456789012 eni-5e6f7g8h 192.168.1.101 198.51.100.3 25 49155 6 10 8000 1620140761 1620140821 ACCEPT OK\n"
            "2 123456789012 eni-9h8g7f6e 172.16.0.100 203.0.113.102 110 49156 6 12 9000 1620140761 1620140821 ACCEPT OK\n"
            "2 123456789012 eni-7i8j9k0l 172.16.0.101 192.0.2.203 993 49157 6 8 5000 1620140761 1620140821 ACCEPT OK\n"
            "2 123456789012 eni-6m7n8o9p 10.0.2.200 198.51.100.4 143 49158 6 18 14000 1620140761 1620140821 ACCEPT OK\n"
            "2 123456789012 eni-1a2b3c4d 192.168.0.1 203.0.113.12 1024 80 6 10 5000 1620140661 1620140721 ACCEPT OK\n"
            "2 123456789012 eni-1a2b3c4d 203.0.113.12 192.168.0.1 80 1024 6 12 6000 1620140661 1620140721 ACCEPT OK\n"
            "2 123456789012 eni-1a2b3c4d 10.0.1.102 172.217.7.228 1030 443 6 8 4000 1620140661 1620140721 ACCEPT OK\n"
            "2 123456789012 eni-5f6g7h8i 10.0.2.103 52.26.198.183 56000 23 6 15 7500 1620140661 1620140721 REJECT OK\n"
            "2 123456789012 eni-9k10l11m 192.168.1.5 51.15.99.115 49321 25 6 20 10000 1620140661 1620140721 ACCEPT OK\n"
            "2 123456789012 eni-1a2b3c4d 192.168.1.6 87.250.250.242 49152 110 6 5 2500 1620140661 1620140721 ACCEPT OK\n"
            "2 123456789012 eni-2d2e2f3g 192.168.2.7 77.88.55.80 49153 993 6 7 3500 1620140661 1620140721 ACCEPT OK\n"
            "2 123456789012 eni-4h5i6j7k 172.16.0.2 192.0.2.146 49154 143 6 9 4500 1620140661 1620140721 ACCEPT OK\n"            
            "2 123456789010 eni-1235b8ca123456789 - - - - - - - 1431280876 1431280934 - NODATA\n"
            "2 123456789010 eni-11111111aaaaaaaaa - - - - - - - 1431280876 1431280934 - SKIPDATA\n"
        )

    @patch("builtins.open", new_callable=mock_open)
    def test_load_lookup_table(self, mock_file):
        from illumio_tech_assessment import load_lookup_table
        mock_file.return_value.read.return_value = self.lookup_table_content
        with patch("builtins.open", mock_open(read_data=self.lookup_table_content)) as mock_lookup_table_file:
            lookup_table = load_lookup_table(mock_lookup_table_file)

        expected_lookup = {
            (25, 'tcp'): 'sv_P1', 
            (68, 'udp'): 'sv_P2', 
            (23, 'tcp'): 'sv_P1', 
            (31, 'udp'): 'SV_P3', 
            (443, 'tcp'): 'sv_P2', 
            (22, 'tcp'): 'sv_P4', 
            (3389, 'tcp'): 'sv_P5', 
            (0, 'icmp'): 'sv_P5', 
            (110, 'tcp'): 'email', 
            (993, 'tcp'): 'email', 
            (143, 'tcp'): 'email'
        }
        self.assertEqual(lookup_table, expected_lookup)

    @patch("builtins.open", new_callable=mock_open)
    def test_parse_flow_logs(self, mock_file):
        from illumio_tech_assessment import parse_flow_logs

        # Mock lookup table
        lookup_table = {
            (25, 'tcp'): 'sv_P1', 
            (68, 'udp'): 'sv_P2', 
            (23, 'tcp'): 'sv_P1', 
            (31, 'udp'): 'SV_P3', 
            (443, 'tcp'): 'sv_P2', 
            (22, 'tcp'): 'sv_P4', 
            (3389, 'tcp'): 'sv_P5', 
            (0, 'icmp'): 'sv_P5', 
            (110, 'tcp'): 'email', 
            (993, 'tcp'): 'email', 
            (143, 'tcp'): 'email',
        }

        # Simulate reading the flow logs file
        mock_file.return_value.read.return_value = self.flow_logs_content

        with patch("builtins.open", mock_open(read_data=self.flow_logs_content)) as mock_flow_file:
            tag_counts, port_protocol_counts, untagged_count = parse_flow_logs(mock_flow_file, lookup_table)

        expected_tag_counts = {
            'sv_P2': 1, 
            'sv_P1': 2, 
            'email': 3
        }

        expected_port_protocol_counts = {
            (49153, 'tcp'): 1, 
            (49154, 'tcp'): 1, 
            (49155, 'tcp'): 1, 
            (49156, 'tcp'): 1, 
            (49157, 'tcp'): 1, 
            (49158, 'tcp'): 1, 
            (80, 'tcp'): 1, 
            (1024, 'tcp'): 1, 
            (443, 'tcp'): 1, 
            (23, 'tcp'): 1, 
            (25, 'tcp'): 1, 
            (110, 'tcp'): 1, 
            (993, 'tcp'): 1, 
            (143, 'tcp'): 1
        }

        self.assertEqual(tag_counts, expected_tag_counts)
        self.assertEqual(port_protocol_counts, expected_port_protocol_counts)
        self.assertEqual(untagged_count, 8)

    @patch("builtins.open", new_callable=mock_open)
    def test_write_output(self, mock_file):
        from illumio_tech_assessment import write_output

        tag_counts = {
            'sv_P2': 1, 
            'sv_P1': 2, 
            'email': 3
        }

        port_protocol_counts = {
            (49153, 'tcp'): 1, 
            (49154, 'tcp'): 1, 
            (49155, 'tcp'): 1, 
            (49156, 'tcp'): 1, 
            (49157, 'tcp'): 1, 
            (49158, 'tcp'): 1, 
            (80, 'tcp'): 1, 
            (1024, 'tcp'): 1, 
            (443, 'tcp'): 1, 
            (23, 'tcp'): 1, 
            (25, 'tcp'): 1, 
            (110, 'tcp'): 1, 
            (993, 'tcp'): 1, 
            (143, 'tcp'): 1
        }

        untagged_count = 8

        with patch("builtins.open", mock_open()) as mocked_file:
            write_output(tag_counts, port_protocol_counts, untagged_count, mock_file)

            mocked_file.assert_called_once_with(mock_file, "w")
            mocked_file().write.assert_any_call("Tag Counts:\n")
            mocked_file().write.assert_any_call("Tag,Count\n")
            mocked_file().write.assert_any_call("sv_P2,1\n")
            mocked_file().write.assert_any_call("sv_P1,2\n")
            mocked_file().write.assert_any_call("Untagged,8\n\n")
            mocked_file().write.assert_any_call("Port/Protocol Combination Counts:\n")
            mocked_file().write.assert_any_call("Port,Protocol,Count\n")
            mocked_file().write.assert_any_call("49153,tcp,1\n")
            mocked_file().write.assert_any_call("49154,tcp,1\n")
            mocked_file().write.assert_any_call("49155,tcp,1\n")
            mocked_file().write.assert_any_call("49156,tcp,1\n")
            mocked_file().write.assert_any_call("49157,tcp,1\n")
            mocked_file().write.assert_any_call("49158,tcp,1\n")
            mocked_file().write.assert_any_call("80,tcp,1\n")
            mocked_file().write.assert_any_call("1024,tcp,1\n")
            mocked_file().write.assert_any_call("443,tcp,1\n")
            mocked_file().write.assert_any_call("23,tcp,1\n")
            mocked_file().write.assert_any_call("25,tcp,1\n")
            mocked_file().write.assert_any_call("110,tcp,1\n")
            mocked_file().write.assert_any_call("993,tcp,1\n")
            mocked_file().write.assert_any_call("143,tcp,1\n")

if __name__ == "__main__":
    unittest.main()

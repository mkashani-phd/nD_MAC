import unittest
import numpy as np

# from Book import Packet, Page
import sys 

sys.path.append('../')
from Book import Packet, Page
from nD_MAC import MACGenerator, MACChecker

class TestMACFunctions(unittest.TestCase):

    def setUp(self):
        # Set up a common test case for multiple tests
        self.page = Page(page_size=3)
        self.packet1 = Packet(SN=0, message=b"Message1", mac=b"")
        self.packet2 = Packet(SN=1, message=b"Message2", mac=b"")
        # Only two packets, third is missing to test fill_missing_packets
        self.page.add_packet(self.packet1)
        self.page.add_packet(self.packet2)

        # Example matrices
        self.X = np.array([[1, 1, 0],  # Packet 1 contributes to both t1 and t2
                           [0, 1, 0],  # Packet 2 contributes only to t2
                           [1, 0, 1]], # Packet 3 contributes only to t1
                          dtype=int)

        self.Y = np.array([[0, 1, 0],  # t2 will be placed in Packet 1's MAC
                           [1, 0, 0],  # t1 will be placed in Packet 2's MAC
                           [0, 0, 1]], # Packet 3 will not have a MAC
                          dtype=int)

        self.secret_key = b"secret_key"

    def test_mac_generation(self):
        # Test the MAC generation process
        generator = MACGenerator(X=self.X, Y=self.Y, secret_key=self.secret_key)
        generator.process_page(self.page)

        # Verify that MACs have been generated correctly
        self.assertIsNotNone(self.page.packets[0].mac)
        self.assertIsNotNone(self.page.packets[1].mac)
        self.assertIsNotNone(self.page.packets[2].mac)  # Packet 3 should be auto-filled

    def test_mac_checking(self):
        # Test the MAC checking process
        generator = MACGenerator(X=self.X, Y=self.Y, secret_key=self.secret_key)
        generator.process_page(self.page)

        checker = MACChecker(X=self.X, Y=self.Y, secret_key=self.secret_key, offset=0)
        concatenated_message, verification_counts, latency = checker.check_page(self.page)

        # Check if all MACs are verified correctly
        self.assertTrue(np.all(verification_counts > 0))

        # Verify that the concatenated message is correct
        expected_message = b"Message1Message2"
        self.assertEqual(concatenated_message, expected_message)

    def test_latency_calculation(self):
        # Test the latency calculation
        generator = MACGenerator(X=self.X, Y=self.Y, secret_key=self.secret_key)
        generator.process_page(self.page)

        checker = MACChecker(X=self.X, Y=self.Y, secret_key=self.secret_key, offset=0.5)
        _, _, latency = checker.check_page(self.page)

        # Verify that the latency is calculated correctly
        self.assertTrue(np.all(latency >= 0.5))

    def test_fill_missing_packets(self):
        # Test the fill_missing_packets method
        generator = MACGenerator(X=self.X, Y=self.Y, secret_key=self.secret_key)
        generator.process_page(self.page)

        self.assertIsNotNone(self.page.packets[2])  # Packet 3 should be auto-filled
        self.assertEqual(self.page.packets[2].message, b'')

    def test_modified_packet(self):
        # Modify a packet to introduce an error and check if MACChecker catches it
        generator = MACGenerator(X=self.X, Y=self.Y, secret_key=self.secret_key)
        generator.process_page(self.page)

        # Modify the message in packet2 to introduce an error
        self.page.packets[1].message = b"TamperedMessage"

        checker = MACChecker(X=self.X, Y=self.Y, secret_key=self.secret_key, offset=0)
        concatenated_message, verification_counts, _ = checker.check_page(self.page)

        # Check if the error is detected
        self.assertTrue(np.any(verification_counts == 0))  # At least one packet should fail verification

if __name__ == "__main__":
    unittest.main()

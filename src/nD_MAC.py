import numpy as np
import hmac
import sys, time
from .Book import Packet, Page


class MACGenerator:
    def __init__(self,X:np.ndarray, Y:np.ndarray, secret_key: bytes = b'key' , digestmod:str = 'sha256'):
        """
        Initialize the HMACCalculator with a given key.

        :param key: The key used to compute HMAC.
        """
        self.secret_key = secret_key
        self.digestmod = digestmod
        self.XT = np.array(X , dtype=int).T
        self.Y = np.array(Y, dtype=int)

    def calculate_hmac(self, message: bytes) -> bytes:
        """
        Calculate the HMAC of a given message.

        :param message: The message for which the HMAC is computed.
        :return: The computed HMAC.
        """
        return hmac.new(self.secret_key, message, digestmod=self.digestmod).digest()

    def process_page(self, page: Page) -> None:
        """
        Process the page and update the packets' MAC fields based on matrices X and Y.

        :param page: The page containing packets to be processed.
        :param X: The matrix that determines which packets' messages are concatenated to generate each HMAC.
        :param Y: The matrix that determines where each HMAC is placed within the packets' MAC fields.
        """
        page.fill_missing_packets()
        messages = np.array([packet.message for packet in page.packets], dtype=object)
        
        # Efficiently concatenate messages using matrix multiplication
        concatenated_messages = np.dot(self.XT, messages)

        # Calculate HMACs for each concatenated message
        tags = np.vectorize(self.calculate_hmac, otypes=[object])(concatenated_messages)

        # Place the tags in the appropriate packets based on the Y matrix using matrix multiplication
        macs = np.dot(self.Y, tags)

        # Use map to avoid explicit loops for updating packet MACs
        list(map(lambda p, m: setattr(p, 'mac', m), page.packets, macs))

class MACChecker:
    def __init__(self,X:np.ndarray, Y:np.ndarray, secret_key: bytes = b'key' , digestmod:str = 'sha256', offset: float = 0):
        
        self.secret_key = secret_key
        self.digestmod = digestmod
        self.X = X
        self.XT = np.array(X, dtype=int).T
        self.Y = np.array(Y, dtype=int)
        self.offset = offset
        


    def calculate_hmac(self, message: bytes) -> bytes:
        """
        Calculate the HMAC of a given message.

        :param message: The message for which the HMAC is computed.
        :return: The computed HMAC.
        """
        return hmac.new(self.secret_key, message, digestmod= self.digestmod).digest()

    def check_page(self, page: Page) -> tuple:
        """
        Check the MACs in the page based on matrices X and Y.

        :param page: The page containing packets to be checked.
        :return: True if all MACs are correct, False otherwise.
        """
        page.fill_missing_packets()
        # Extract all packet messages as a numpy array
        messages = np.array([packet.message for packet in page.packets], dtype=object)
        # Vectorized HMAC generation and comparison
        concatenated_messages = np.dot(self.XT, messages)
        expected_tags = np.array([self.calculate_hmac(msg) for msg in concatenated_messages], dtype=object)
        expected_macs = np.dot(self.Y, expected_tags)
        # Vectorized comparison of actual MACs and expected MACs
        actual_macs = np.array([packet.mac for packet in page.packets], dtype=object)
        verification_results = np.equal(expected_macs, actual_macs)
        # Count the number of times each packet was verified
        verified_tags = np.dot(verification_results.astype(int), self.Y)
        verification_counts = np.dot(self.X, verified_tags)
        

        modified_messages = np.where(verification_counts > 0,
                                     messages,
                                     b'\x00')
        concatenated_message = b''.join(modified_messages)

        current_time = time.time()

        latency = current_time  - np.fromiter((packet.timestamp for packet in page.packets[verification_counts > 0] if packet.timestamp !=0), dtype=float)
        # latency  = np.array([current_time - packet.timestamp for i in range(len(page.packets)) for packet in page.packets if packet.timestamp !=0])
        del page.packets
        return concatenated_message, verification_counts, latency




# Example usage
if __name__ == "__main__":
    # Example Page setup with 3 packets
    page = Page(page_size=3)
    packet1 = Packet(SN=0, message=b"Message1", mac=b"")
    packet2 = Packet(SN=1, message=b"Message2", mac=b"")
    # packet3 = Packet(SN=2, message=b"Message3", mac=b"")
    page.add_packet(packet1)
    page.add_packet(packet2)
    # page.add_packet(packet3)

    

    # Example matrices
    X = np.array([[1, 1, 0],  # Packet 1 contributes to both t1 and t2
                  [0, 1, 0],  # Packet 2 contributes only to t2 
                  [1, 0, 1]], # Packet 3 contributes only to t1 
                 dtype=int)

    Y = np.array([[0, 1, 0],  # t2 will be placed in Packet 1's MAC
                  [1, 0, 0],  # t1 will be placed in Packet 2's MAC
                  [0, 0, 1]], # Packet 3 will not have a MAC
                 dtype=int)
                                                # tag 0                                         # tag 1                                  # tag 2 
    # concatenated_messages = [ page.packets[0].message + page.packets[1].message, page.packets[0].message + page.packets[2].message, page.packets[2].message]

    # macs = [hmac.new(b"secret_key", message, digestmod='sha256').digest() for message in concatenated_messages]
    # Initialize HMACCalculator with a secret key
    hmac_calculator = MACGenerator(X=X, Y=Y, secret_key=b"secret_key")
    # Process the page
    hmac_calculator.process_page(page)
    # Print out the MACs of the packets to verify
    for i, packet in enumerate(page.packets):
        print(f"Packet {i} MAC: {packet.mac.hex()}")
    
    # if all([packet.mac == mac for packet, mac in zip(page.packets, macs)]):
    #     print("MACs are correct!")

    # Initialize HMACChecker with the same secret key
    hmac_checker = MACChecker(X=X, Y=Y, secret_key=b"secret_key", offset=0) 
    # Check the page
    
    print(hmac_checker.check_page(page))
    del page
    # Modify a packet to introduce an error

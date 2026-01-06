import sys
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
sys.path.insert(0, SRC_DIR)
from Capture_packet.capture import start_capture

if __name__ == "__main__":
    start_capture()

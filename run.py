import os
import sys

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

try:
    from AISCRIPTS.generate_sample_dataset import generate_dataset
except ImportError:
    generate_dataset = None

import uvicorn


def print_banner():
    banner = r"""
================================================================================
  _______ _____             _____ ______ ____  _   _ 
 |__   __|  __ \     /\    / ____|  ____/ __ \| \ | |
    | |  | |__) |   /  \  | |    | |__ | |  | |  \| |
    | |  |  _  /   / /\ \ | |    |  __|| |  | | . ` |
    | |  | | \ \  / ____ \| |____| |___| |__| | |\  |
    |_|  |_|  \_\/_/    \_/_____|______\____/|_| \_|
                                                     
  AI-Powered Email Threat Detection, Hop-by-Hop GeoLocation
  & Zero-Retention Forensic Sentinel Platform [PS #26106]
================================================================================
  * Host URL       : http://127.0.0.1:8000
  * Documentation  : http://127.0.0.1:8000/docs
  * Privacy Policy : http://127.0.0.1:8000/privacy (Zero-Disk Retention)
  * Terms & Legal  : http://127.0.0.1:8000/terms
  * Extension      : D:\TraceON\extension (Chrome / Edge / Brave)
================================================================================
"""
    print(banner)


def main():
    print_banner()

    sample_dir = os.path.join(BASE_DIR, "samples")
    if generate_dataset and (not os.path.exists(sample_dir) or len(os.listdir(sample_dir)) == 0):
        print("[*] Generating forensic sample dataset in samples/...")
        generate_dataset(sample_dir)

    print("[+] System verified. Starting TRACEON SOC Server...")
    print("[*] Press CTRL+C to stop the server.\n")

    uvicorn.run("web.app:app", host="127.0.0.1", port=8000, reload=False, log_level="info")


if __name__ == "__main__":
    main()

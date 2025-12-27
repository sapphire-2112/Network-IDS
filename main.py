## Main file for the application
## This file initializes and runs the main application logic.
## It combines various modules and handles user interactions.
## Work flow will be like this:
## 1. Import necessary modules
## 2. Initialize application settings
## 3. Start packet capture
## 4. Packets are parsed
## 5. Parsed packets are tested by detection modules
## 6. Alerts are generated if attacks are detected

from capture.sniffer import start_sniffer

def main():
    start_sniffer()

if __name__ == "__main__":
    main()

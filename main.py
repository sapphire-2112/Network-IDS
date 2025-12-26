## Main file for the application
## This file initializes and runs the main application logic.
## It combines various modules and handles user interactions.
## Work flow will be like this:
## 1. Import necessary modules
## 2. Initialize application settings
## 3. Then it captures user input
## 4. Process the input using defined functions
## 5. like parsers and then tests.
## 6. Test the processed input
## 7. Log the results
## 8. Finally, it will display the output to the user.
## Main file for the application
## Entry point of the program

from capture.sniffer import capture_packet

def main():
    capture_packet()

if __name__ == "__main__":
    main()

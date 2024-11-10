#!/usr/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# All rights reserved.

import os
import sys
import json
import datetime

# Set log file location based on operating system
if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

# Define command constants
ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

# Define status codes
OS_SUCCESS = 0
OS_INVALID = -1

# Define the message class
class message:
    def __init__(self):
        self.alert = ""
        self.command = 0

# Function to write a message to the debug log file
def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name + ": " + msg + "\n")

# Function to setup and check message validity
def setup_and_check_message(argv):

    # Get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    # Try parsing the JSON data
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    # Set alert and determine command
    message.alert = data
    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return message

# Function to send keys and validate the response
def send_keys_and_check_message(argv, keys):

    # Build and send message with keys
    keys_msg = json.dumps({
        "version": 1,
        "origin": {"name": argv[0], "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": keys}
    })

    # Write the message to log
    write_debug_file(argv[0], keys_msg)

    # Output the message and flush stdout
    print(keys_msg)
    sys.stdout.flush()

    # Read the response to the previous message
    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    # Attempt to parse the JSON response
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return message

    # Determine action based on response command
    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret

# Main function
def main(argv):

    write_debug_file(argv[0], "Started")

    # Validate JSON input and retrieve command
    msg = setup_and_check_message(argv)

    # Exit if command is invalid
    if msg.command < 0:
        sys.exit(OS_INVALID)

    # Process ADD_COMMAND
    if msg.command == ADD_COMMAND:
        alert = msg.alert["parameters"]["alert"]
        keys = [alert["rule"]["id"]]
        action = send_keys_and_check_message(argv, keys)

        # Abort execution if necessary
        if action != CONTINUE_COMMAND:
            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file(argv[0], "Invalid command")
                sys.exit(OS_INVALID)

        # Attempt to remove the threat file
        try:
            file_path = msg.alert["parameters"]["alert"]["data"]["virustotal"]["source"]["file"]
            if os.path.exists(file_path):
                os.remove(file_path)
            write_debug_file(argv[0], json.dumps(msg.alert) + " Successfully removed threat")
        except OSError as error:
            write_debug_file(argv[0], json.dumps(msg.alert) + " Error removing threat")

    else:
        # Log invalid command if not ADD_COMMAND
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")

    # Exit with success status
    sys.exit(OS_SUCCESS)

# Entry point
if __name__ == "__main__":
    main(sys.argv)

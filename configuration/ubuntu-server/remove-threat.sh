#!/bin/bash

# Set the LOCAL variable to the directory of the script and change to it
LOCAL=`dirname $0`
cd $LOCAL
cd ../

# Set PWD variable to the current directory
PWD=`pwd`

# Read JSON input from stdin
read INPUT_JSON
# Extract the filename and command from the JSON input
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
# Define the log file path
LOG_FILE="${PWD}/../logs/active-responses.log"

#------------------------ Analyze command -------------------------#
if [ ${COMMAND} = "add" ]; then
  # Send control message to execd for verification
  printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'

  # Read response from execd
  read RESPONSE
  # Extract command from the response
  COMMAND2=$(echo $RESPONSE | jq -r .command)
  # If the command is not "continue", log and exit
  if [ ${COMMAND2} != "continue" ]; then
    echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Remove threat active response aborted" >> ${LOG_FILE}
    exit 0
  fi
fi

# Attempt to remove the file specified in FILENAME
rm -f $FILENAME
# Check if file removal was successful
if [ $? -eq 0 ]; then
  # Log success message if file was removed
  echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Successfully removed threat" >> ${LOG_FILE}
else
  # Log error message if file removal failed
  echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Error removing threat" >> ${LOG_FILE}
fi

# Exit the script
exit 0

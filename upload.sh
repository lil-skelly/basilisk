#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

# Define color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Define constants
TARGET_DIR="/home/skelly/vagrant_boxes/ubuntu18/"
SOURCE_DIR="/home/skelly/projects/basilisk/src"
REMOTE_USER="vagrant"
REMOTE_HOST="127.0.0.1"
REMOTE_PORT="2222"
REMOTE_DIR="/home/vagrant/basilisk/src"

# Save the current directory
CWD=$(pwd)

# Change to the target directory
cd "$TARGET_DIR" || { echo -e "${RED}Error: Failed to change directory to $TARGET_DIR. Exiting.${NC}"; exit 1; }

# Check the status of the Vagrant box
if ! vagrant_status=$(vagrant status | grep 'default' | awk '{print $2}'); then
    echo -e "${RED}Error: Failed to check Vagrant status. Exiting.${NC}"
    exit 1
fi

if [ "$vagrant_status" != "running" ]; then
    echo -e "${RED}Error: Vagrant box is not running. Attempting to start it...${NC}"
    if ! vagrant up; then
        echo -e "${RED}Error: Failed to start Vagrant box. Exiting.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}==> Vagrant box is up and running.${NC}"
fi

# Return to the original directory
cd "$CWD" || { echo -e "${RED}Error: Failed to return to the original directory ($CWD). Exiting.${NC}"; exit 1; }

# Upload source code to the VM
echo -e "${BLUE}--> Uploading source code to VM...${NC}"
if ! scp -P "$REMOTE_PORT" -r "$SOURCE_DIR" "$REMOTE_USER@$REMOTE_HOST:basilisk"; then
    echo -e "${RED}Error: Failed to upload source code.${NC}"
    exit 1
fi
echo -e "${GREEN}==> Source code uploaded successfully.${NC}"

# Compile source code in the Vagrant box
echo -e "${BLUE}Compiling source code in Vagrant box...${NC}"
if ! ssh -p "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST" << 'EOF'
    cd /home/vagrant/basilisk/src || { echo -e "${RED}Error: Failed to change directory to src. Exiting.${NC}"; exit 1; }
    echo "Running make..."
    make || { echo -e "${RED}Error: Compilation failed.${NC}"; exit 1; }
    echo -e "${GREEN}==> Compilation successful.${NC}"
EOF
then
    echo -e "${RED}Error: SSH command failed.${NC}"
    exit 1
fi

echo -e "${GREEN}==> Compilation completed successfully. Happy Hacking X)${NC}"
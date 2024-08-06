#!/usr/bin/bash 
cd /home/skelly/vagrant_boxes/ubuntu18/ || { echo "Failed to change directory. Exiting."; exit 1; }

# Check the status of the Vagrant box
VAGRANT_STATUS=$(vagrant status | grep 'default' | awk '{print $2}')
if [ "$VAGRANT_STATUS" != "running" ]; then
    echo "Error: Vagrant box is not running. Please start the Vagrant box and try again."
    exit 1
fi
echo "=> Vagrant Box is up and running"

# Return to the original directory
cd "$CWD" || { echo "Failed to return to the original directory. Exiting."; exit 1; }

echo "-> Uploading source code to VM"
scp -P 2222 -r "/home/skelly/projects/basilisk/src" "vagrant@127.0.0.1:src"
if [ "$?" -eq 0 ]; then
    echo "==> Uploading complete. Happy Hacking X) <=="
else
    echo "Error: Failed to upload source code."
    exit 1
fi

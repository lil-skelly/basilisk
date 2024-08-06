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
scp -P 2222 -r "/home/skelly/projects/basilisk/src" "vagrant@127.0.0.1:basilisk"
if [ "$?" -eq 0 ]; then
    echo "==> Uploading complete <=="
else
    echo "Error: Failed to upload source code."
    exit 1
fi

echo "-> Compiling source code in Vagrant box"
ssh -p 2222 vagrant@127.0.0.1 << 'EOF'
    cd /home/vagrant/basilisk/src || { echo "Failed to change directory to src. Exiting."; exit 1; }
    echo "Running make..."
    make
    if [ "$?" -ne 0 ]; then
        echo "Error: Compilation failed."
        exit 1
    fi
EOF

# Check if SSH command was successful
if [ "$?" -eq 0 ]; then
    echo "==> Compilation completed successfully <=="
    echo "Happy Hacking X)"
else
    echo "Error: SSH command failed."
    exit 1
fi

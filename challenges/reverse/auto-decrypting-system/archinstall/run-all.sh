#!/bin/bash

IP_ADDRESS="192.168.1.147"

ssh-keygen -R $IP_ADDRESS
scp user_configuration.json user_credentials.json fscrypt.sh flag*.txt launch_codes.txt issue.txt root@$IP_ADDRESS:
ssh -t root@$IP_ADDRESS "sed -i -E 's/(kernels=config.kernels,)/\0base_packages=[\"base\",\"linux\"]/' /usr/lib/python3.13/site-packages/archinstall/scripts/guided.py && archinstall --config user_configuration.json --creds user_credentials.json --silent && ./fscrypt.sh && shutdown now"

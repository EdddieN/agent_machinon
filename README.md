

# Installing Agent-Machinon on your Raspbian

### This project is work in progress

***Until public release this application and the attached documentation is strictly for Logic Energy Ltd. personnel only!!***

This Python app will run in background on your Raspberry Pi and will listen the Re:Machinon portal's remote link commands.

## Requirements

* Raspberry Pi 3 Model B+
* Linux OS (Raspbian recommended)

- Python 3.5+ with the following libraries:
	- paho-mqtt (https://pypi.org/project/paho-mqtt/)
	- python-dotenv (https://github.com/theskumar/python-dotenv)
- Autossh
- Git

***This app is designed for Linux OS only.***

### Regarding the packet manager

This guide suggests to install the software on a fresh installation of **Raspbian**, therefore we'll use *apt* as packet manager. 

In case you have an already working Raspbian or another Linux OS distribution installed you may find some packages are already installed.
Also you may have to use a different packet manager, as *yum*, *rpm*, etc... 

Keep that in mind and modify the package install command lines accordingly to your OS's packet manager.

Whenever apt asks for confirmation, just answer Yes.

## Updating your system

First ensure the apt repository is up to date:
```
sudo apt-get update
```

If possible (and safe) upgrade your Raspbian installation:
```
sudo apt-get dist-upgrade
sudo apt-get clean
sudo reboot
```

## Install Python 3.5+ and required libraries

Change the package versions accordingly to your Raspbian repository available version.

```
sudo apt-get install python3 python3-pip
sudo -H pip3 install paho-mqtt python-dotenv
```

## Install autossh

This app is required to open the SSH tunnels and keep them opened without timeouts.

```
sudo apt-get install autossh
```

## Install GIT

```
sudo apt-get install git
```

## Download the current agent_machinon app from GitHub

As the repository is private, you'll be asked for your GitHub user and password, that's okay.

```
cd /opt
sudo git clone https://github.com/EdddieN/agent_machinon.git
sudo chown pi:pi -R agent_machinon
cd agent_machinon
```

## Installing SSH Re:Machinon server  key and signature
***LOGIC ENERGY LTD. EMPLOYEES ONLY***

A public key is needed to let the app open the link with the  Re:Machinon server.

***WIP*** Ed, all this will be downloaded / installed internally or generated in the Pi and installed on the server somehow when automating the installation, at the moment I'll send the key to you by email. Until we have this installed in a safer server this is on hold.

#### Copy the contents of the key I've sent you in this file and set the  right permissions

```
sudo nano /etc/ssh/remachinon_test_aws.pem 
sudo chmod 400 /etc/ssh/remachinon_test_aws.pem
```
#### Preload the Re:Machinon server key in the known_hosts file

```
ssh-keyscan re.machinon.com | sudo tee -a /etc/ssh/ssh_known_hosts
```

***IMPORTANT*** Keep in mind now we're changing of servers so we will have to edit this file in the future manually to update records.


## Setup agent_machinon
***LOGIC ENERGY LTD. EMPLOYEES ONLY***

The app provides a sample .env.example file as template but we will create a new .env file configured to use the AWS re.machinon.com site.

```
sudo nano .env
```

Put on it the following contents, save and exit:

```
# MQTT Broker definitions  
MQTT_SERVER_HOST=dev.machinon.com  
MQTT_SERVER_PORT=1883  
MQTT_SERVER_PORT_SSL=8883  
MQTT_SERVER_USE_SSL=True  
MQTT_SERVER_USERNAME=machinon  
MQTT_SERVER_PASSWORD=<sent by email>  
MQTT_CERTS_PATH=/etc/ssl/certs  
  
# MQTT client and topic definitions  
MQTT_CLIENT_ID_PREFIX=machinon2_  
MQTT_TOPIC_PREFIX_REMOTECONNECT=remote  
  
# SSH Tunnel details  
SSH_HOSTNAME=re.machinon.com  
SSH_USERNAME=ec2-user
SSH_KEY_FILE=/etc/ssh/remachinon_test_aws.pem  
  
# Remachinon API base URL  
REMACHINON_API_URL=http://${SSH_HOSTNAME}/api/v1  
  
# script user must have write access to this file or folder  
LOG_FILE=tunnel-agent.log
```

## Installing agent_machinon as service

You have to create a new service and put some code on it
```
sudo nano /etc/systemd/system/agent_machinon.service
```

Write in the service file que following code, save and exit

```
# Service for Logic Energy Re:Machinon Tunnel Agent  
[Unit]  
       Description=agent_machinon_service  
[Service]  
       User=pi  
       Group=users  
       ExecStart=/usr/bin/python3 /opt/agent_machinon/tunnel-agent.py
       WorkingDirectory=/opt/agent_machinon/ 
       Restart=always  
       RestartSec=20  
       #StandardOutput=null  
[Install]  
       WantedBy=multi-user.target
```

Register and start the new service

```
sudo systemctl daemon-reload  
sudo systemctl enable agent_machinon.service  
sudo systemctl start agent_machinon.service
```

## Getting your device's MUID

Let's identify your Raspberry MUID (the ethernet MAC address in use), which you'll need to register the device in Re:Machinon. 

```
cat tunnel-agent.log | grep "remote"
```

If the agent is running correctly, you'll get a message like this
```
MQTT Subscribed to 'remote/B827EB8B4A89' QOS=(0,)
```
Copy the hexadecimal value **after** `remote/` , that's the device's MUID!

If the tunnel-agent.log does not exist please re-check all the previous steps, as something's not working.

## Debugging possible errors

In case something goes wrong, you can always run agent_machinon directly from command line:

```
cd /opt/agent_machinon
env python3 tunnel-agent.py
```

If the app is running properly you'll see the app connects to MQTT server and waits for incoming commands. Otherwise it will drop some Python errors.

## Monitoring Agent-Machinon

You can also check Agent Machinon while the service is running by watching the log file. 
This command will continuously show the log contents until Ctrl+C is pressed:

```
cd /opt/agent_machinon
tail -f tunnel-agent.py
```

## Now what?

The next step would be installing web_machinon in your Raspberry, that will create a web service with all the code needed to confirm and authenticate the remote link once is established, as well as forward to any other local service you may have in your Raspberry. By default this service is a Domoticz installation running on 8080 port.

https://github.com/EdddieN/web_machinon


> Written with [StackEdit](https://stackedit.io/).
<!--stackedit_data:
eyJoaXN0b3J5IjpbOTA2NTA2MjA0LDExNDQ0NDI3MTgsNjM3MT
AwMjY3XX0=
-->
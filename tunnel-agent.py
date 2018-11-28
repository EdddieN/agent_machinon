#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 Agent Machinon v1.1 for Machinon2

 (c) Logic Energy 2018
 MGC 2018-07-27
 JJG 2018-11-22

 Monitors MQTT topics for a command to open a SSH tunnel to Remachinon server.

 Uses Paho-MQTT library

 Expects an MQTT message with JSON payload in the form:
    {"tunnel":"open", "port":"50000", "tunnel_uuid":"12345678-1234-4000-8234-1234567890AB"}
    or
    {"tunnel":"close"}

    2018-11-22 Receiving "device_id" in the JSON is now deprecated, server sends "tunnel_uuid" UUID4 instead

"""

import os
import sys  # for argv
import argparse  # easy argv parsing
import socket
import paho.mqtt.client as pahomqtt
import time
import logging.handlers
import atexit  # for pre-exit cleanup
import urllib.request  # for HTTP functions (GET/POST request and response handling)
import urllib.error
import fcntl
import struct
import binascii
import json
import subprocess
import re

# Loading the .env configuration variables
from dotenv import load_dotenv

load_dotenv()

# MQTT Broker definitions
MQTT_SERVER_HOST = os.getenv('MQTT_SERVER_HOST')
MQTT_SERVER_PORT = int(os.getenv('MQTT_SERVER_PORT'))
MQTT_SERVER_PORT_SSL = int(os.getenv('MQTT_SERVER_PORT_SSL'))
MQTT_SERVER_USE_SSL = bool(os.getenv('MQTT_SERVER_USE_SSL'))
MQTT_SERVER_USERNAME = os.getenv('MQTT_SERVER_USERNAME')
MQTT_SERVER_PASSWORD = os.getenv('MQTT_SERVER_PASSWORD')
MQTT_CERTS_PATH = os.getenv('MQTT_CERTS_PATH')

# MQTT client and topic definitions
MQTT_CLIENT_ID_PREFIX = os.getenv('MQTT_CLIENT_ID_PREFIX')
MQTT_TOPIC_PREFIX_REMOTECONNECT = os.getenv('MQTT_TOPIC_PREFIX_REMOTECONNECT')

# Misc general definitions
PROG_NAME = "Machinon Tunnel Agent"
PROG_VERSION = "1.1.0"  # program version as string

LOG_FILE = os.getenv('LOG_FILE')  # script user must have write access to this file or folder
LOG_FILE_MAX_SIZE = 10 * 1024 * 1024

# SSH and SSL definitions
SSH_USERNAME = os.getenv('SSH_USERNAME') + '@' + os.getenv('SSH_HOSTNAME')
SSH_KEY_FILE = os.getenv('SSH_KEY_FILE')

# Remote ports the autossh will connect to on demand
MIN_REMOTE_PORT = 10000
MAX_REMOTE_PORT = 65535

# Port where the local nginx/apache serves the remachinon_web app
DEFAULT_LOCAL_PORT = 80

# Program allows to run with a custom port between 80 and 65535
MIN_LOCAL_PORT = 80
MAX_LOCAL_PORT = 65535

# Re:Machinon API URL
REMACHINON_API_URL = os.getenv('REMACHINON_API_URL')


# Validates uuid received in the JSON
def valid_uuid(uuid):
    regex = re.compile('^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
    match = regex.match(uuid)
    return bool(match)


# Get MAC address for specified network interface
# Python3 version from https://stackoverflow.com/questions/28927958/python-get-mac-address/34922412#34922412
def get_mac_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(ifname[:15], 'utf-8')))
    # Classic colon-delimited MAC
    # return ''.join(l + ':' * (n % 2 == 1) for n, l in enumerate(binascii.hexlify(info[18:24]).decode('utf-8')))[:-1]
    # 12-digit hex only
    return ''.join(binascii.hexlify(info[18:24]).decode('utf-8')).upper()


def on_connect(client, userdata, flags, result):
    # logger.info("MQTT Connection result: " + pahomqtt.connack_string(result))
    if result == 0:
        # got connected OK
        logger.info("MQTT Connected OK.")
        # subscribe here, so that we always renew subs after reconnecting
        paho_client.subscribe(MQTT_TOPIC_PREFIX_REMOTECONNECT + "/" + mac_address)
    else:
        logger.warning("MQTT Connect failed: " + pahomqtt.connack_string(result))


def on_message(client, userdata, message):
    global tunnel_do_open
    global tunnel_do_close
    global remote_port_num
    global tunnel_uuid
    global tunnel_token

    message_string = message.payload.decode("utf-8")
    logger.debug("MQTT_msg: Topic='" + message.topic + "'   Payload='" + message_string + "'")

    if message.topic != (MQTT_TOPIC_PREFIX_REMOTECONNECT + "/" + mac_address):
        logger.debug("Invalid topic!")
        return

    try:
        message_dict = json.loads(message_string)
    except json.JSONDecodeError as exc:
        logger.debug("MQTT JSON decode error: " + str(exc))
    else:
        logger.debug("MQTT JSON decoded: " + str(message_dict))
        if "tunnel" in message_dict and message_dict["tunnel"] == "open":
            if "port" in message_dict:
                remote_port_num = 0
                try:
                    remote_port_num = int(message_dict["port"])
                except:
                    logger.info("MQTT JSON: Bad port value")
                else:
                    if remote_port_num >= MIN_REMOTE_PORT and remote_port_num <= MAX_REMOTE_PORT:
                        tunnel_uuid = ""
                        if "uuid" in message_dict:
                            try:
                                tunnel_uuid = str(message_dict["uuid"])
                            except:
                                logger.info("MQTT JSON: Bad tunnel_uuid value")
                            else:
                                if valid_uuid(tunnel_uuid):
                                    logger.info("MQTT got tunnel open command with port=" + str(
                                        remote_port_num) + " tunnel_uuid=" + str(tunnel_uuid))
                                    # trigger r-ssh open
                                    tunnel_do_open = True
                                    tunnel_token = ""
                                    if "access_token" in message_dict:
                                        try:
                                            tunnel_token = str(message_dict["access_token"])
                                        except:
                                            logger.info("MQTT JSON: Bad access_token value")
                                        else:
                                            logger.info("MQTT JSON: All okay!")
                                else:
                                    logger.info("MQTT JSON: Bad tunnel_uuid value")
                        else:
                            logger.info("MQTT JSON: tunnel_uuid not specified. Confirmation will be skipped.")
                            # trigger r-ssh open
                            tunnel_do_open = False
                    else:
                        logger.info("MQTT JSON: Bad port value")
            else:
                logger.debug("MQTT JSON: port number not specified!")
        elif "tunnel" in message_dict and message_dict["tunnel"] == "close":
            # terminate r-ssh session
            logger.info("MQTT got tunnel close command")
            tunnel_do_close = True
        else:
            logger.debug("MQTT JSON: tunnel command not found.")


def on_disconnect(client, userdata, result):
    if result != 0:
        # result != 0 if it's an error/unexpected disconnection.
        logger.warning("MQTT disconnected unexpectedly")
    else:
        # result=0 if this is in response to an intentional disconnect() call.
        logger.info("MQTT Disconnected")


def on_subscribe(client, userdata, mid, granted_qos):
    logger.info(
        "MQTT Subscribed to '" + MQTT_TOPIC_PREFIX_REMOTECONNECT + "/" + mac_address + "' QOS=" + str(granted_qos))


def cleanup():
    logger.info("Machinon Tunnel Agent exit")
    # disconnect cleanly in case we're still connected
    paho_client.disconnect()
    time.sleep(0.5)  # kludge to allow time for disconnect to be sent and callback triggered

    # close any existing tunnels
    try:
        # TODO use more secure/graceful way to stop autossh
        ssh_output = subprocess.check_output("sudo killall autossh", shell=True)
        if not ssh_output:
            logger.info("Tunnel closed")
    except subprocess.CalledProcessError as e:
        # logger.info("Tunnel close failed or no existing tunnel: " + str(e))
        logger.info("Tunnel close failed or no existing tunnel")


def main(argv):
    global paho_client
    global mac_address
    global client_id
    global tunnel_state_actual
    global tunnel_do_open
    global tunnel_do_close
    global remote_port_num
    global tunnel_uuid
    global tunnel_token
    global local_port_num

    # ssh_process = None
    # ssh_output = ""

    atexit.register(cleanup)

    mac_address = 'B827EB8B4A89'  # get_mac_address('eth0')
    client_id = MQTT_CLIENT_ID_PREFIX + mac_address
    logger.info(PROG_NAME + " version " + PROG_VERSION + " started. MQTT ClientID = " + client_id)
    logger.info("Machinon MAC: " + mac_address)
    logger.info("Local server port: " + str(local_port_num))
    # sys.exit(0)

    paho_client = pahomqtt.Client(client_id, True, None, pahomqtt.MQTTv311, "tcp")
    paho_client.on_connect = on_connect
    paho_client.on_subscribe = on_subscribe
    paho_client.on_message = on_message
    paho_client.on_disconnect = on_disconnect
    paho_client.username_pw_set(MQTT_SERVER_USERNAME, MQTT_SERVER_PASSWORD)
    # Misc PahoMQTT options/parameters
    # paho_client.max_inflight_messages_set(50)
    # TODO set up SSL if required
    if MQTT_SERVER_USE_SSL:
        paho_client.tls_set()  # use default system certs path/files

    try:
        if MQTT_SERVER_USE_SSL:
            paho_client.connect(MQTT_SERVER_HOST, MQTT_SERVER_PORT_SSL, 60, "")
        else:
            paho_client.connect(MQTT_SERVER_HOST, MQTT_SERVER_PORT, 60, "")
        # Steve's Internet Guide recommends starting the loop AFTER calling connect().
        # See http://www.steves-internet-guide.com/loop-python-mqtt-client/
        paho_client.loop_start()
    except:
        logger.info("MQTT Connect failed!")
        sys.exit(1)

    while True:
        # loop forever, waiting for MQTT messages and starting/stopping tunnel as required
        time.sleep(0.2)  # is there a better way to yield control to system?

        # check to see if tunnel  open or close has been requested
        if tunnel_do_open:
            # try to open the tunnel
            tunnel_do_open = False
            logger.info("Attempting to open tunnel...")

            # check for and kill any existing autossh process
            try:
                full_ssh_command = "pgrep -x autossh"
                ssh_output = subprocess.check_output(full_ssh_command, shell=True)
                if not ssh_output:
                    logger.info("No existing tunnel")
                else:
                    ssh_output = subprocess.check_output("sudo killall autossh", shell=True)
                    if not ssh_output:
                        logger.info("Existing tunnel closed")
            except subprocess.CalledProcessError as e:
                # logger.info("Tunnel close failed or no existing tunnel: " + str(e))
                logger.info("Tunnel close failed or no existing tunnel")

            # try to open a new tunnel
            try:
                # TODO get local HTTP server port from system/service info instead of hard coding.
                # autossh command line options:
                #   "-f" = run autossh in background
                #   "-i <key_file>" = use the specified private key (identity)
                #   "-R <remote_port>:localhost:<local_port>" = open a tunnel between local_port and remote_port
                #   "-N" = do not execute any remote command (only use the connection for forwarding)
                full_ssh_command = "sudo autossh -f -N -i %s -R %d:localhost:%d %s" % (
                    SSH_KEY_FILE, remote_port_num, local_port_num, SSH_USERNAME)
                ssh_output = subprocess.check_output(full_ssh_command, shell=True)
                if not ssh_output:
                    logger.info("Tunnel opened")
            except subprocess.CalledProcessError as e:
                logger.info("Tunnel open failed: " + str(e))
            else:
                # tunnel opened, so call LE API to confirm that we are online
                if valid_uuid(tunnel_uuid) and tunnel_token:
                    headers = {
                        'Authorization': 'Bearer ' + tunnel_token,
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                    }
                    # This line calls the new Remachinon App (Laravel) confirmation endpoint
                    confirm_url = REMACHINON_API_URL + '/tunnels/' + str(tunnel_uuid) + '/confirm'
                    logger.debug('Calling : ' + confirm_url)
                    req = urllib.request.Request(confirm_url, None, headers, method='PUT')
                    try:
                        response = urllib.request.urlopen(req)
                        # response_page = response.read()
                    except urllib.error.URLError as e:
                        logger.info("Confirmation API GET failed: " + str(e))
                    else:
                        logger.info("Confirmation API call OK")
                else:
                    logger.info("Confirmation API call skipped")

        if tunnel_do_close:
            # try to close the tunnel
            tunnel_do_close = False
            logger.info("Attempting to close tunnel...")
            # ssh_process.terminate()
            try:
                # TODO use more secure/graceful way to stop autossh
                ssh_output = subprocess.check_output("sudo killall autossh", shell=True)
                if not ssh_output:
                    logger.info("Tunnel closed")
            except subprocess.CalledProcessError as e:
                logger.info("Tunnel close failed or no existing tunnel")
                # logger.info("Tunnel close failed or no existing tunnel: " + str(e))


rootlogger = logging.getLogger()
rootlogger.setLevel(logging.DEBUG)
# use UTC/GMT for log timestamps
logging.Formatter.converter = time.gmtime
# set a format suitable for log files
formatter = logging.Formatter('%(asctime)-24s %(threadName)-12s %(levelname)-8s: %(message)s')

# Add a rotating log file handler to the logger
logfilehandler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=LOG_FILE_MAX_SIZE, backupCount=10)
logfilehandler.setFormatter(formatter)
logfilehandler.setLevel(logging.DEBUG)
rootlogger.addHandler(logfilehandler)

# Add a Linux syslog handler
# sysloghandler = logging.handlers.SysLogHandler(

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
# console.setLevel(logging.DEBUG)
console.setFormatter(formatter)
rootlogger.addHandler(console)

logger = logging.getLogger(__name__)

# Global vars for ClientID, MAC address etc
client_id = ""
mac_address = ""
tunnel_state_actual = False
tunnel_do_open = False
tunnel_do_close = False
remote_port_num = 0
local_port_num = DEFAULT_LOCAL_PORT
tunnel_uuid = ""

# Global objects for the MQTT client
paho_client = None

parser = argparse.ArgumentParser(description=PROG_NAME + " " + PROG_VERSION)
parser.add_argument('-p', '--port', help='Local port to forward to, e.g. "-p 80" for local httpd (default is 80)',
                    required=False, type=int)
parser.add_argument('-v', '--version', help='Print version info', action='version',
                    version=PROG_NAME + " version " + PROG_VERSION)
args = parser.parse_args()
if args.port:
    if MIN_LOCAL_PORT <= args.port <= MAX_LOCAL_PORT:
        local_port_num = args.port

if __name__ == '__main__':
    main(sys.argv[1:])

# end of code

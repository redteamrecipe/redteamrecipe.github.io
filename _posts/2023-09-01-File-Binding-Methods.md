---
layout: post
title:  "File Binding Methods(RTC0015)"
author: redteamrecipe
categories: [ tutorial ]
tags: [red, blue]
image: assets/images/27.png
description: "File Binding Methods"
featured: true
hidden: true
rating: 4.5
---





### Create an ISO Image:

- **Method:** Create an ISO image that includes both the EXE and other files.


**Method 1: Using Bash (Linux)**

You can create an ISO image using the `genisoimage` tool, which is commonly available on Linux systems. If it's not installed, you can install it on Debian/Ubuntu with `apt-get` or on Red Hat/CentOS with `yum`. Here's a Bash script to create an ISO image:


```
#!/bin/bash

# Define your source directory containing the files
source_dir="/path/to/source"

# Define the output ISO file name
iso_filename="output.iso"

# Create the ISO image
genisoimage -o "$iso_filename" -r -J "$source_dir"

echo "ISO image created: $iso_filename"
```

**Method 2: Using Python (Cross-Platform)**


```
import os
from pyisomaker import PyIsoMaker

# Define your source directory containing the files
source_dir = "/path/to/source"

# Define the output ISO file name
iso_filename = "output.iso"

# Create the ISO image
with PyIsoMaker(source_dir, iso_filename) as iso:
    iso.generate()

print(f"ISO image created: {iso_filename}")
```


### Embed in a Windows Installer (MSI)

- **Method:** Package files with a Windows Installer (MSI) package. 


Create a WiX script (e.g., `package_files.wxs`) with the following content:


```
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*" Name="My Application" Language="1033" Version="1.0.0" Manufacturer="Your Company" UpgradeCode="PUT-GUID-HERE">
        <Package InstallerVersion="200" Compressed="yes" />

        <Media Id="1" Cabinet="media1.cab" EmbedCab="yes" />

        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="ProgramFilesFolder">
                <Directory Id="INSTALLFOLDER" Name="My Application">
                    <Component Id="MainExecutable" Guid="PUT-GUID-HERE">
                        <File Id="MyAppEXE" Source="your_program.exe" KeyPath="yes" />
                    </Component>
                    <Component Id="AdditionalFiles" Guid="PUT-GUID-HERE">
                        <File Id="File1" Source="file1.txt" />
                        <File Id="File2" Source="file2.txt" />
                    </Component>
                </Directory>
            </Directory>
        </Directory>

        <Feature Id="MainFeature" Title="Main Feature" Level="1">
            <ComponentRef Id="MainExecutable" />
            <ComponentRef Id="AdditionalFiles" />
        </Feature>
    </Product>
</Wix>
```


In this script:

- Replace `"your_program.exe"`, `"file1.txt"`, and `"file2.txt"` with the paths to the files you want to package.
- Customize the other information such as product name, version, manufacturer, and GUIDs as needed.


**Compile and Build the MSI:**

Open a command prompt and run the following commands:


```
candle package_files.wxs
light package_files.wixobj -out package_files.msi
```


These commands will compile the WiX script and create the MSI package (`package_files.msi`).


### Embed in a Virtual Disk Image

- **Method:** Create a virtual disk image (e.g., VHD) that includes both the EXE and other files. - 


```
import os
import pyvhd

# Define the path to the VHD file
vhd_file_path = "my_virtual_disk.vhd"

# Define the files you want to embed in the VHD
files_to_embed = [
    ("your_program.exe", "path/inside/vhd/your_program.exe"),
    ("file1.txt", "path/inside/vhd/file1.txt"),
    ("file2.txt", "path/inside/vhd/file2.txt"),
]

# Create a new VHD with a size of 1GB (you can adjust the size as needed)
vhd = pyvhd.VHD.create_dynamic(vhd_file_path, size=1024 * 1024 * 1024)

# Open the VHD for writing
with vhd.open() as vhd_file:
    # Add files to the VHD
    for source_file, destination_path_in_vhd in files_to_embed:
        with open(source_file, "rb") as file:
            file_data = file.read()
            vhd_file.write_file_data(destination_path_in_vhd, file_data)

print(f"Files embedded in '{vhd_file_path}'.")

# Optionally, you can mount the VHD or use it as needed in your virtualization software.
```


In this script:

- You define the path to the VHD file (`vhd_file_path`) and the list of files to embed within the VHD (`files_to_embed`).
- The script creates a new dynamic VHD with a size of 1GB. You can adjust the size as needed.
- It then opens the VHD for writing and adds the specified files to the VHD, specifying the destination path inside the VHD for each file.
- After running the script, you'll have a VHD file (`my_virtual_disk.vhd`) that includes the specified files.

### Custom File Format

- **Method:** Create a custom file format that includes the EXE and other data. 

```
import struct

# Define your custom file format
# For example, a format that includes an EXE file and two integers
# Format: EXE file (variable length), Integer A (4 bytes), Integer B (4 bytes)

# File paths
exe_file_path = "your_program.exe"
custom_file_path = "custom_file.bin"

# Metadata (replace with your data)
integer_a = 42
integer_b = 123

# Create the custom file
with open(custom_file_path, 'wb') as custom_file:
    # Write the EXE file (binary)
    with open(exe_file_path, 'rb') as exe_file:
        exe_data = exe_file.read()
        custom_file.write(exe_data)

    # Write the two integers
    custom_file.write(struct.pack('I', integer_a))
    custom_file.write(struct.pack('I', integer_b))

print(f"Custom file '{custom_file_path}' created.")
```


In this example:

1. We specify the structure of our custom file format, which includes an EXE file (variable length) followed by two 4-byte integers (Integer A and Integer B). Modify this structure as needed.
    
2. We open the EXE file and read its binary content.
    
3. We open the custom file in binary write mode and write the EXE data followed by the two integers using `struct.pack`.
    

After running this script, you will have a custom file (`custom_file.bin`) that includes the EXE and metadata. To read the custom file and extract the data, you'll need to reverse the process by reading the EXE data and unpacking the integers using `struct.unpack`. This depends on your specific use case.


### Use Resource Hacker (Windows Executable Files)

- **Method:** Embed arbitrary files as resources within a Windows EXE using Resource Hacker.

You can use a batch script to automate the process of embedding files using Resource Hacker. Below is a batch script example that embeds a file into an EXE:

```
@echo off
setlocal

rem Define the paths to Resource Hacker and the input EXE file
set resource_hacker_path="C:\Path\To\ResourceHacker.exe"
set input_exe="C:\Path\To\Input.exe"
set file_to_embed="C:\Path\To\FileToEmbed.txt"

rem Define the output EXE file (with the embedded resource)
set output_exe="C:\Path\To\Output.exe"

rem Use Resource Hacker to add the file as a resource to the input EXE
%resource_hacker_path% -add %input_exe%, %output_exe%, %file_to_embed%,,,

echo File embedded successfully.
exit /b 0
```

In this script:
    
- `resource_hacker_path` is the path to the Resource Hacker executable.
- `input_exe` is the path to the original EXE file.
 - `file_to_embed` is the path to the file you want to embed.
- `output_exe` is the path to the output EXE file with the embedded resource.

**Run the Batch Script:**
    
Save the batch script to a `.bat` file, for example, `embed_file.bat`. Make sure to adjust the paths for `resource_hacker_path`, `input_exe`, `file_to_embed`, and `output_exe`.
    
Run the batch script to embed the file into the EXE. After running the script, the output EXE (`Output.exe`) will contain the embedded file as a resource.

### Create a Self-Extracting Archive with 7-Zip

- **Method:** Use 7-Zip to create a self-extracting archive.


```
@echo off
setlocal

rem Define your source files to be included in the archive
set source_files=file1.txt file2.txt

rem Set the path to your 7-Zip executable (adjust as needed)
set sevenzip_path="C:\Program Files\7-Zip\7z.exe"

rem Set the name for the self-extracting archive
set sfx_archive=output_sfx.exe

rem Create the self-extracting archive using 7-Zip
%sevenzip_path% a -sfx7z.sfx -o%temp% %sfx_archive% %source_files%

rem Add any additional commands or cleanup here

endlocal
```


In this script:

- `set source_files` lists the files you want to include in the archive.
- `set sevenzip_path` specifies the path to your 7-Zip executable.
- `set sfx_archive` sets the name for the self-extracting archive.
- `%sevenzip_path% a -sfx7z.sfx -o%temp% %sfx_archive% %source_files%` creates the self-extracting archive using 7-Zip. Adjust the `-sfx7z.sfx` part based on the 7-Zip SFX module you want to use (e.g., `-sfx7zCon.sfx` for the console version).
- You can add any additional commands or cleanup as needed.

Then, simply run the batch script (`create_sfx.bat`), and it will create the self-extracting archive with the specified source files.



### Hide Files in Image Pixels (Steganography)

- **Method:** Use steganography to hide files within image pixels.

```
from PIL import Image

# Function to hide a file within an image
def hide_file(image_path, file_to_hide, output_image_path):
    # Open the image
    image = Image.open(image_path)

    # Open the file to hide
    with open(file_to_hide, "rb") as file:
        data_to_hide = file.read()

    # Convert data to a list of bits
    binary_data = [format(byte, '08b') for byte in data_to_hide]

    # Embed the data into the image's LSBs
    pixel_data = list(image.getdata())
    pixel_index = 0

    for i in range(len(binary_data)):
        pixel = list(pixel_data[pixel_index])
        for j in range(3):  # Process the RGB channels
            pixel[j] = int(format(pixel[j], '08b')[:-1] + binary_data[i][j], 2)
            i += 1
            if i == len(binary_data):
                break
        pixel_data[pixel_index] = tuple(pixel)
        pixel_index += 1

    # Create a new image with the hidden data
    hidden_image = Image.new(image.mode, image.size)
    hidden_image.putdata(pixel_data)

    # Save the image with hidden data
    hidden_image.save(output_image_path)
    print(f"File '{file_to_hide}' hidden within '{image_path}' and saved as '{output_image_path}'.")

# Function to extract a hidden file from an image
def extract_hidden_file(image_path, output_file):
    # Open the image
    image = Image.open(image_path)

    # Extract LSBs from the image pixels and convert to bytes
    binary_data = ""
    pixel_data = list(image.getdata())

    for pixel in pixel_data:
        for channel in pixel:
            binary_data += format(channel, '08b')[-1]

    # Convert binary data to bytes
    extracted_data = bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))

    # Write the extracted data to the output file
    with open(output_file, "wb") as file:
        file.write(extracted_data)

    print(f"Hidden file extracted and saved as '{output_file}'.")

# Example usage
if __name__ == "__main__":
    # Hide a file within an image
    hide_file("image.png", "file_to_hide.txt", "output_image_with_hidden_data.png")

    # Extract the hidden file from the image
    extract_hidden_file("output_image_with_hidden_data.png", "extracted_hidden_file.txt")
```

In this example, we use the Pillow library to manipulate the image. The `hide_file` function hides the data within an image, and the `extract_hidden_file` function extracts the hidden data.

Ensure you have the necessary image and file-to-hide files in the same directory, and replace `"image.png"`, `"file_to_hide.txt"`, `"output_image_with_hidden_data.png"`, `"extracted_hidden_file.txt"` with your file names.

### Hide Files in Audio Files (Audio Steganography)

- **Method:** Employ audio steganography to hide files within audio files.

```
import wave

# Function to hide a file within an audio file
def hide_file(audio_file, file_to_hide, output_audio_file):
    # Open the audio file
    audio = wave.open(audio_file, "rb")
    frames = audio.readframes(-1)
    audio.close()

    # Open the file to hide
    with open(file_to_hide, "rb") as file:
        data_to_hide = file.read()

    # Ensure the audio file has enough space to hide the data
    if len(data_to_hide) > len(frames):
        print("Error: The audio file does not have enough space to hide the data.")
        return

    # Hide the data within the audio using LSB
    frames_with_hidden_data = bytearray(frames)
    for i in range(len(data_to_hide)):
        frames_with_hidden_data[i] = (frames_with_hidden_data[i] & 254) | ((data_to_hide[i] >> 7) & 1)

    # Write the frames with hidden data to the output audio file
    audio = wave.open(output_audio_file, "wb")
    audio.setparams(audio.getparams())
    audio.writeframes(frames_with_hidden_data)
    audio.close()

    print(f"File '{file_to_hide}' hidden within '{audio_file}' and saved as '{output_audio_file}'.")

# Function to extract a hidden file from an audio file
def extract_hidden_file(audio_file, output_file):
    audio = wave.open(audio_file, "rb")
    frames = audio.readframes(-1)
    audio.close()

    hidden_data = bytearray()
    for i in range(len(frames)):
        hidden_data.append(frames[i] & 1)

    # Write the extracted data to the output file
    with open(output_file, "wb") as file:
        file.write(hidden_data)

    print(f"Hidden file extracted and saved as '{output_file}'.")

# Example usage
if __name__ == "__main__":
    # Hide a file within an audio file
    hide_file("audio.wav", "file_to_hide.txt", "output_audio_with_hidden_data.wav")

    # Extract the hidden file from the audio
    extract_hidden_file("output_audio_with_hidden_data.wav", "extracted_hidden_file.txt")
```


### Bind Files with a Custom File Format (Binary Serialization)

- **Method:** Create a custom binary file format to bind files together.

```
import struct
import os

# Define your custom file format
# For example, a format that stores a 4-byte header followed by the file content
FORMAT_HEADER = b'CUSTOM'  # 4 bytes
HEADER_SIZE = 4  # 4 bytes
MAX_FILE_SIZE = 1024 * 1024  # Maximum file size (1MB)

# Define a function to bind files into a single binary file
def bind_files(output_filename, files_to_bind):
    with open(output_filename, 'wb') as output_file:
        # Write the custom header
        output_file.write(FORMAT_HEADER)
        
        # Write the number of files as a 32-bit integer
        num_files = len(files_to_bind)
        output_file.write(struct.pack('I', num_files))
        
        for file_name in files_to_bind:
            # Write the file size as a 32-bit integer
            file_size = os.path.getsize(file_name)
            if file_size > MAX_FILE_SIZE:
                raise ValueError(f"File '{file_name}' exceeds the maximum allowed size.")
            output_file.write(struct.pack('I', file_size))
            
            # Write the file content
            with open(file_name, 'rb') as input_file:
                output_file.write(input_file.read())

# Define a function to extract files from the binary file
def extract_files(input_filename, output_directory):
    with open(input_filename, 'rb') as input_file:
        # Verify the custom header
        header = input_file.read(HEADER_SIZE)
        if header != FORMAT_HEADER:
            raise ValueError("Invalid file format.")
        
        # Read the number of files
        num_files = struct.unpack('I', input_file.read(4))[0]
        
        for i in range(num_files):
            # Read the file size
            file_size = struct.unpack('I', input_file.read(4))[0]
            
            # Read and save the file content
            file_content = input_file.read(file_size)
            output_file_name = os.path.join(output_directory, f"extracted_file_{i+1}.bin")
            with open(output_file_name, 'wb') as output_file:
                output_file.write(file_content)

# Usage example
if __name__ == '__main__':
    # List of files to bind
    files_to_bind = ["file1.txt", "file2.txt"]
    
    # Output file name
    output_filename = "bound_files.custom"
    
    # Bind the files together into a custom binary file
    bind_files(output_filename, files_to_bind)
    
    # Extract the files from the custom binary file
    extract_files(output_filename, "extracted_files")
```


### Use a Virtual File System (VFS)

- **Method:** Create a virtual file system to bundle files.

```
import zipfile
import os

# Define the names of the files to bundle
files_to_bundle = ["file1.txt", "file2.txt"]

# Name of the output ZIP archive
vfs_archive = "my_vfs.zip"

# Create a ZIP archive for the VFS
with zipfile.ZipFile(vfs_archive, "w", zipfile.ZIP_DEFLATED) as vfs:
    for file_name in files_to_bundle:
        # Specify the path inside the ZIP where the file will be stored
        zip_path = os.path.basename(file_name)
        vfs.write(file_name, zip_path)

print(f"Virtual File System (VFS) created: {vfs_archive}")
```

### Bind Using a Software Installer

- **Method:** Package files within a software installer.


```
# create_installer.py
import os
import sys
import shutil
import subprocess

# Define the files you want to include in the installer
files_to_package = ["file1.txt", "file2.txt"]

# Define the destination folder within the installer where the files will be extracted
destination_folder = "extracted_files"

# Create the destination folder if it doesn't exist
if not os.path.exists(destination_folder):
    os.makedirs(destination_folder)

# Copy the files to the destination folder
for file_name in files_to_package:
    shutil.copy(file_name, os.path.join(destination_folder, file_name))

# Create a Python script that will run when the installer is executed
installer_script = """
import os
import sys
import shutil

# Define the destination folder where the files will be extracted
destination_folder = "{destination_folder}"

# Create the destination folder if it doesn't exist
if not os.path.exists(destination_folder):
    os.makedirs(destination_folder)

# Extract files from the installer to the destination folder
for file_name in {files_to_package}:
    source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_name)
    destination_path = os.path.join(destination_folder, file_name)
    shutil.copy(source_path, destination_path)

print("Files extracted to:", destination_folder)
""".format(destination_folder=destination_folder, files_to_package=files_to_package)

# Write the installer script to a file
installer_script_file = "installer_script.py"
with open(installer_script_file, "w") as script_file:
    script_file.write(installer_script)

# Create the installer using PyInstaller
subprocess.run(["pyinstaller", "--onefile", installer_script_file])

# Clean up temporary files
os.remove(installer_script_file)

# Move the installer executable to the current directory
installer_name = os.path.splitext(installer_script_file)[0] + ".exe"
shutil.move(os.path.join("dist", installer_name), installer_name)

print("Installer created:", installer_name)
```

### Embed Files in a Database

- **Method:** Store files within a database.


**Using SQLite**

```
import sqlite3

# Connect to the SQLite database (create a new one if it doesn't exist)
conn = sqlite3.connect("embedded_files.db")
cursor = conn.cursor()

# Create a table to store files
cursor.execute('''CREATE TABLE IF NOT EXISTS Files
                  (id INTEGER PRIMARY KEY, filename TEXT, filedata BLOB)''')

# Function to insert a file into the database
def insert_file(filename, filedata):
    cursor.execute("INSERT INTO Files (filename, filedata) VALUES (?, ?)", (filename, filedata))
    conn.commit()

# Function to retrieve a file from the database by filename
def retrieve_file(filename):
    cursor.execute("SELECT filedata FROM Files WHERE filename = ?", (filename,))
    data = cursor.fetchone()
    if data:
        return data[0]
    else:
        return None

# Example usage
file_name = "example.txt"
with open(file_name, "rb") as file:
    file_data = file.read()
    insert_file(file_name, file_data)

retrieved_data = retrieve_file(file_name)
if retrieved_data:
    with open("retrieved_" + file_name, "wb") as retrieved_file:
        retrieved_file.write(retrieved_data)

# Close the database connection
conn.close()
```


**Database-agnostic**

```
-- Create a table to store files
CREATE TABLE IF NOT EXISTS Files (
    id SERIAL PRIMARY KEY,
    filename TEXT,
    filedata BYTEA -- Use appropriate data type for binary data (BYTEA for PostgreSQL)
);

-- Insert a file into the database
INSERT INTO Files (filename, filedata)
VALUES ('example.txt', E'\\x5468697320697320616e20656967687465656e2066696c652e'); -- Replace with your binary data
```


### Embed Files in a Virtual Machine (VM)

- **Method:** Include files within a virtual machine image.

```
import os
import subprocess
import sys

# Define your VM name and the path to the file you want to embed.
vm_name = "YourVMName"
file_to_embed = "path/to/your/file.ext"

# Check if the VM exists
try:
    subprocess.run(["VBoxManage", "showvminfo", vm_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except subprocess.CalledProcessError:
    print(f"Error: VM '{vm_name}' does not exist.")
    sys.exit(1)

# Check if the file to embed exists
if not os.path.exists(file_to_embed):
    print(f"Error: File '{file_to_embed}' not found.")
    sys.exit(1)

# Define the path where the file will be copied inside the VM (change as needed)
destination_path_in_vm = "/path/inside/vm"

# Use VBoxManage to copy the file into the VM
try:
    subprocess.run(["VBoxManage", "guestcontrol", vm_name, "copyto", "--target", destination_path_in_vm, file_to_embed], check=True)
    print(f"File '{file_to_embed}' successfully embedded into VM '{vm_name}' at '{destination_path_in_vm}'.")
except subprocess.CalledProcessError as e:
    print(f"Error embedding file: {e.stderr.decode().strip()}")
    sys.exit(1)
```



### Attach EXE File in PDF (Adobe Acrobat)
    

- **Method**: Use Adobe Acrobat (or other PDF editors) to attach an EXE file to a PDF document.
- **Steps**:
    1. Open the PDF in Adobe Acrobat.
    2. Go to the "Tools" menu.
    3. Select "Edit PDF."
    4. Click the "Attach a File" tool.
    5. Choose the EXE file you want to attach.
    6. Save the PDF.


### **Use Hyperlinks**(PDF):

- **Method**: Create a hyperlink within a PDF that links to an EXE file.
- **Steps**: This can be done using various PDF editing tools. Here's an example using LaTeX with the `hyperref` package:

```
\documentclass{article}
\usepackage{hyperref}

\begin{document}
Click [here](file://C:/path/to/your/exefile.exe) to open the EXE file.
\end{document}
```


### **JavaScript Action (PDF)**:

- **Method**: Add a JavaScript action to a PDF that opens an EXE file.
- **Steps**: This requires knowledge of PDF scripting. You can use Adobe Acrobat's JavaScript console or libraries like PDF.js.


### **PDF Document as a Container**:

- **Method**: Create a PDF that serves as a container for the EXE file without directly embedding it. Include instructions on how to open the EXE file separately.
- **Steps**: You can create a PDF document with text or links directing the user to download or execute the EXE file from a trusted source.


### Use a PDF Toolkit (pdftk):

- **Method:** Use pdftk to attach the PDF to the EXE as an additional file.
- **Commands/Tools:** You need to install pdftk.
- **Code Example (Command):**

```
pdftk your.pdf attach_files your.exe to_page 1 output combined.exe
```


### **Create a Self-Extracting Archive (SFX)**:

- **Method**: Use a tool like 7-Zip or WinRAR to create a self-extracting archive (SFX) that contains both the PDF and EXE files.
- **Steps**:
    1. Compress both the PDF and EXE into an SFX archive.
    2. Distribute the SFX archive to users, and they can extract both files together.


### **Embed PDF in EXE with Programming

- **Method:** Use a programming language like C#, Python, or PowerShell to create a custom EXE that embeds the PDF.
- **Commands/Tools:** You'll need a code editor and the respective programming language's tools.
- **Code Example (Python):**

```
import shutil

exe_data = open('your.exe', 'rb').read()
pdf_data = open('your.pdf', 'rb').read()

with open('output.exe', 'wb') as output:
    output.write(exe_data)
    output.write(pdf_data)
```


### EXE files to PNG
https://github.com/OsandaMalith/Exe2Image


### Exe files to JPG

https://github.com/Tsuyoken/ImgBackdoor



### Multi Exe

https://github.com/0x44F/exejoiner



### Java exe to jar

https://github.com/MagicianMido32/Java-exe-to-jar-multi-file-binder-FUD


### Use Microsoft Office Macros (VBA)

- **Method:** Create a Microsoft Office document (e.g., Word or Excel) that includes VBA macros that execute the EXE file.
- **Commands/Tools:** Microsoft Word, Excel, or other Office applications for creating documents with macros.
- **Code Example (VBA Macro in Word):**

```
Sub RunExeFile()
    Shell "path_to_your.exe", vbNormalFocus
End Sub
```





### All-in-One

https://github.com/nemesisS666/Pure-Crypter-Upgrade-Undetected
https://github.com/UnamSanctam/UnamBinder
https://github.com/Paskowsky/Dream-AIO


Cover By Joel Moran

# McTunnel: SSH Port Mapping for LAN-hosted Minecraft Servers

McTunnel is a Python application designed to facilitate remote connections to LAN-hosted Minecraft
servers by setting up an SSH tunnel for port mapping. This tool leverages SSH port forwarding to
allow connections to internal servers (such as a Minecraft server) from outside your local network.

--------------------------------------------------------------------------------------------------------------------------------------

## Features

- **SSH Tunneling for Port Mapping**: Enables external clients to connect to a LAN-hosted Minecraft
  server by forwarding SSH connections.
  
- **Auto Signing of RSA Keys**: Generates and automatically signs RSA host keys at startup.  
  
- **Manual Connection Approval**: For connections from IP addresses not explicitly whitelisted, the
   application requires manual approval through the GUI.
  
- **GUI Interface**: Built with Tkinter, the application provides a tabbed interface with separate
   sections for hosting, connecting, and monitoring logs & pending connection requests.
  
- **Logging**: All significant events (including connection attempts and errors) are logged in real-time
   to a file (`app.log`) and displayed in the GUI.
  
- **Minimal SSH Server**: The SSH server in this application is solely meant for port mapping.
   There is **no additional service attached** to it, so when testing manually (e.g., in a terminal),
   you may encounter:
  
  - **Channel Request Errors**: When requests to open a new session or direct TCP/IP channel fail.
  - **Key Signing Warnings**: Due to the automatic RSA key generation and signing process.
  - **Connection Timeouts**: Particularly if the router’s port forwarding (port 22) is not correctly configured.

----------------------------------------------------------------------------------------------------------------------------------------
## Important Considerations

- **Auto Signing Keys on Windows**:  
  The application auto-generates and signs RSA host keys. Although this simplifies setup, on Windows systems,
  this behavior may raise security alerts. I am aware of, and plan to address this issue in future releases.

- **Router Configuration for Hosting**:  
  To properly use the hosting functionality, ensure that **port 22 on your router is forwarded** to the machine running
  McTunnel. Without this, external SSH connections required for port mapping may fail.

- **Intended Use and Error Messages**:  
  McTunnel is focused on enabling port mapping so that Minecraft servers hosted on a LAN become accessible from outside
  the local network. When testing manually:
  - You may see **channel request errors** if the SSH client attempts services not provided by this minimal server.
  - **Random warnings or errors** may also appear during key signing or if the connection does not follow the expected forwarding
    flow. These issues are expected behavior given the limited scope of the SSH server.

- **Ongoing Development**:  
  This is in very early stages at the moment. It should work if everything is configured correctly, but I will slowly be consolidating
  its functionality, incorperating self tests, and educating myself on the interaction between paramiko and its dependencies.


## Getting Started

### Prerequisites

- **Python 3.x** installed on your system.
- The following Python module needs to be installed (see [requirements.txt](requirements.txt)):

  - [Paramiko](http://www.paramiko.org/)
  - 

### Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/mctunnel.git
   cd mctunnel


1. **Install the dependencies:**
   ```bash
   pip install -r requirements.txt


2. **Run the application:**
   ```bash
   python main.py

### Bonus

To quickly package this into an exe:

1. **Install pyinstaller:**
   ```bash
   python -m pip install pyinstaller

2. **Navigate to the cloned project:**
   ```bash
   cd <project_directory>

3. **Run the following:**
   ```
   python -m PyInstaller --onefile --noconsole --uac-admin main.py

  _python -m PyInstaller_ - runs pyinstaller as a python module

  _--uac-admin_ - embeds an automatic 'run as administrator' prompt,
  which is necessary for performing network operations on port 22.


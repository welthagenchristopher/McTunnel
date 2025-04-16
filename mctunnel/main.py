import os
import socket
import threading
import select
import paramiko
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import webbrowser
import urllib.request
import datetime

# ------------------------------
# Global Variables and Utilities
# ------------------------------

# Log file and lock
LOG_FILE = "app.log"
log_lock = threading.Lock()

# Global pending connection dictionary (for manual approval)
pending_connections = {}  # key: pending_id, value: dict with client, addr, event, decision, timestamp
pending_lock = threading.Lock()
pending_counter = 0  # to assign unique IDs

# Global variables for session management
ssh_server_stop_event = threading.Event()  # signal to stop SSH server thread
server_socket = None   # will hold the listening socket for the SSH server
ssh_server_thread = None  # reference to the SSH server thread

ssh_client_connection = None  # reference for the SSH client (connect side)

def log_event(message):
    """Append a timestamped message to the console and to the log file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    with log_lock:
        with open(LOG_FILE, "a") as f:
            f.write(log_msg + "\n")

# Ensure the log file exists
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write("")

def get_public_ip():
    """Retrieves the current public IP address."""
    try:
        external_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
        return external_ip
    except Exception as e:
        log_event(f"Error retrieving public IP: {e}")
        return "Unavailable"

# ------------------------------
# SSH Tunnel Functions (Client Side)
# ------------------------------

def handler(chan, host, port):
    """Transfer data between the SSH channel and the socket."""
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        log_event(f"Connection error on target {host}:{port}: {e}")
        return
    while True:
        # Empty arguments fulfill syntax requirement of 
        # read-ready, write-ready, exceptional conditions arguments
        # for select method. Only read ready is being monitored in
        # this case.
        r, _, _ = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if not data:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if not data:
                break
            sock.send(data)
    chan.close()
    sock.close()

def forward_tunnel(local_port, remote_host, remote_port, transport):
    """Set up local port forwarding via an established SSH transport."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', int(local_port)))
    sock.listen(100)
    log_event(f"Forwarding local port {local_port} to {remote_host}:{remote_port}")
    while True:
        client, addr = sock.accept()
        log_event(f"Local forwarder received connection from {addr}")
        try:
            chan = transport.open_channel('direct-tcpip', (remote_host, int(remote_port)), addr)
        except Exception as e:
            log_event(f"Failed to open channel: {e}")
            client.close()
            continue
        threading.Thread(target=handler, args=(chan, remote_host, int(remote_port)), daemon=True).start()

# ------------------------------
# Minimal SSH Server Interface (Host Side)
# ------------------------------

class SimpleSSHServer(paramiko.ServerInterface):
    def __init__(self, allowed_username, allowed_password, allowed_forward_port):
        self.allowed_username = allowed_username
        self.allowed_password = allowed_password
        self.allowed_forward_port = int(allowed_forward_port)
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        if username == self.allowed_username and password == self.allowed_password:
            log_event(f"User '{username}' authenticated successfully.")
            return paramiko.AUTH_SUCCESSFUL
        log_event(f"User '{username}' failed authentication.")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, chanid, origin_addr, target_addr):
        log_event(f"Port forwarding requested to: {target_addr}")
        if target_addr[1] == self.allowed_forward_port:
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

# ------------------------------
# SSH Server Daemon (Host Side)
# ------------------------------

def ssh_server_daemon(server_host, server_port, host_key_file, allowed_username, allowed_password, allowed_forward_port, allowed_client_ips):
    global server_socket
    try:
        host_key = paramiko.RSAKey.from_private_key_file(host_key_file, password=allowed_password)
    except Exception as e:
        log_event(f"Failed to load host key: {e}")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket = sock  # store for later shutdown
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((server_host, int(server_port)))
    except Exception as e:
        log_event(f"Failed to bind to {server_host}:{server_port}: {e}")
        return
    sock.listen(100)
    sock.settimeout(1.0)  # periodically check the stop event
    log_event(f"SSH server listening on {server_host}:{server_port} ...")

    while not ssh_server_stop_event.is_set():
        try:
            try:
                client, addr = sock.accept()
            except socket.timeout:
                continue
            client_ip = addr[0]
            # If allowed_client_ips is provided and client_ip is not in it, require manual approval.
            if allowed_client_ips and len(allowed_client_ips) > 0 and client_ip not in allowed_client_ips:
                log_event(f"Connection from {client_ip} requires manual approval.")
                global pending_counter
                with pending_lock:
                    pending_counter += 1
                    request_id = pending_counter
                    pending_connections[request_id] = {
                        'client': client,
                        'addr': addr,
                        'event': threading.Event(),
                        'decision': None,
                        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                pending_connections[request_id]['event'].wait()
                decision = pending_connections[request_id]['decision']
                with pending_lock:
                    del pending_connections[request_id]
                if not decision:
                    log_event(f"Connection from {client_ip} refused by manual approval.")
                    client.close()
                    continue
                else:
                    log_event(f"Connection from {client_ip} accepted via manual override.")
            else:
                log_event(f"Accepted connection from {addr} (automatic approval).")

            transport = paramiko.Transport(client)
            transport.add_server_key(host_key)
            server = SimpleSSHServer(allowed_username, allowed_password, allowed_forward_port)
            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                log_event(f"SSH negotiation failed: {e}")
                continue

            chan = transport.accept(20)
            if chan is None:
                log_event("No channel was opened. Closing connection.")
                continue

            chan.send("Welcome to the Paramiko SSH server!\n")
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                chan.send(data)
            chan.close()
            transport.close()
        except Exception as e:
            log_event(f"Error in SSH server loop: {e}")
    log_event("SSH server has been stopped.")
    sock.close()

# ------------------------------
# Tkinter Application with Tabbed Interface
# ------------------------------

class App:
    def __init__(self):
        self.app_window = tk.Tk()
        self.app_window.title("McTunnel")
        self.app_window.geometry("900x750")

        # Create a Notebook for persistent tabs
        self.notebook = ttk.Notebook(self.app_window)
        self.notebook.pack(expand=True, fill="both")

        # Create tabs for Host, Connect, and Logs & Pending
        self.host_tab = tk.Frame(self.notebook, bg="lightgray")
        self.connect_tab = tk.Frame(self.notebook, bg="lightgray")
        self.logs_tab = tk.Frame(self.notebook, bg="white")

        self.notebook.add(self.host_tab, text="Host")
        self.notebook.add(self.connect_tab, text="Connect")
        self.notebook.add(self.logs_tab, text="Logs & Pending")

        # Set up contents in each tab.
        self.setup_host_tab()
        self.setup_connect_tab()
        self.setup_logs_tab()

        # Docs button, placed below the notebook.
        self.docs_button = tk.Button(self.app_window, text="Docs", font=("Helvetica", 18), command=self.open_docs)
        self.docs_button.pack(pady=10)

        self.app_window.protocol("WM_DELETE_WINDOW", self.window_exit)
        self.app_window.mainloop()

    def window_exit(self):
        if messagebox.askyesno("Exit?", "Are you sure you want to exit?"):
            self.stop_hosting()  # try to stop if running
            if ssh_client_connection:
                try:
                    ssh_client_connection.close()
                except Exception:
                    pass
            self.app_window.destroy()

    # ------------------------------
    # Host Tab Setup
    # ------------------------------
    def setup_host_tab(self):
        # Host form frame
        form_frame = tk.Frame(self.host_tab, bg="lightgray")
        form_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        # Labels and entries for hosting configuration.
        labels = ["Listening IP:", "SSH Port:", "SSH Username:", "SSH Password:", "Forwarding Port:", "Allowed Client IPs (Optional, comma-separated):"]
        self.host_entries = {}
        defaults = ["0.0.0.0", "22", "testuser", "testpass", "25655", ""]
        for i, (label_text, default_val) in enumerate(zip(labels, defaults)):
            lbl = tk.Label(form_frame, text=label_text, font=("Helvetica", 16), bg="lightgray")
            lbl.grid(row=i, column=0, sticky="e", pady=5, padx=5)
            ent = tk.Entry(form_frame, font=("Helvetica", 16))
            ent.insert(0, default_val)
            ent.grid(row=i, column=1, sticky="ew", pady=5, padx=5)
            self.host_entries[label_text] = ent
        form_frame.columnconfigure(1, weight=1)
        # Start Hosting button
        self.host_start_btn = tk.Button(form_frame, text="Start Hosting", font=("Helvetica", 18), command=self.start_hosting)
        self.host_start_btn.grid(row=len(labels), column=0, columnspan=2, pady=20)
        # Session control area (Stop Hosting button will appear here)
        self.host_session_frame = tk.Frame(self.host_tab, bg="lightgray")
        self.host_session_frame.pack(fill=tk.X, padx=20, pady=10)
        # Status label area (for displaying messages)
        self.host_status_label = tk.Label(self.host_tab, text="", font=("Helvetica", 16), bg="lightgray")
        self.host_status_label.pack(fill=tk.X, padx=20, pady=10)

    def start_hosting(self):
        # Retrieve host configuration from entries
        ip = self.host_entries["Listening IP:"].get().strip()
        port = self.host_entries["SSH Port:"].get().strip()
        username = self.host_entries["SSH Username:"].get().strip()
        password = self.host_entries["SSH Password:"].get().strip()
        forward_port = self.host_entries["Forwarding Port:"].get().strip()
        allowed_ips_str = self.host_entries["Allowed Client IPs (Optional, comma-separated):"].get().strip()
        allowed_client_ips = []
        if allowed_ips_str:
            allowed_client_ips = [s.strip() for s in allowed_ips_str.split(",") if s.strip()]
            log_event(f"IP filtering enabled. Allowed client IPs: {allowed_client_ips}")

        if int(port) < 1024:
            if os.name == "posix":
                if os.geteuid() != 0:
                    messagebox.showerror("Privileges Error", f"Binding to port {port} requires root privileges. Please run with sudo.")
                    return
            elif os.name == "nt":
                messagebox.showwarning("Privileges Warning", f"Binding to port {port} requires Administrator privileges. Please run as Administrator.")

        # Generate a new RSA host key (delete old if present)
        # Does run into issue of requiring manual approval each time due to
        # default strick check & attempted automatic key singing.

        # Perhaps a sys.time based key or manual re-generation
        key_file = "server.key"
        if os.path.exists(key_file):
            os.remove(key_file)
        try:
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(key_file, password=password)
            log_event(f"Generated and encrypted host key at {key_file}")
        except Exception as e:
            messagebox.showerror("Key Generation Error", f"Failed to generate host key: {e}")
            return

        pub_ip = get_public_ip()
        status_msg = (f"SSH server started.\nListening on {ip}:{port}\nAllowed forwarding to: localhost:{forward_port}\nYour public IP: {pub_ip}\nConnect with: ssh {username}@<YourPublicIP>")
        self.host_status_label.config(text=status_msg)
        log_event("SSH server started.")

        # Clear any existing stop event
        ssh_server_stop_event.clear()
        # Start the SSH server in a background thread.
        global ssh_server_thread
        ssh_server_thread = threading.Thread(target=ssh_server_daemon, kwargs={
            "server_host": ip,
            "server_port": port,
            "host_key_file": key_file,
            "allowed_username": username,
            "allowed_password": password,
            "allowed_forward_port": forward_port,
            "allowed_client_ips": allowed_client_ips
        }, daemon=True)
        ssh_server_thread.start()
        # Add a Stop Hosting button to the session control frame
        for widget in self.host_session_frame.winfo_children():
            widget.destroy()
        stop_btn = tk.Button(self.host_session_frame, text="Stop Hosting", font=("Helvetica", 18), bg="red", fg="white", command=self.stop_hosting)
        stop_btn.pack(fill=tk.X, padx=10, pady=5)

    def stop_hosting(self):
        ssh_server_stop_event.set()
        global server_socket
        if server_socket:
            try:
                server_socket.close()
                log_event("Server socket closed.")
            except Exception as e:
                log_event(f"Error closing server socket: {e}")
            server_socket = None
        for widget in self.host_session_frame.winfo_children():
            widget.destroy()
        self.host_status_label.config(text="SSH server stopped.")
        log_event("SSH server stopped.")

    # ------------------------------
    # Connect Tab Setup (Client Side)
    # ------------------------------
    def setup_connect_tab(self):
        form_frame = tk.Frame(self.connect_tab, bg="lightgray")
        form_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        labels = ["SSH Server Address:", "SSH Server Port:", "SSH Username:", "SSH Password:", "Local Forwarding Port:", "Remote Target Port:"]
        self.connect_entries = {}
        defaults = ["example.ddns.net", "22", "testuser", "testpass", "25655", "25655"]
        for i, (lbl_txt, def_val) in enumerate(zip(labels, defaults)):
            lbl = tk.Label(form_frame, text=lbl_txt, font=("Helvetica", 16), bg="lightgray")
            lbl.grid(row=i, column=0, sticky="e", pady=5, padx=5)
            ent = tk.Entry(form_frame, font=("Helvetica", 16))
            ent.insert(0, def_val)
            ent.grid(row=i, column=1, sticky="ew", pady=5, padx=5)
            self.connect_entries[lbl_txt] = ent
        form_frame.columnconfigure(1, weight=1)
        self.connect_start_btn = tk.Button(form_frame, text="Connect", font=("Helvetica", 18), command=self.start_client_connection)
        self.connect_start_btn.grid(row=len(labels), column=0, columnspan=2, pady=20)

        self.connect_status_label = tk.Label(self.connect_tab, text="", font=("Helvetica", 16), bg="lightgray")
        self.connect_status_label.pack(fill=tk.X, padx=20, pady=10)
        # Session control area for client (Disconnect button will appear here)
        self.connect_session_frame = tk.Frame(self.connect_tab, bg="lightgray")
        self.connect_session_frame.pack(fill=tk.X, padx=20, pady=10)

    def start_client_connection(self):
        server_addr = self.connect_entries["SSH Server Address:"].get().strip()
        server_port = self.connect_entries["SSH Server Port:"].get().strip()
        username = self.connect_entries["SSH Username:"].get().strip()
        password = self.connect_entries["SSH Password:"].get().strip()
        local_port = self.connect_entries["Local Forwarding Port:"].get().strip()
        remote_port = self.connect_entries["Remote Target Port:"].get().strip()

        self.connect_status_label.config(text="Connecting to SSH server...")
        def client_thread():
            global ssh_client_connection
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh_client.connect(server_addr, port=int(server_port), username=username, password=password)
            except Exception as e:
                self.connect_status_label.config(text=f"SSH connection failed: {e}")
                log_event(f"Client SSH connection failed: {e}")
                return
            ssh_client_connection = ssh_client
            transport = ssh_client.get_transport()
            threading.Thread(target=forward_tunnel, args=(local_port, "localhost", remote_port, transport), daemon=True).start()
            self.connect_status_label.config(text=f"SSH tunnel established.\nConnect your Minecraft client to localhost:{local_port}")
            log_event("Client SSH tunnel established.")
            # Add Disconnect button in session control frame.
            for widget in self.connect_session_frame.winfo_children():
                widget.destroy()
            disconnect_btn = tk.Button(self.connect_session_frame, text="Disconnect", font=("Helvetica", 18), bg="red", fg="white", command=self.disconnect_client)
            disconnect_btn.pack(fill=tk.X, padx=10, pady=5)
        threading.Thread(target=client_thread, daemon=True).start()

    def disconnect_client(self):
        global ssh_client_connection
        if ssh_client_connection:
            try:
                ssh_client_connection.close()
                log_event("Client SSH connection disconnected.")
            except Exception as e:
                log_event(f"Error disconnecting SSH client: {e}")
        ssh_client_connection = None
        self.connect_status_label.config(text="Disconnected from SSH server.")
        for widget in self.connect_session_frame.winfo_children():
            widget.destroy()

    # ------------------------------
    # Logs Tab Setup (Always Present)
    # ------------------------------
    def setup_logs_tab(self):
        # Create two vertical panes using frames.
        left_frame = tk.Frame(self.logs_tab, bg="lightblue", width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)
        right_frame = tk.Frame(self.logs_tab, bg="white")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        tk.Label(left_frame, text="Pending Connection Requests", bg="lightblue", font=("Helvetica", 16))\
            .pack(pady=10)
        self.pending_container = tk.Frame(left_frame, bg="lightblue")
        self.pending_container.pack(fill=tk.BOTH, expand=True)

        # Start updating pending requests automatically.
        self.update_pending_requests(left_frame)

        # Create scrolled text for log file contents.
        self.log_scroller = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, font=("Helvetica", 12))
        self.log_scroller.pack(expand=True, fill='both')
        self.update_logs(right_frame)

    def update_pending_requests(self, parent):
        for widget in self.pending_container.winfo_children():
            widget.destroy()
        with pending_lock:
            for req_id, req in pending_connections.items():
                frame = tk.Frame(self.pending_container, bg="lightblue", bd=2, relief=tk.RIDGE)
                frame.pack(fill=tk.X, padx=5, pady=5)
                label = tk.Label(frame, text=f"{req['addr'][0]} at {req['timestamp']}", bg="lightblue", font=("Helvetica", 12))
                label.pack(side=tk.LEFT, padx=5)
                def make_accept(rid=req_id):
                    def accept():
                        with pending_lock:
                            if rid in pending_connections:
                                pending_connections[rid]['decision'] = True
                                pending_connections[rid]['event'].set()
                    return accept
                def make_refuse(rid=req_id):
                    def refuse():
                        with pending_lock:
                            if rid in pending_connections:
                                pending_connections[rid]['decision'] = False
                                pending_connections[rid]['event'].set()
                    return refuse
                btn_accept = tk.Button(frame, text="Accept", command=make_accept(), bg="green", fg="white")
                btn_accept.pack(side=tk.LEFT, padx=5)
                btn_refuse = tk.Button(frame, text="Refuse", command=make_refuse(), bg="red", fg="white")
                btn_refuse.pack(side=tk.LEFT, padx=5)
        self.logs_tab.after(2000, lambda: self.update_pending_requests(parent))

    def update_logs(self, parent):
        try:
            with open(LOG_FILE, "r") as f:
                content = f.read()
        except Exception as e:
            content = f"Failed to read log file: {e}"
        self.log_scroller.configure(state="normal")
        self.log_scroller.delete(1.0, tk.END)
        self.log_scroller.insert(tk.END, content)
        self.log_scroller.configure(state="disabled")
        self.logs_tab.after(2000, lambda: self.update_logs(parent))

    # ------------------------------
    # Docs
    # ------------------------------
    def open_docs(self):
        github_url = "https://github.com/your_repo"  # Replace with your repository URL.
        webbrowser.open_new_tab(github_url)

if __name__ == "__main__":
    App()

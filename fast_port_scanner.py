import socket, sys
import time, queue
import threading
import requests

usage = "python3 simple_port_scanner.py TARGET START_PORT END_PORT THREADS"

print("*" * 50)
print("Python Simple Port Scanner")
print("*" * 50)

# Ensure correct number of arguments
if len(sys.argv) < 5:
    print(usage)
    exit()

# Get arguments
target = sys.argv[1]
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])
thread_no = int(sys.argv[4])

result = "PORT\tSTATE\tSERVICE\n"

# Resolve host
try:
    target = socket.gethostbyname(target)
except socket.gaierror:
    print("[-] Host resolution failed.")
    exit()

def get_banner(port, s):
    if (port == 80):
       response = requests.get("http://" + target)
       return response.headers['Server']
    try:
        return s.recv(1024).decode()
    except:
        return 'Not found'

print("[+] Scanning target: {}".format(target))

# Create a queue for ports
q = queue.Queue()

# Port scanning function
def scan_port():
    global result
    while not q.empty():
        port = q.get()
        print("Scanning port {}...".format(port))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)  # Prevents long waits on unresponsive ports
            conn = s.connect_ex((target, port))
            if conn == 0:  # connect_ex() returns 0 when port is open
               banner = get_banner(port, s)
               banner = ''.join(banner.splitlines())
               result += f"{port}\tOPEN\t{banner}\n"
            s.close()
        except Exception as e:
            pass
        q.task_done()

# Add ports to queue
for j in range(start_port, end_port + 1):
    q.put(j)

# Start time
start_time = time.time()

# Create and start threads
for _ in range(thread_no):
    t = threading.Thread(target=scan_port)
    t.start()

# Wait for all threads to finish
q.join()

# End time
end_time = time.time()
print(result)
print("Time Taken: {:.2f} seconds".format(end_time - start_time))

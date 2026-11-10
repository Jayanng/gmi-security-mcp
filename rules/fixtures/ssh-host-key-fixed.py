import paramiko

client = paramiko.SSHClient()
client.load_system_host_keys()
client.connect("example.com", username="admin", password="hunter2")

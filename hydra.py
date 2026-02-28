import socket
import threading

def start_fake_service(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(('0.0.0.0', port))
        server.listen(5)
        print(f"Opening port: {port}")
        while True:
            client, addr = server.accept()
            client.close()
    except:
        pass

if __name__ == "__main__":
    print("--- FAKE SERVICES STARTED ---")
    ports = [21, 22, 9999, 8888, 7777, 6666, 4444, 8000, 8081, 8082, 8083, 8084, 443, 1234]
    
    for p in ports:
        threading.Thread(target=start_fake_service, args=(p,)).start()
#!/usr/bin/env python3

import socket
import threading
import time
import sys

def handle_client(conn, addr):
    print(f"[SERVER] Connection from {addr}")
    client_id = f"{addr[0]}:{addr[1]}"

    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break

            message = data.decode('utf-8').strip()
            timestamp = time.strftime("%H:%M:%S")

            print(f"[SERVER] [{timestamp}] From {client_id}: '{message}'")

            if message.lower() == 'quit':
                response = "SERVER: Goodbye!"
                conn.send(response.encode('utf-8'))
                break

            # Echo with server info
            response = f"SERVER_ECHO[{timestamp}]: {message}"
            conn.send(response.encode('utf-8'))
            print(f"[SERVER] [{timestamp}] To {client_id}: '{response}'")

    except Exception as e:
        print(f"[SERVER] Error with {client_id}: {e}")
    finally:
        conn.close()
        print(f"[SERVER] {client_id} disconnected")

def main():
    print("=" * 50)
    print("IPsec VPN Test Server")
    print("=" * 50)

    # Server listens on corporate network IP
    server_ip = "10.1.0.1"
    server_port = 8080

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((server_ip, server_port))
        server.listen(5)

        print(f"[SERVER] Server started on {server_ip}:{server_port}")
        print(f"[SERVER] All traffic will be encrypted via IPsec tunnel")
        print(f"[SERVER] Waiting for VPN clients...")
        print()
        print("=" * 50)
        print()

        while True:
            conn, addr = server.accept()

            # Start new thread for each client
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True
            )
            client_thread.start()

    except KeyboardInterrupt:
        print("\n[SERVER] Server shutting down...")
    except Exception as e:
        print(f"[SERVER] Server error: {e}")
    finally:
        server.close()
        print("[SERVER] Server socket closed")

if __name__ == "__main__":
    main()
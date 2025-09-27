#!/usr/bin/env python3

import socket
import sys
import time
import signal
import select

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[CLIENT] Interrupt received, exiting...")
    sys.exit(0)

def get_user_input(prompt):
    """Get user input with proper cleanup"""
    try:
        # Clear any pending input first
        if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
            sys.stdin.readline()  # Discard any pending input

        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return "quit"

def main():
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    print("=" * 50)
    print("IPsec VPN Test Client")
    print("=" * 50)

    # Connect to server through IPsec tunnel
    server_ip = "10.1.0.1"  # Server's corporate network IP
    server_port = 8080

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        print(f"[CLIENT] Connecting to {server_ip}:{server_port}")
        print(f"[CLIENT] Connection will be encrypted via IPsec tunnel")

        client.connect((server_ip, server_port))

        print(f"[CLIENT] Connected successfully!")
        print(f"[CLIENT] Type messages to send (or 'quit' to exit)")
        print()
        print("=" * 50)
        print()

        while True:
            # Get message from user
            message = get_user_input("[CLIENT] Enter message: ")

            if not message:
                continue

            timestamp = time.strftime("%H:%M:%S")
            print(f"[CLIENT] [{timestamp}] SENDING: '{message}'")

            # Send message
            client.send(message.encode('utf-8'))

            if message.lower() == 'quit':
                # Wait for server response then exit
                try:
                    response = client.recv(1024)
                    if response:
                        print(f"[CLIENT] [{timestamp}] RECEIVED: '{response.decode('utf-8')}'")
                except:
                    pass
                break

            # Receive response
            try:
                response = client.recv(1024)
                if response:
                    decoded_response = response.decode('utf-8')
                    print(f"[CLIENT] [{timestamp}] RECEIVED: '{decoded_response}'")
                else:
                    print(f"[CLIENT] No response from server")
                    break
            except Exception as e:
                print(f"[CLIENT] Error receiving response: {e}")
                break

            print()

    except ConnectionRefusedError:
        print(f"[CLIENT] Connection refused to {server_ip}:{server_port}")
        print(f"[CLIENT] Make sure:")
        print(f"[CLIENT]   1. IPsec tunnel is established")
        print(f"[CLIENT]   2. Server is running on {server_ip}:{server_port}")
        print(f"[CLIENT]   3. Check: docker exec -it ipsec-client swanctl --list-sas")
    except KeyboardInterrupt:
        print("\n[CLIENT] Interrupted by user")
    except Exception as e:
        print(f"[CLIENT] Error: {e}")
    finally:
        try:
            client.close()
        except:
            pass
        print("[CLIENT] Disconnected from server")

if __name__ == "__main__":
    main()
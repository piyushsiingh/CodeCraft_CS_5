import socket
import struct
import time
from datetime import datetime
import threading
import sys
from queue import Queue

# ========== CONSTANTS & SETUP ========== #
DISCLAIMER = """
\033[91m
╔════════════════════════════════════════════════════════════╗
║                ETHICAL PACKET SNIFFER v2.0                 ║
║                  (EDUCATIONAL USE ONLY)                    ║
╠════════════════════════════════════════════════════════════╣
║ WARNING: Unauthorized network monitoring may be illegal.   ║
║ Use only on networks you own or have permission to monitor.║
╚════════════════════════════════════════════════════════════╝
\033[0m
Press \033[92mEnter\033[0m to continue or \033[91mCtrl+C\033[0m to exit...
"""

PROTOCOL_COLORS = {
    'TCP': '\033[94m',    # Blue
    'UDP': '\033[95m',    # Purple
    'ICMP': '\033[96m',   # Cyan
    'OTHER': '\033[93m',  # Yellow
    'RESET': '\033[0m'
}

# ========== ANIMATION THREAD ========== #
class SnifferAnimation:
    def __init__(self):
        self.animation_active = True
        self.spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.spinner_pos = 0
        self.packet_queue = Queue()
        self.stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'other': 0,
            'bytes': 0
        }

    def update_stats(self, protocol, size):
        self.stats['total'] += 1
        self.stats['bytes'] += size
        if protocol == 'TCP':
            self.stats['tcp'] += 1
        elif protocol == 'UDP':
            self.stats['udp'] += 1
        elif protocol == 'ICMP':
            self.stats['icmp'] += 1
        else:
            self.stats['other'] += 1

    def show_animation(self):
        """Display animated packet capture status"""
        while self.animation_active:
            # Spinner animation
            sys.stdout.write(f"\r\033[K{self.spinner[self.spinner_pos]} Capturing packets... | ")
            sys.stdout.write(f"TCP: {self.stats['tcp']} | ")
            sys.stdout.write(f"UDP: {self.stats['udp']} | ")
            sys.stdout.write(f"ICMP: {self.stats['icmp']} | ")
            sys.stdout.write(f"Total: {self.stats['total']} packets")
            sys.stdout.flush()
            self.spinner_pos = (self.spinner_pos + 1) % len(self.spinner)
            time.sleep(0.1)

            # Process queued packets
            while not self.packet_queue.empty():
                packet = self.packet_queue.get()
                self.display_packet(packet)

    def display_packet(self, packet):
        """Display packet with color coding"""
        timestamp, src, dest, protocol, size, info = packet
        color = PROTOCOL_COLORS.get(protocol, PROTOCOL_COLORS['OTHER'])
        
        print(f"\r\033[K{color}{timestamp} {src:>15} → {dest:<15} {protocol:<5} {size:>5} bytes  {info}{PROTOCOL_COLORS['RESET']}")
        print(f"\033[K", end='')  # Clear line for animation

# ========== PACKET CAPTURE ========== #
def start_sniffer(animation):
    """Main packet capture loop"""
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        while animation.animation_active:
            raw_data, _ = conn.recvfrom(65535)
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            
            if eth_proto == 8:  # IPv4
                version, _, ttl, proto, src, target, data = ipv4_packet(data)
                protocol, info = "", ""
                
                # TCP
                if proto == 6:
                    src_port, dest_port, *_, data = tcp_segment(data)
                    flags = []
                    protocol = "TCP"
                    info = f"{src_port}→{dest_port}"
                
                # UDP
                elif proto == 17:
                    src_port, dest_port, _, data = udp_segment(data)
                    protocol = "UDP"
                    info = f"{src_port}→{dest_port}"
                
                # ICMP
                elif proto == 1:
                    icmp_type, code, _, data = icmp_packet(data)
                    protocol = "ICMP"
                    info = f"Type:{icmp_type} Code:{code}"
                
                else:
                    protocol = f"IPv4-{proto}"
                
                animation.packet_queue.put((timestamp, src, target, protocol, len(raw_data), info))
                animation.update_stats(protocol, len(raw_data))

    except KeyboardInterrupt:
        animation.animation_active = False
    except Exception as e:
        print(f"\n\033[91mError: {str(e)}\033[0m")
        animation.animation_active = False

# ========== PROTOCOL PARSERS ========== #
def ethernet_frame(data):
    """Parse Ethernet frame"""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    """Format MAC address"""
    return ':'.join(f'{byte:02x}' for byte in bytes_addr).upper()

def ipv4_packet(data):
    """Parse IPv4 packet"""
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

def ipv4(addr):
    """Format IPv4 address"""
    return '.'.join(map(str, addr))

def tcp_segment(data):
    """Parse TCP segment"""
    (src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'urg': (offset_reserved_flags & 32) >> 5,
        'ack': (offset_reserved_flags & 16) >> 4,
        'psh': (offset_reserved_flags & 8) >> 3,
        'rst': (offset_reserved_flags & 4) >> 2,
        'syn': (offset_reserved_flags & 2) >> 1,
        'fin': offset_reserved_flags & 1
    }
    return src_port, dest_port, sequence, ack, flags, data[offset:]

def udp_segment(data):
    """Parse UDP segment"""
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def icmp_packet(data):
    """Parse ICMP packet"""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# ========== MAIN ========== #
def main():
    print(DISCLAIMER)
    input()  # Wait for user acknowledgment
    
    animation = SnifferAnimation()
    
    # Start animation thread
    anim_thread = threading.Thread(target=animation.show_animation)
    anim_thread.daemon = True
    anim_thread.start()
    
    # Start capture thread
    capture_thread = threading.Thread(target=start_sniffer, args=(animation,))
    capture_thread.daemon = True
    capture_thread.start()
    
    try:
        while True:
            # Check for user input to quit
            time.sleep(0.1)
            if not anim_thread.is_alive() or not capture_thread.is_alive():
                break
                
    except KeyboardInterrupt:
        print("\n\033[93mStopping capture...\033[0m")
        animation.animation_active = False
        capture_thread.join()
        anim_thread.join()
    
    # Final stats
    print("\n\033[1mCapture Summary:\033[0m")
    print(f"Total Packets: {animation.stats['total']}")
    print(f"TCP: {animation.stats['tcp']} | UDP: {animation.stats['udp']} | ICMP: {animation.stats['icmp']} | Other: {animation.stats['other']}")
    print(f"Total Data: {animation.stats['bytes'] / 1024:.2f} KB")

if __name__ == "__main__":
    main()

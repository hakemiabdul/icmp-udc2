# ICMP UDC2 Server

An ICMP-based UDP-to-TCP relay server to demonstrate implementing an ICMP C2 channel using
User-Defined C2.

## Features

### Core Features
- **ICMP Packet Processing**: Handles Beacon ICMP echo requests with custom headers
- **Packet Fragmentation**: Automatic handling of large payloads with fragmentation
- **Team Server Relay**: Persistent connections to team server with automatic reconnection
- **Multi-threaded**: Concurrent handling of multiple clients
- **Configuration Management**: JSON-based configuration with command-line overrides
- **Metrics & Monitoring**: Optional metrics collection for performance monitoring

## Requirements

- Python 3.7+
- Administrative/root privileges (for raw socket access)
- Network access to team server

## Installation

1. Ensure Python 3.7+ is installed
2. No external dependencies required (uses only standard library)
3. If you want to deploy and run it as a service, copy the files in this folder to a linux system and run the deploy script. If you just want to run the python script standalone, see the Usage section below. 

## Configuration

### Configuration File (config.json)
```json
{
  "ts_addr": "127.0.0.1",
  "ts_port": 2222,
  "listen_addr": "0.0.0.0",
  "max_fragment_size": 65491,
  "log_level": "INFO",
  "connection_timeout": 300,
  "max_connections": 1000,
  "enable_metrics": true
}
```

### Generate Configuration File
```bash
python icmp_udc2_server.py --generate-config config.json
```

## Usage

### Basic Usage
```bash
# Set address and port of UDC2 listener
sudo python icmp_udc2_server.py --ts-addr 192.168.1.100 --ts-port 3333
```

### Advanced Usage
```bash
# Use configuration file
sudo python icmp_udc2_server.py --config config.json

# Enable debug logging and metrics
sudo python icmp_udc2_server.py --log-level DEBUG --enable-metrics

# Custom listen address for icmp listener (default is 0.0.0.0)
sudo python icmp_udc2_server.py --listen-addr 192.168.1.50
```

### Command Line Options
- `--config, -c`: Path to configuration file
- `--ts-addr`: Team server address (default: 127.0.0.1)
- `--ts-port`: Team server port (default: 2222)
- `--listen-addr`: Listen address (default: 0.0.0.0)
- `--log-level`: Log level (DEBUG, INFO, WARNING, ERROR)
- `--enable-metrics`: Enable metrics collection
- `--generate-config`: Generate sample configuration file

## Architecture

### Components

1. **ICMPServer**: Main server class coordinating all components
2. **ICMPPacketHandler**: Handles ICMP packet parsing and construction
3. **BeaconManager**: Manages Beacon state and fragmentation
4. **ConnectionManager**: Manages connections to team server
5. **ServerMetrics**: Collects performance metrics

### Threading Model

- **ICMPListener**: Listens for incoming ICMP packets
- **TSRelayWorker**: Relays data to/from team server
- **CleanupWorker**: Performs periodic maintenance tasks

### Packet Flow

1. Client sends ICMP echo request with custom header
2. Server parses packet and extracts custom data
3. For Beacon data: fragments are assembled if needed, then relayed to team server
4. For task requests: server responds with cached team server responses
5. Server sends ICMP echo reply acknowledgments

## Protocol Details

### Custom Header Format
```c
typedef struct _ICMP_HEADER {
    DWORD Type;           // Packet type (BEACON_DATA, REQUEST_TS_REPLY, ACK, TASK)
    DWORD Identifier;     // Custom identifier for session tracking
    DWORD Flags;          // Fragmentation and control flags
    DWORD FragmentIndex;  // Fragment index for large payloads
} ICMP_HEADER;
```

### Packet Types
- `BEACON_DATA (0)`: Client sending data to team server
- `REQUEST_TS_REPLY (1)`: Client requesting reply to Beacon data (ie task) from team server
- `ACK (2)`: Server acknowledgment of each Beacon data packet
- `TASK (3)`: Server sending task to client in response to ts reply request

### Fragmentation Flags
- `FRAGMENTED (0x1)`: Indicates packet is fragmented
- `FIRST_FRAG (0x10)`: First fragment in sequence
- `LAST_FRAG (0x100)`: Last fragment in sequence
- `FETCH_FRAG (0x1000)`: Request specific fragment

## Monitoring

### Log Files
- Console output with timestamped entries
- File logging to `icmp_udc2_server.log`
- Structured logging with thread names

### Metrics (when enabled)
- Packets received/sent counts
- Fragment processing statistics
- Active connection counts
- Error counts
- Server uptime and performance

## Security Considerations

### Input Validation
- Packet size limits (10MB maximum frame size)
- Header validation
- Fragment timeout handling

### Resource Management
- Connection limits and timeouts
- Automatic cleanup of expired data

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure running with administrative/root privileges
   - Raw sockets require elevated permissions

2. **Connection Refused**
   - Verify team server is running and accessible
   - Check firewall settings
   - Confirm correct IP/port configuration

3. **Beacon communication not working**
   - Ensure system icmp echo reply is disabled
   - Linux: sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1

4. **Packet Loss**
   - Check network MTU settings
   - Monitor fragmentation statistics
   - Verify ICMP is not blocked by firewalls

### Debug Mode
```bash
sudo python icmp_udc2_server_professional.py --log-level DEBUG
```

### Log Analysis
```bash
# Monitor real-time logs
tail -f icmp_udc2_server.log

# Filter specific events
grep "ERROR" icmp_udc2_server.log
grep "Fragment" icmp_udc2_server.log
```

## Performance Tuning

### Configuration Optimization
- Adjust `max_fragment_size` but be careful with this as you need to adjust how fragmentation is handled in both the BOF and the server. Currently it uses the entirety of the icmp payload max size for each fragment. If you reduce this, you will be sending potentially a lot more ICMP packets for large payloads and you will need to make sure the BOF and the server properly handle this. Changing this value without modifying the BOF will break this demo.
- Tune `connection_timeout` for your environment. If you have Beacons checking in on very long intervals, adjust this slightly above that so the relay connection for that Beacon doesn't time out prematurely.
- Set appropriate `max_connections` limit
- Configure log level for production (INFO or WARNING)

### System Optimization
- Increase socket buffer sizes if needed
- Monitor system resources during peak load
- Consider process priority adjustment for critical deployments

## License

Apache 2.0 - See LICENSE in root folder

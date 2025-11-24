# ICMP UDC2 BOF

A Beacon Object File (BOF) implementation that provides an ICMP UDC2 channel that uses ICMP echo requests/replies. 

## Overview

The ICMP UDC2 BOF acts as a communication proxy that:
- Encapsulates Beacon traffic within ICMP echo requests
- Fragments large payloads across multiple ICMP packets when needed

## Features

### Core Functionality
- **ICMP Communication**: Native ICMP echo request/reply protocol implementation
- **Packet Fragmentation**: Automatic fragmentation for large payloads
- **Retry Logic**: Configurable retry attempts with exponential backoff

### BOF Compliance
- **No MSVCRT Dependencies**: Uses only Windows API functions
- **Minimal Footprint**: Optimized for in-memory execution

## ICMP UDC2 Release Example Quick Start Guide

To quickly get the ICMP UDC2 Release BOF built and usable within Cobalt Strike, follow the instructions below. Note that you should have the `Release` solution configuration selected for this.

1. In the icmp_udc2_bof.cpp file, find the following line: `gUdc2State.serverAddr = "127.0.0.1"; // TODO: SET THIS TO YOUR UDC2 SERVER ADDRESS`
2. Change the gUdc2State.serverAddr to the IP address where your UDC2 server will be listening (See step 6)
3. Make sure the "Release" configuration is selected in Visual Studio and choose the architecture you wish to build the BOF for (x64 or x86)
4. From the Build menu in Visual Studio, click Build Solution
5. Once the BOF has been successfully built, open the Cobalt Strike client and open the listeners page. Create a new UDC2 listener. Give it a name like udc2-icmp-x64 or udc2-icmp-x86 and choose a port for the UDC2 listener to listen on. For the UDC2 BOF field, click on the open-file dialog option and select the ICMP UDC2 BOF that you just built in the previous step. Ensure that the "Debug only" checkbox is **NOT** checked. If you want to apply guard rails, apply them, and finally click Save.
6. For specific usage instructions of the ICMP UDC2 server python script, refer to the documentation in the server\\README.md file. In the interim, run the python script with the following options: `python3 icmp_udc2_server.py --ts-addr YOUR_TS_UDC2_LISTENER_IP --ts-port YOUR_TS_UDC2_LISTENER_PORT`
7. If you are running the python script under WSL on Windows, or from a linux environment, make sure that you disable automatic ICMP echo replies, as this will interfere with Beacon communication. To temporarily disable ICMP echo replies, use either of the following commands: `sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1` or `sudo echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all`. Note you may need to disable icmp echo replies on Windows if you are running the script from Windows.
8. From the Cobalt Strike client, export a payload as you would normally, but choose the new UDC2 listener you created in step 5.
9. Your payload is now ready to execute with the ICMP UDC2 BOF stomped into it. Run the payload and you should see ICMP requests being sent to your python UDC2 server which will extract the Beacon frame data from them and forward it on to the UDC2 listener on the Team Server. 
10. You should now see a new Beacon registered in the Cobalt Strike client.

## ICMP UDC2 Debug Example Quick Start Guide

To get started with the ICMP UDC2 example, follow the instructions below. Note that you should have the `Debug` solution configuration selected for this.  

1. If you don't already have a UDC2 debug listener set up: In your Cobalt Strike client, open the listeners page and create a new UDC2 listener. Give it a name like "udc2-debug", leave the BOF field empty, tick the "Debug only" option, and click Save. Take note of the UDC2 listener port.
2. In the icmp_udc2_bof.cpp file, find the following line: gUdc2State.serverAddr = "127.0.0.1"; // TODO: SET THIS TO YOUR UDC2 SERVER ADDRESS
3. Change the gUdc2State.serverAddr to the IP address where your ICMP UDC2 server will be listening (See step 9)
4. In the main function in icmp_udc2_bof.cpp, find the following line: `LPCSTR              UDC2_DEBUG_HOST = "127.0.0.1"; // SET THIS TO YOUR UDC2 LISTENER HOST (Team Server)`
5. Set the UDC2_DEBUG_HOST to your team server IP where the debug udc2 listener is listening
6. In the main function in icmp_udc2_bof.cpp, find the following line: `USHORT              UDC2_DEBUG_PORT = 2222; // SET THIS TO YOUR UDC2 LISTENER PORT`
7. Set the UDC2_DEBUG_PORT to the port you used for your udc2 debug listener in step 1
8. For specific usage instructions of the icmp udc2 server python script, refer to the documentation in the server\\README.md file. In the interim, run the python script with the following options: `python3 icmp_udc2_server.py --ts-addr YOUR_TS_UDC2_LISTENER_IP --ts-port YOUR_TS_UDC2_LISTENER_PORT`
9. If you are running the python script under WSL on Windows, or from a linux environment, make sure that you disable automatic ICMP echo replies, as this will interfere with Beacon communication. To temporarily disable ICMP echo replies, use either of the following commands: `sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1` or `sudo echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all`. Note you may need to disable icmp echo replies on Windows if you are running the script from Windows.
10. The setup is now complete and you can click on the Run button with Local Windows Debugger in Visual Studio to run the project under the debugger. You should now see a new Beacon show up in your Beacon list in the Cobalt Strike client. This Beacon is communicating with the python UDC2 server using the ICMP protocol, which you can verify with WireShark. 

## Architecture

### Core Components

#### Global State Management
```cpp
typedef struct _UDC2_STATE {
    PacketList packetList;      // Linked list of outbound packets
    ULONG beaconId;             // Unique Beacon identifier
    const char* serverAddr;     // Target server IP address
    BOOL initialized;           // Initialization status
} UDC2_STATE;
```

#### Packet Structure
```cpp
typedef struct _ICMP_HEADER {
    ULONG Type;                // Packet type (Beacon data, request, ack, task)
    ULONG Identifier;          // Beacon ID for correlation
    ULONG Flags;               // Fragmentation and control flags
    ULONG FragmentIndex;       // Fragment sequence number
} ICMP_HEADER;
```

### Communication Protocol

#### Packet Types
- `TYPE_BEACON_DATA (0)`: Outbound Beacon data
- `TYPE_REQUEST_TS_REPLY (1)`: Request for team server response
- `TYPE_ACK (2)`: Acknowledgment packet
- `TYPE_TASK (3)`: Inbound task data

#### Fragmentation Flags
- `FRAGMENTED (0x00000001)`: Indicates fragmented payload
- `FIRST_FRAG (0x00000010)`: First fragment in sequence
- `LAST_FRAG (0x00000100)`: Last fragment in sequence
- `FETCH_FRAG (0x00001000)`: Request for next fragment

#### Protocol Flow
1. Beacon sends a frame wrapped in an ICMP packet (fragmenting if necessary)
2. UDC2 server processes frame data from ICMP echo request (de-fragmenting if necessary) 
3. UDC2 server checks packet type, and for TYPE_BEACON_DATA, replies with a TYPE_ACK packet in an ICMP echo reply to the original echo request after forwarding on the Beacon data to the team server
4. Beacon validates that it receives a TYPE_ACK in reply
5. Beacon now sends another ICMP echo request with a TYPE_REQUEST_TS_REPLY to get the team server response to the Beacon data it previously sent
6. UDC2 server assembles the task data it received from the team server, fragmenting if necessary, and sends either the first frag or the complete payload if it doesn't need fragmentation
7. Beacon receives the TYPE_TASK packet and checks if it is fragmented. If it is fragmented, Beacon sends additional echo requests with TYPE_REQUEST_TS_REPLY and the FETCH_FRAG flag set until it has received all the fragmented data.
8. Beacon processes the task data and performs the task and the cycle repeats

## Configuration

### Server Configuration
```cpp
// Update this to your UDC2 server address
gUdc2State.serverAddr = "127.0.0.1"; // Change to your server IP
```

### Protocol Constants
```cpp
#define MAX_ICMP_PAYLOAD_SIZE       65507      // Maximum ICMP payload
#define MAX_ICMP_PACKET_SIZE        65535      // Maximum ICMP packet
#define MAX_RETRY_ATTEMPTS          3          // Retry attempts
#define ICMP_TIMEOUT_MS             1000       // Timeout in milliseconds
#define BEACON_ID_MASK              0x0000FFFF // Beacon ID mask
```

### Debug Testing

#### Prerequisites
1. Set up UDC2 debug listener in Cobalt Strike
2. Update debug configuration:
```cpp
LPCSTR UDC2_DEBUG_HOST = "127.0.0.1";     // Your team server IP
USHORT UDC2_DEBUG_PORT = 2222;            // Your UDC2 listener port
```

## API Reference

### Core Functions

#### `int udc2Proxy(const char* sendBuf, int sendBufLen, char* recvBuf, int recvBufMaxLen)`
Main proxy function for relaying Beacon traffic.

**Parameters:**
- `sendBuf`: Points to Beacon frame data that needs to be sent out
- `sendBufLen`: The total length of the frame data
- `recvBuf`: Points to Beacon memory that you should copy response frame data to
- `recvBufMaxLen`: The max size of the recv buffer

**Returns:** Number of bytes received on success, negative error code on failure

#### `void udc2Close()`
Cleanup function for session termination.

#### `int sendIcmpData(void* buffer, int length, BOOL ackOnly, void** ppvData)`
Send ICMP data with optional response handling.

**Parameters:**
- `buffer`: Data buffer to send
- `length`: Length of data
- `ackOnly`: TRUE for acknowledgment only, FALSE to return data
- `ppvData`: Pointer to store reply data (if ackOnly is FALSE)

### Packet Management

#### `int createIcmpPackets(int len)`
Create ICMP packets with proper fragmentation.

#### `int sendIcmpPackets(const char* data, int len)`
Send all created packets with payload data.

#### `int recvReply(char* read, int readLen)`
Receive and process server replies.

## Error Handling

### Error Codes
```cpp
#define UDC2_SUCCESS                 0   // Operation successful
#define UDC2_ERROR_INVALID_PARAM    -1   // Invalid parameter
#define UDC2_ERROR_MEMORY_ALLOC     -2   // Memory allocation failure  
#define UDC2_ERROR_NETWORK          -3   // Network operation failure
#define UDC2_ERROR_TIMEOUT          -4   // Operation timeout
#define UDC2_ERROR_PROTOCOL         -5   // Protocol violation
#define UDC2_ERROR_FRAGMENTATION    -6   // Fragmentation error
```

## Dependencies

### Windows APIs
- **IPHLPAPI.dll**: ICMP operations (`IcmpCreateFile`, `IcmpSendEcho`, `IcmpCloseHandle`)
- **KERNEL32.dll**: Memory management (`HeapAlloc`, `HeapFree`, `GetProcessHeap`)
- **WS2_32.dll**: Network utilities (`inet_addr`)
- **NTDLL.dll**: System utilities (`RtlRandomEx`)

### Headers Required
```cpp
#include <Windows.h>      // Windows base types
#include <iphlpapi.h>     // ICMP API functions  
#include <IcmpAPI.h>      // ICMP structures
```

## Limitations

### Technical Constraints
- **Payload Size**: Limited by ICMP packet size (65KB maximum)
- **Network Dependencies**: Requires ICMP traffic to be allowed

### Operational Constraints
- **Detection Risk**: ICMP traffic is commonly monitored
- **Performance**: Higher latency compared to TCP/UDP
- **Reliability**: ICMP is connectionless and may be dropped

## License

Apache 2.0 (see LICENSE file in udc2-vs main template folder)

## References

- [Cobalt Strike Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm)
- [BOF Development Guide](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm)
- [ICMP Protocol Specification (RFC 792)](https://tools.ietf.org/html/rfc792)
- [Windows ICMP API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/icmpapi/)

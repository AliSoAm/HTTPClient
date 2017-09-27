#include "HTTPClient.h"
#include <iostream>
using namespace std;
int main()
{
    HTTPClient::BasicHTTPClient a("GET", "http://localhost", "text/html");
    a.finishRequest();
    while (!a.isRecvCompleted())
    {
        char b[21];
        int recvLen = a.recv(b, 20);
        b[20] = 0;
        b[recvLen] = 0;
        cout << b;
    }
    return EXIT_SUCCESS;
}

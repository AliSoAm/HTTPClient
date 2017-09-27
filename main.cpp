#include "HTTPClient.h"
#include <iostream>
using namespace std;
int main(int argc, char** argv)
{
    uint32_t i = 0, j = 0;
    while (true)
    {
        try
        {
            i++;
            string body;
            int code;
            tie(code, body) = HTTPClient::HTTPGet(argv[1], "text/html", {{"accept", "*/*"}});
            cout << code <<     endl
                 << body << endl;
             j++;
             cout << j << "/" << i << endl
                  << "-----------------" << endl;
        }
        catch (exception& e)
        {
            cout << endl
                 << "------------------------------------------" << endl
                 <<  "Exception: " << e.what() << endl;
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

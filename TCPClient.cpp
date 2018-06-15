#include "TCPClient.h"
#include <stdexcept>
#include <cstring>

using namespace std;

extern void* TCPClientCreateSocket(const string& address, unsigned short int port, bool secure);
extern void TCPClientSend(void* context, const char* buffer, size_t length);
extern size_t TCPClientRecv(void* context, char* buffer, size_t length);
extern void TCPClientClose(void* context);

TCPClientException::TCPClientException(const char* what)
{
    strncpy(what_, what, 49);
    what_[49] = '\0';
}

const char* TCPClientException::what() const noexcept
{
    return what_;
}

TCPClient::TCPClient(const string& address, uint16_t port, bool secure): open(false), secure_(secure)
{
  context = TCPClientCreateSocket(address, port, secure);
}

TCPClient::~TCPClient()
{
  Close();
}

void TCPClient::Send(const char* buffer, size_t length)
{
  if (!isOpen())
    throw TCPClientException("Receiving from closed connection");
  TCPClientSend(context, buffer, length);
}

size_t TCPClient::Recv(char* buffer, size_t length)
{
  if (!isOpen())
    throw TCPClientException("Receiving from closed connection");
  return TCPClientRecv(context, buffer, length);
}

bool TCPClient::isOpen() const
{
  return open;
}

void TCPClient::closeContext()
{
  if (isOpen())
  {
    open = false;
    TCPClientClose(context);
  }
}

void TCPClient::Close()
{
  closeContext();
}

bool TCPClient::isSecure()
{
  return secure_;
}
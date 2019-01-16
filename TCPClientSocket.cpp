#include "TCPClient.h"
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <iostream>
#include <netdb.h>
 #include <unistd.h>
using namespace std;
#ifdef SECURE_TCP
const char certificate[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\r\n"
  "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\r\n"
  "DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\r\n"
  "PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\r\n"
  "Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n"
  "AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\r\n"
  "rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\r\n"
  "OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\r\n"
  "xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\r\n"
  "7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\r\n"
  "aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\r\n"
  "HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\r\n"
  "SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\r\n"
  "ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\r\n"
  "AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\r\n"
  "R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\r\n"
  "JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\r\n"
  "Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\r\n"
  "-----END CERTIFICATE-----\r\n";

static void my_debug( void *ctx, int level, const char *file, int line, const char *str )
{
  ((void) level);
  printf("%s:%04d: %s", file, line, str);
}

#endif

static int myRecv(void *ctx, unsigned char *buffer, size_t length)
{
  int socketFD = *(int*)ctx;
  return recv(socketFD, buffer, length, 0);
}

static int mySend(void *ctx, const unsigned char *buffer, size_t length)
{
  int socketFD = *(int*)ctx;
  return send(socketFD, buffer, length, MSG_NOSIGNAL);
}

TCPClientException::TCPClientException(const char* what)
{
  strncpy(what_, what, 49);
  what_[49] = '\0';
}

const char* TCPClientException::what() const noexcept
{
  return what_;
}

#ifdef SECURE_TCP
TCPClient::TCPClient(const string& address, uint16_t port, bool secure): open(false), peerClosed(false), secure_(secure), TLSInit(false)
{
  try
  {
    createSocket(address, port);
  }
  catch (...)
  {
    Close();
    throw;
  }
}
#else
TCPClient::TCPClient(const string& address, uint16_t port, bool secure): open(false), peerClosed(false)
{
  if (secure)
    throw TCPClientException("Secure TCP is not supported");
  try
  {
    createSocket(address, port);
  }
  catch (...)
  {
    Close();
    throw;
  }
}
#endif

TCPClient::~TCPClient()
{
  Close();
}

int TCPClient::normalSend(const char* buffer, size_t length)
{
  return mySend(&socketFD, (const unsigned char*)buffer, length);
}

void TCPClient::Send(const char* buffer, size_t length)
{
  if (!isOpen())
    throw TCPClientException("Sending to closed connection");
  if (length < 1)
    return;
  int sentLen;
#ifdef SECURE_TCP
  if (secure_)
    sentLen = TLSSend(buffer, length);
  else
    sentLen = normalSend(buffer, length);
#else
  sentLen = normalSend(buffer, length);
#endif
  if (sentLen != length)
  {
    peerClosed = true;
    Close();
    throw TCPClientException("Send faild");
  }
}

int TCPClient::normalRecv(char* buffer, size_t length)
{
  return myRecv(&socketFD, (unsigned char*)buffer, length);
}

size_t TCPClient::Recv(char* buffer, size_t length)
{

  if (!isOpen())
    throw TCPClientException("Receiving from closed connection");
  if (length < 1)
    return length;
  int recvLen;
#ifdef SECURE_TCP
  if (secure_)
    recvLen =  TLSRecv(buffer, length);
  else
    recvLen = normalRecv(buffer, length);
#else
    recvLen = normalRecv(buffer, length);
#endif
  if (recvLen <= 0)
  {
    peerClosed = true;
    Close();
    throw TCPClientException("Receive failed");
  }
  return recvLen;
}

bool TCPClient::isOpen() const
{
  return open;
}

void TCPClient::closeSocket()
{
  if (isOpen())
  {
    open = false;
    close(socketFD);
  }
}
void TCPClient::Close()
{
#ifdef SECURE_TCP
  if (secure_)
    TLSExit();
#endif
  peerClosed = true;
  closeSocket();
}

void TCPClient::createSocket(const string& address, uint16_t port)
{
#ifdef SECURE_TCP
  if (secure_)
    createTLSSocket(address, port);
  else
    createNormalSocket(address, port);
#else
  createNormalSocket(address, port);
#endif
}

void TCPClient::createNormalSocket(const string& address, uint16_t port)
{
  int rc, err = ERANGE;
  struct hostent hbuf;
  struct hostent *server;
  size_t len = 512;
  void* tmp = NULL;
  do
  {
    len *= 2;
    tmp = (char*)realloc(tmp, len);
    if (tmp == NULL)
    {
      free(tmp);
      throw TCPClientException("malloc problem");
    }
    char* buf = (char*)tmp;
    rc = gethostbyname_r(address.c_str(), &hbuf, buf, len, &server, &err);
  } while (err == ERANGE && len <= 80 * 1024);
  if (0 != rc || NULL == server)
  {
    free(tmp);
    throw TCPClientException("Cant resolve host");
  }
  struct sockaddr_in serveraddr;
  memset(&serveraddr, 0, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  memcpy(&serveraddr.sin_addr.s_addr, server->h_addr, server->h_length);
  free(tmp);
  serveraddr.sin_port = htons(port);
  socketFD = socket(AF_INET, SOCK_STREAM, 0);
  if (socketFD < 0)
    throw TCPClientException("ERROR opening socket");
  open = true;
  int timeout = 5 * 1000;
  //if (setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0)
    //throw TCPClientException("ERROR setsockopt SO_RCVTIMEO");
  //if (setsockopt(socketFD, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) < 0)
    //throw TCPClientException("ERROR setsockopt SO_SNDTIMEO");
  if (connect(socketFD, (const sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
    throw TCPClientException("ERROR connecting");
}

#ifdef SECURE_TCP
int TCPClient::TLSSend(const char* buffer, size_t length)
{
  int ret = -1;
  do
    ret = mbedtls_ssl_write(&ssl, (unsigned char*)buffer, length);
  while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  return ret;
}

int TCPClient::TLSRecv(char* buffer, size_t length)
{
  int ret = -1;
  do
    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buffer, length);
  while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  return ret;
}

void TCPClient::createTLSSocket(const string& address, uint16_t port)
{
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  //mbedtls_debug_set_threshold(10);
  TLSInit = true;
  if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)0xA023EE00 , 30) != 0)
    throw TCPClientException("mbedtls_ctr_drbg_seed failed");
  if (mbedtls_x509_crt_parse(&cacert, (const unsigned char *)certificate,  strlen(certificate) + 1) != 0)
    throw TCPClientException("mbedtls_x509_crt_parse failed");
  if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    throw TCPClientException("mbedtls_ssl_config_defaults failed");
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
  if (mbedtls_ssl_setup(&ssl, &conf) != 0)
    throw TCPClientException("mbedtls_ssl_setup failed");
  if (mbedtls_ssl_set_hostname(&ssl, address.c_str()) != 0)
    throw TCPClientException("mbedtls_ssl_set_hostname failed");
  createNormalSocket(address, port);
  mbedtls_ssl_set_bio(&ssl, &socketFD, mySend, myRecv, NULL);
  int ret;
  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
      throw TCPClientException("mbedtls_ssl_handshake failed");
}

void TCPClient::TLSExit()
{
  if (TLSInit)
  {
    TLSInit = false;
    if (open && !peerClosed)
      mbedtls_ssl_close_notify(&ssl);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
  }
}

#endif

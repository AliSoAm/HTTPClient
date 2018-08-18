#pragma once

#include <cstdint>
#include <string>
#include <exception>
#include <initializer_list>
#ifdef SECURE_TCP
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#endif

typedef int Socket;
class TCPClientException: public std::exception
{
public:
  TCPClientException(const char* what);
  virtual const char* what() const noexcept;
private:
  char what_[50];
};

class TCPClient
{
public:
  TCPClient (const std::string& address, std::uint16_t port, bool secure = false);
  ~TCPClient();
  void Send (const char* buffer, size_t length);
  size_t Recv (char* buffer, size_t length);
  bool isOpen () const;
  void Close ();
private:
  Socket socketFD;
  bool open;
  bool peerClosed;
  void createSocket (const std::string& address, std::uint16_t port);
  void createNormalSocket (const std::string& address, std::uint16_t port);
       
  void closeSocket ();
       
  int normalRecv (char* buffer, size_t length);
  int normalSend (const char* buffer, size_t length);

#ifdef SECURE_TCP
  bool secure_;
  bool TLSInit;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
  void createTLSSocket (const std::string& address, std::uint16_t port);
  int TLSRecv (char* buffer, size_t length);
  int TLSSend (const char* buffer, size_t length);
  void TLSExit ();
#endif

};

#pragma once

#include <cstdint>
#include <string>
#include <exception>
#include <initializer_list>

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
                          TCPClient                       (const std::string& address,
                                                           std::uint16_t port,
                                                           bool secure = false);
                          ~TCPClient();
  void                    Send                            (const char* buffer,
                                                           size_t length);
  size_t                  Recv                            (char* buffer,
                                                           size_t length);
  bool                    isOpen                          ()                                     const;
  void                    Close                           ();
  bool                    isSecure();
private:
  void*                   context;
  bool                    open;
  bool                    secure_;
  void                    closeContext                    ();
};

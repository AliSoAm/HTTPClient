#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H
#include <map>
#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include "TCPClient.h"

namespace HTTPClient{

  class HTTPClientException: public std::exception
  {
  public:
    HTTPClientException() noexcept;
    HTTPClientException(const char* what) noexcept;
    virtual const char* what() const noexcept;
  private:
    char what_[40];
  };
  typedef std::map<std::string, std::string> HeaderFields;
  typedef std::pair<std::string, std::string> Parameter;

  class BasicHTTPClient
  {
  public:
    BasicHTTPClient(const std::string& method, const std::string& URL, const std::string& contentType = "text/html", const std::initializer_list<std::pair<std::string, std::string>>& headerFields = {});
    BasicHTTPClient(const std::string& method, const std::string& URL, const std::string& contentType, const std::initializer_list<std::pair<std::string, std::string>>& headerFields, size_t contentLength);
    BasicHTTPClient(const std::string& method, const std::string& URL, const std::string& contentType = "text/html", const std::vector<std::pair<std::string, std::string>>& headerFields = {});
    BasicHTTPClient(const std::string& method, const std::string& URL, const std::string& contentType, const std::vector<std::pair<std::string, std::string>>& headerFields, size_t contentLength);

    std::string URI();
    int responseCode();
    HeaderFields header();
    void finishRequest();
    void put(const char* buffer, size_t length);
    bool isRecvCompleted() const;
    size_t get(char* buffer, size_t length);
  private:
    std::shared_ptr<TCPClient>          TCP;
    char                                remainingBuffer[150];
    size_t                              remainingBufferLen;
    size_t                              remainingChunkLen;
    size_t                              contentReceived;
    bool                                recvComplete;
    bool                                chunkedTransfer_;
    size_t                              contentLength_;
    bool                                responseHeaderReceived;
    int                                 responseCode_;
    HeaderFields                        header_;
    bool                                chunkedSend_;
    std::string                         URI_;

    std::tuple<bool, std::string, std::uint16_t, std::string> splitAddressPortURI(const std::string& URL);
    void sendHeader(const std::string& method, const std::string& URI, const std::string& host, const std::string& contentType, const std::vector<std::pair<std::string, std::string>>& headerFields);
    void sendHeader(const std::string& method, const std::string& URI, const std::string& host, const std::string& contentType, const std::vector<std::pair<std::string, std::string>>& headerFields, size_t contentLength);
    void ParseResponse();
    void ParseResponseHeader(const std::string& header);


    void chunkedSend(const char* buffer, size_t length);
    void normalSend(const char* buffer, size_t length);

    size_t chunkedRecv(char* buffer, size_t length);
    size_t normalRecv(char* buffer, size_t length);
    size_t recvRemainingBuffer(char* buffer, size_t length, size_t recvedLen);
    size_t recvRemainingChunk(char* buffer, size_t length, size_t recvedLen);
    void completeCurrentChunk();
    void prepareForNextChunk();
  };
  std::tuple<int, std::string> HTTPGet(const std::string& URL, const std::string& content_type = "text/html", const std::initializer_list<std::pair<std::string, std::string>>& headerFields = {});
  std::tuple<int, std::string> HTTPPost(const std::string& URL, const std::string& content_type = "text/html", const std::initializer_list<std::pair<std::string, std::string>>& headerFields = {}, const std::string& body = "");

  // TODO add function without content length
  std::shared_ptr<BasicHTTPClient> HTTPClient(const std::string& username, const std::string& password, const std::string& method, const std::string& URL, const std::string& content_type = "text/html", const std::initializer_list<std::pair<std::string, std::string>>& headerFields = {}, const std::string& cnonce = "abcdefg", unsigned int nonceCount = 1);
  std::shared_ptr<BasicHTTPClient> HTTPClient(const std::string& username, const std::string& password, const std::string& method, const std::string& URL, const std::string& content_type = "text/html", const std::initializer_list<std::pair<std::string, std::string>>& headerFields = {}, size_t contentLength = 0, const std::string& cnonce = "abcdefg", unsigned int nonceCount = 1);
}
#endif

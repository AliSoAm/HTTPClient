#include "HTTPClient.h"
#include <tuple>
#include <cstring>
#include <array>
#include <algorithm>
#include <sstream>
#include "md5.h"

using namespace std;
namespace HTTPClient
{
  HTTPClientException::HTTPClientException() noexcept
  {
    strcpy(what_, "HTTP client exception");
  }

  HTTPClientException::HTTPClientException(const char* what) noexcept
  {
    strncpy(what_, what, 40);
    what_[39] = 0;
  }

  const char* HTTPClientException::what() const noexcept
  {
    return what_;
  }

  BasicHTTPClient::BasicHTTPClient(const string& method, const string& URL, const string& contentType
    , const initializer_list<pair<string, string>>& headerFields)
    : BasicHTTPClient(method, URL, contentType, vector<pair<string, string>>(headerFields))
  {
  }

  BasicHTTPClient::BasicHTTPClient(const string& method, const string& URL, const string& contentType
    , const initializer_list<pair<string, string>>& headerFields, size_t contentLength)
    : BasicHTTPClient(method, URL, contentType, vector<pair<string, string>>(headerFields), contentLength)
  {
  }

  BasicHTTPClient::BasicHTTPClient(const string& method, const string& URL, const string& contentType
    , const vector<pair<string, string>>& headerFields)
    : remainingChunkLen(0), contentReceived(0), recvComplete(false), chunkedTransfer_(false)
    , contentLength_(0), responseHeaderReceived(false), chunkedSend_(true)
  {
    string host;
    uint16_t port;
    bool HTTPS;
    tie (HTTPS, host, port, URI_) = splitAddressPortURI(URL);
    TCP = make_shared<TCPClient>(host, port, HTTPS);
    sendHeader(method, URI_, host, contentType, headerFields);
  }

  BasicHTTPClient::BasicHTTPClient(const string& method, const string& URL, const string& contentType
    , const vector<pair<string, string>>& headerFields, size_t contentLength)
    : remainingChunkLen(0), contentReceived(0), recvComplete(false), chunkedTransfer_(false)
    , contentLength_(0), responseHeaderReceived(false), chunkedSend_(false)
  {
    string host;
    uint16_t port;
    bool HTTPS;
    tie (HTTPS, host, port, URI_) = splitAddressPortURI(URL);
    TCP = make_shared<TCPClient>(host, port, HTTPS);
    sendHeader(method, URI_, host, contentType, headerFields, contentLength);
  }

  int BasicHTTPClient::responseCode()
  {
    if (!responseHeaderReceived)
      ParseResponse();
    return responseCode_;
  }
  tuple<bool, string, uint16_t, string> BasicHTTPClient::splitAddressPortURI(const string& URL)
  {
    string protocole = URL.substr(0, 8);
    transform(protocole.begin(), protocole.end(), protocole.begin(), ptr_fun <int, int> (toupper));
    bool HTTPS_ = false;
    if (protocole.compare(0, 8, "HTTPS://") == 0)
       HTTPS_ = true;
    else if (protocole.compare(0, 7, "HTTP://") != 0)
      throw HTTPClientException("Bad URL");
    string URN;
    if (HTTPS_)
      URN = URL.substr(8);
    else
      URN = URL.substr(7);
    size_t slashPos = URN.find("/");
    string host = URN.substr(0, slashPos);
    if (host == "")
      throw HTTPClientException("Bad URL");
    URN.erase(0, slashPos);
    if (URN == "")
      URN = "/";
    uint16_t port;
    if (HTTPS_)
      port = 443;
    else
      port = 80;
    size_t colonPos = host.find(":");
    if (colonPos != string::npos)
    {
      port = stoi(host.substr(colonPos + 1));
      host.erase(colonPos);
    }
    return make_tuple(HTTPS_, host, port, URN);
  }

  std::string BasicHTTPClient::URI()
  {
    return URI_;
  }

  void BasicHTTPClient::sendHeader(const string& method, const string& URI, const string& host
    , const string& contentType, const vector<pair<string, string>>& headerFields)
  {
    stringstream response;
    response << method << " " << URI << " " << "HTTP/1.1" << "\r\n"
         << "host: " << host << "\r\n"
         << "Content-type: " << contentType << "\r\n";
    for (auto& headerField : headerFields)
      response << headerField.first << ":" << headerField.second << "\r\n";
      response << "Connection: close\r\n"
           << "Transfer-Encoding: chunked\r\n"
           << "\r\n";
    TCP->Send(response.str().c_str(), response.str().length());
  }

  void BasicHTTPClient::sendHeader(const string& method, const string& URI, const string& host
    , const string& contentType, const vector<pair<string, string>>& headerFields, size_t contentLength)
  {
    stringstream response;
    response << method << " " << URI << " " << "HTTP/1.1" << "\r\n"
         << "host: " << host << "\r\n"
         << "content-type: " << contentType << "\r\n";
    for (auto& headerField : headerFields)
      response << headerField.first << ":" << headerField.second << "\r\n";
      response << "Connection: close\r\n"
           << "content-length:" << contentLength << "\r\n"
           << "\r\n";
    TCP->Send(response.str().c_str(), response.str().length());
  }

  void BasicHTTPClient::chunkedSend(const char* buffer, size_t length)
  {
    char sendBuffer[100];
    size_t remainedLength = length;
    while (remainedLength > 0)
    {
      if (remainedLength > (100 - 7))
      {
        sprintf(sendBuffer, "%03x\r\n", 100 - 7);
        memcpy(sendBuffer + 5, buffer, 100 - 7);
        sendBuffer[100 - 2] = '\r';
        sendBuffer[100 - 1] = '\n';
        TCP->Send(sendBuffer, 100);
        buffer += 100 - 7;
        remainedLength -= 100 - 7;
      }
      else
      {
        sprintf(sendBuffer, "%03x\r\n", remainedLength);
        memcpy(sendBuffer + 5, buffer, remainedLength);
        sendBuffer[remainedLength + 5] = '\r';
        sendBuffer[remainedLength + 6] = '\n';
        TCP->Send(sendBuffer, remainedLength + 7);
        buffer += remainedLength;
        remainedLength = 0;
      }
    }
  }

  void BasicHTTPClient::normalSend(const char* buffer, size_t length)
  {
    TCP->Send(buffer, length);
  }

  void BasicHTTPClient::put(const char* buffer, size_t length) //TODO allow before request finish only
  {
    if (chunkedSend_)
      chunkedSend(buffer, length);
    else
      normalSend(buffer, length);
  }

  size_t BasicHTTPClient::get(char* buffer, size_t length)//TODO allow after request finish only
  {
    if (!responseHeaderReceived)
      ParseResponse();

    if (isRecvCompleted())
      throw HTTPClientException();
    size_t recvedLen = 0;
    if (chunkedTransfer_)
      recvedLen = chunkedRecv(buffer, length);
    else
      recvedLen = normalRecv(buffer, length);
    return recvedLen;
  }

  size_t BasicHTTPClient::chunkedRecv(char* buffer, size_t length)
  {
    size_t recvedLen = 0;
    while (recvedLen < length && !isRecvCompleted())
    {
      if (remainingChunkLen > 0)
      {
        if (remainingBufferLen > 0)
        {
          recvedLen = recvRemainingBuffer(buffer, length, recvedLen);
        }
        else
        {
          recvedLen = recvRemainingChunk(buffer, length, recvedLen);
//          if (remainingChunkLen > 0 && length != recvedLen)
//            throw HTTPClientException();
        }
        if (remainingChunkLen == 0)
          completeCurrentChunk();
      }
      else
      {
        prepareForNextChunk();
      }
    }
    return recvedLen;
  }

  size_t BasicHTTPClient::normalRecv(char* buffer, size_t length)
  {
    size_t recvedLen = 0;
    if (remainingBufferLen > 0)///XXX
    {
      size_t readLen = min(remainingBufferLen, length);
      memcpy(buffer, remainingBuffer, readLen);
      memmove(remainingBuffer, remainingBuffer + readLen, remainingBufferLen - readLen);
      recvedLen = readLen;
      remainingBufferLen -= recvedLen;
      contentReceived += recvedLen;
    }
    while (length > recvedLen && contentReceived < contentLength_)
    {
      size_t readLen = min(length - recvedLen, contentLength_ - contentReceived);
      size_t recvLen = TCP->Recv(buffer + recvedLen, readLen);
      if (recvLen <= 0)
        throw HTTPClientException();
      contentReceived += recvLen;
      recvedLen += recvLen;
    }
    if (contentReceived >= contentLength_)
      recvComplete = true;
    return recvedLen;
  }

  size_t BasicHTTPClient::recvRemainingBuffer(char* buffer, size_t length, size_t recvedLen)
  {
    size_t readyLen = min(remainingChunkLen, remainingBufferLen);
    size_t readLen = min(length - recvedLen, readyLen);
    memcpy(buffer + recvedLen, remainingBuffer, readLen);
    recvedLen += readLen;
    remainingChunkLen -= readLen;
    remainingBufferLen -= readLen;
    memmove(remainingBuffer, remainingBuffer + readLen, remainingBufferLen);
    remainingBuffer[remainingBufferLen] = 0;
    return recvedLen;
  }

  size_t BasicHTTPClient::recvRemainingChunk(char* buffer, size_t length, size_t recvedLen)
  {
    int recvLen = 0;
    size_t readLen = min((length - recvedLen), remainingChunkLen);
    recvLen = TCP->Recv(buffer + recvedLen, readLen);
//    if (recvLen != readLen)
//      throw HTTPClientException("Bad HTTP chunk3");
    remainingChunkLen -= recvLen;
    recvedLen += recvLen;
    return recvedLen;
  }

  void BasicHTTPClient::completeCurrentChunk()
  {
    if (remainingBufferLen >= 2)
    {
      memmove(remainingBuffer, remainingBuffer + 2, remainingBufferLen - 2);
      remainingBufferLen -= 2;
      remainingBuffer[remainingBufferLen] = 0;
    }
    else if (remainingBufferLen == 1)
    {
      char buff[1];
      remainingBufferLen = 0;
      remainingBuffer[0] = 0;
      if (TCP->Recv(buff, 1) != 1)
        throw HTTPClientException("Bad HTTP chunk4");
    }
    else
    {
      char buff[2];
      if (TCP->Recv(buff, 2) != 2)
        throw HTTPClientException("Bad HTTP chunk5");
    }
  }

  void BasicHTTPClient::prepareForNextChunk()
  {
    int recvLen = remainingBufferLen;
    size_t startChunk = 0;
    string chunk(remainingBuffer);
    if (chunk.find("\r\n") == string::npos)
    {
      recvLen = TCP->Recv(remainingBuffer, 99);
      if (recvLen == 0)
        throw HTTPClientException("Bad HTTP chunk1");
      remainingBuffer[recvLen] = 0;
      chunk += remainingBuffer;
      startChunk = chunk.find("\r\n") + 2 - remainingBufferLen;
    }
    else
    {
      startChunk = chunk.find("\r\n") + 2;
    }
    if (chunk.find("\r\n") == string::npos)
      throw HTTPClientException("Bad HTTP chunk2");
    remainingChunkLen = strtol(chunk.c_str(), NULL, 16);
    if (remainingChunkLen == 0)
    {
      recvComplete = true;
      return;
    }
    remainingBufferLen = recvLen - startChunk;
    memmove(remainingBuffer, remainingBuffer + startChunk, remainingBufferLen);
    remainingBuffer[remainingBufferLen] = 0;
    return;
  }

  bool BasicHTTPClient::isRecvCompleted() const
  {
    return recvComplete;
  }

  void BasicHTTPClient::finishRequest() //TODO Only execute once
  {
    if (chunkedSend_)
      TCP->Send("0\r\n\r\n", 5);
  }

  void BasicHTTPClient::ParseResponse()
  {
    char buffer[100];
    string packet, header, body;
    size_t headerEnd = 0;
    size_t bufferEnd = 0;
    int recvLen = 0;
    do
    {
      recvLen = TCP->Recv(buffer, 99);
      if (recvLen <= 0)
      {
        //XXX
      }
      buffer[recvLen] = '\0';
      bufferEnd += recvLen;
      packet += buffer;
      headerEnd = packet.find("\r\n\r\n");
    } while (headerEnd == string::npos);
    size_t payloadStart = recvLen - (bufferEnd - (headerEnd + 4));
    remainingBufferLen = bufferEnd - (headerEnd + 4);
    memcpy(remainingBuffer, buffer + payloadStart, remainingBufferLen);
    remainingBuffer[remainingBufferLen] = 0;
    header = packet.substr(0, headerEnd);
    int code;
    HeaderFields headerFields;
    ParseResponseHeader(header);
  }

  void BasicHTTPClient::ParseResponseHeader(const string& header)
  {
    stringstream headerStream(header), lineStream;
    string line, methodStr;
    getline(headerStream, line);
    lineStream.str(line);
    lineStream.exceptions(ios::failbit | ios::badbit);
    string protocole;
    lineStream >> protocole >> responseCode_;
    if (protocole != "HTTP/1.1")
      throw HTTPClientException("Bad protocole");
    HeaderFields headerFields;
    while (getline(headerStream, line))
    {
      if (line.back() == '\r')
        line.pop_back();
      size_t colonPosition = line.find(":");
      string name = line.substr(0, colonPosition);
      string value = line.substr(colonPosition + 1);
      if (value.front() == ' ')
        value.erase(value.begin());
      if (colonPosition == string::npos)
        throw HTTPClientException("Bad header format");

      name.erase(remove(name.begin(), name.end(), ' '), name.end());
      //value.erase(remove(value.begin(), value.end(), ' '), value.end());
      transform(name.begin(), name.end(), name.begin(), [&](char ch) -> char {if (ch >= 'A' && ch <= 'Z') ch += 32; return ch;});
      //transform(value.begin(), value.end(), value.begin(), [&](char ch) -> char {if (ch >= 'A' && ch <= 'Z') ch += 32; return ch;});
      header_.emplace(name, value);
      if (name == "transfer-encoding" && value == "chunked")
          chunkedTransfer_ = true;
      if (name == "content-length")
        contentLength_ = atoi(value.c_str());
    }
    responseHeaderReceived = true;
  }

  HeaderFields BasicHTTPClient::header()
  {
    return header_;
  }

  tuple<int, string> HTTPGet(const string& URL, const string& content_type
    , const initializer_list<pair<string, string>>& headerFields)
  {
    BasicHTTPClient client("GET", URL, content_type, headerFields, 0);
    client.finishRequest();
    string responseBody;
    while (!client.isRecvCompleted())
    {
      char buffer[51];
      int recvLen = client.get(buffer, 50);
      buffer[recvLen] = 0;
      responseBody += buffer;
    }
    return make_tuple(client.responseCode(), responseBody);
  }

  tuple<int, string> HTTPPost(const string& URL, const string& content_type
    , const initializer_list<pair<string, string>>& headerFields, const string& body)
  {
    BasicHTTPClient client("POST", URL, content_type, headerFields);
    client.put(body.c_str(), body.length());
    client.finishRequest();
    string responseBody;
    while (!client.isRecvCompleted())
    {
      char buffer[51];
      int recvLen = client.get(buffer, 50);
      buffer[recvLen] = 0;
      responseBody += buffer;
    }
    return make_tuple(client.responseCode(), responseBody);
  }

  static map<string, string> parseAuthenticateFields(const string& authenticateFields)
  {
    map<string, string> toBeReturned;
    const char*feilds[4] = {"qop", "realm", "nonce", "algorithm"};
    for (auto feild: feilds)
    {
      size_t posBegin = authenticateFields.find(feild);
      string authenticateField = "";
      if (posBegin != std::string::npos)
      {
        for (; authenticateFields.at(posBegin) != '='; posBegin++);
        for (; authenticateFields.at(posBegin) != '\"'; posBegin++);
        posBegin++;
        size_t posEnd = posBegin;
        for (; authenticateFields.at(posEnd) != '\"'; posEnd++);
        authenticateField = authenticateFields.substr(posBegin, posEnd - posBegin);
      }
      toBeReturned.emplace(feild, authenticateField);
    }
    return toBeReturned;
  }

  static string makeAuthenticateResponse(map<string, string>& authenticateFields
    , const string& username, const string& password, const string& method, const string& cnonce
    , unsigned int nonceCount, const string& digestURI, const string& bodyMD5 = "")
  {
    string HA1;
    if (authenticateFields["algorithm"].empty() || authenticateFields["algorithm"] == "md5")
      HA1 = md5(username + ":" + authenticateFields["realm"]   + ":" + password);
    else if (authenticateFields["algorithm"] == "md5-sess")
      HA1 = md5(md5(username + ":" + authenticateFields["realm"] + ":" + password) + ":" + authenticateFields["nonce"] + ":" + cnonce);
    else
      throw HTTPClientException("Undefined algorithm");
    string HA2;
    char* qop = "auth";
    char nonceCountStr[9];
    if (authenticateFields["qop"].empty() || authenticateFields["qop"].find("auth") != string::npos)
      HA2 = md5(method + ":" + digestURI);
    else if (authenticateFields["qop"].find("auth-int") != string::npos)
    {
      qop = "auth-int";
      HA2 = md5(method + ":" + digestURI + ":" + bodyMD5);
    }
    else
      throw HTTPClientException("Undefined qop");
    string response;
    if (authenticateFields["qop"].empty())
      response = md5(HA1 + ":" + authenticateFields["nonce"] + ":" + HA2);
    else if (authenticateFields["qop"].find("auth") != string::npos || authenticateFields["qop"].find("auth-int") != string::npos)
      response = md5(HA1 + ":" + authenticateFields["nonce"] + ":" + nonceCountStr + ":" + cnonce + ":" + qop + ":" + HA2);
    return "username=\"" + username + "\", realm=\"" + authenticateFields["realm"] + "\", nonce=\""
           + authenticateFields["nonce"] + "\", uri=\"" + digestURI + "\", response=\"" + response + "\", qop="
           + qop + ", nc=" + nonceCountStr + ", cnonce=\"" + cnonce + "\"";
  }

  shared_ptr<BasicHTTPClient> HTTPClient(const string& username, const string& password
    , const string& method, const string& URL, const string& content_type, const initializer_list<pair<string, string>>& headerFields
    , size_t contentLength, const string& cnonce, unsigned int nonceCount)
  {
    BasicHTTPClient client(method, URL, content_type, headerFields, contentLength);
    client.finishRequest();
    array<char, 50> buffer;
    while (!client.isRecvCompleted())
      int recvLen = client.get(buffer.data(), 50);
    if (client.responseCode() == 401 && client.header().count("www-authenticate") > 0)
    {
      vector<pair<string, string>> newHeaderFields(headerFields);
      string authenticate = client.header().at("www-authenticate");
      if (authenticate.compare(0, 5, "Basic") == 0)
      {
        newHeaderFields.push_back(make_pair("Authorization", "Basic " + md5(username + ":" + password)));
        return make_shared<BasicHTTPClient>(method, URL, content_type, newHeaderFields, contentLength);
      }
      else if (authenticate.compare(0, 6, "Digest") == 0)
      {
        auto authenticateFields = parseAuthenticateFields(authenticate);
        string authorizationString = makeAuthenticateResponse(authenticateFields, username, password, method, cnonce, nonceCount, client.URI());
        newHeaderFields.push_back(make_pair("Authorization", "Digest " + authorizationString));
        return make_shared<BasicHTTPClient>(method, URL, content_type, newHeaderFields, contentLength);
      }
      else
        throw HTTPClientException("Undefined authenticate method");
    }
    return make_shared<BasicHTTPClient>(method, URL, content_type, headerFields);
  }
}

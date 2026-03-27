#include "network.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace host
{
namespace
{
int connect_socket(const Endpoint& endpoint)
{
    struct addrinfo hints
    {
    };
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = nullptr;
    const std::string port = std::to_string(endpoint.port);
    const int lookup = getaddrinfo(endpoint.host.c_str(), port.c_str(), &hints, &result);
    if (lookup != 0)
    {
        throw std::runtime_error("getaddrinfo failed for " + endpoint.host + ":" + port + ": " + gai_strerror(lookup));
    }

    int fd = -1;
    for (auto* current = result; current != nullptr; current = current->ai_next)
    {
        fd = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (fd < 0)
        {
            continue;
        }

        if (connect(fd, current->ai_addr, current->ai_addrlen) == 0)
        {
            freeaddrinfo(result);
            return fd;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(result);
    throw std::runtime_error("connect failed for " + endpoint.host + ":" + port);
}
} // namespace

int create_listen_socket(uint16_t port)
{
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        throw std::runtime_error("socket() failed");
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);

    if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
    {
        close(fd);
        throw std::runtime_error("bind() failed on port " + std::to_string(port) + ": " + std::strerror(errno));
    }

    if (listen(fd, 64) != 0)
    {
        close(fd);
        throw std::runtime_error("listen() failed on port " + std::to_string(port));
    }

    return fd;
}

int accept_client(int listen_fd)
{
    const int fd = accept(listen_fd, nullptr, nullptr);
    if (fd < 0)
    {
        throw std::runtime_error("accept() failed");
    }

    return fd;
}

std::string recv_line(int fd)
{
    std::string line;
    char ch = '\0';

    while (true)
    {
        const ssize_t bytes = recv(fd, &ch, 1, 0);
        if (bytes == 0)
        {
            break;
        }

        if (bytes < 0)
        {
            throw std::runtime_error("recv() failed");
        }

        if (ch == '\n')
        {
            break;
        }

        line.push_back(ch);
    }

    return line;
}

void send_line(int fd, const std::string& line)
{
    const std::string payload = line + "\n";
    const char* data = payload.data();
    size_t remaining = payload.size();

    while (remaining > 0)
    {
        const ssize_t sent = send(fd, data, remaining, 0);
        if (sent < 0)
        {
            throw std::runtime_error("send() failed");
        }

        data += sent;
        remaining -= static_cast<size_t>(sent);
    }
}

std::string request_reply(const Endpoint& endpoint, const std::string& message)
{
    const int fd = connect_socket(endpoint);
    try
    {
        send_line(fd, message);
        const std::string reply = recv_line(fd);
        close(fd);
        return reply;
    }
    catch (...)
    {
        close(fd);
        throw;
    }
}

void close_socket(int fd)
{
    if (fd >= 0)
    {
        close(fd);
    }
}
} // namespace host

#ifndef HOST_NETWORK_HPP
#define HOST_NETWORK_HPP

#include <cstdint>
#include <string>

namespace host
{
struct Endpoint
{
    std::string host;
    uint16_t port = 0;
};

int create_listen_socket(uint16_t port);
int accept_client(int listen_fd);
std::string recv_line(int fd);
void send_line(int fd, const std::string& line);
std::string request_reply(const Endpoint& endpoint, const std::string& message);
void close_socket(int fd);
} // namespace host

#endif

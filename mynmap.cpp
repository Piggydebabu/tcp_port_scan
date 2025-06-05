#include <arpa/inet.h>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ThreadPool.h>
#include "SYN_scan.h"

bool is_port_open(char *addr, int port, std::mutex &mutex, std::vector<int> &open_ports);
void port_scan_addr(char *addr);
void port_scan_range(char *addr, int portfrom, int portto);

int main(int argc, char *argv[])
{
    if (argc == 2)
    {
        port_scan_addr(argv[1]);
    }
    else if (argc == 4)
    {
        port_scan_range(argv[1], atoi(argv[2]), atoi(argv[3]));
    }
    else
    {
        std::cout << "Usage: mynmap IP [Port] / [PortFrom] [PortTo]" << std::endl;
    }
    return 0;
}

bool is_port_open(char *addr, int port, std::mutex &mutex, std::vector<int> &open_ports)
{
    int sockfd;
    struct sockaddr_in server_addr;
    bool is_open = false;
    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        std::cerr << "Error creating socket" << std::endl;
        return false;
    }

    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK); // 设置非阻塞模式

    // 设置服务器地址结构
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0)
    {
        close(sockfd);
        is_open = true;
    }
    else if (errno == EINPROGRESS)
    {
        // 连接正在进行中，等待连接完成
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sockfd, &write_fds);

        struct timeval timeout;
        timeout.tv_sec = 0; // 设置超时时间为200ms
        timeout.tv_usec = 200000;

        if (select(sockfd + 1, NULL, &write_fds, NULL, &timeout) > 0)
        {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0)
            {

                close(sockfd);
                is_open = true; // 连接成功
            }
        }
    }

    close(sockfd);
    if (is_open)
    {
        std::lock_guard<std::mutex> lock(mutex);
        open_ports.push_back(port);
    }
    return is_open;
}

void port_scan_addr(char *addr)
{

    float costtime;
    clock_t start, end;
    start = clock();

    ThreadPool pool(std::thread::hardware_concurrency());

    pool.init();

    std::mutex mutex;
    std::vector<int> open_ports;

    for (int i = 1; i < 65536; i++)
    {
        pool.submit([addr, i, &mutex, &open_ports]()
                    { is_port_open(addr, i, mutex, open_ports); });
        // pool.submit([addr, i, &mutex, &open_ports]()
        //             { is_port_open_syn(addr, i, mutex, open_ports); });
    }

    pool.shutdown();

    end = clock();
    costtime = (float)(end - start) / CLOCKS_PER_SEC;

    std::sort(open_ports.begin(), open_ports.end());
    std::cout << "Open ports:" << std::endl;
    for (int port : open_ports)
    {
        std::cout << addr << ":" << port << " open" << std::endl;
    }

    std::cout << "Time taken: " << costtime << " seconds" << std::endl;
}

void port_scan_range(char *addr, int portfrom, int portto)
{
    if (portfrom < 1 || portto > 65535 || portfrom > portto)
    {
        std::cout << "port range error!" << std::endl;
        return;
    }

    ThreadPool pool(4);
    pool.init();

    float costtime;
    clock_t start, end;
    start = clock();

    std::mutex mutex;
    std::vector<int> open_ports;

    for (int i = portfrom; i <= portto; i++)
    {
        pool.submit([addr, i, &mutex, &open_ports]()
                    { is_port_open(addr, i, mutex, open_ports); });
        // pool.submit([addr, i, &mutex, &open_ports]()
        // { is_port_open_syn(addr, i, mutex, open_ports); });
    }

    pool.shutdown();
    end = clock();
    costtime = (float)(end - start) / CLOCKS_PER_SEC;

    std::sort(open_ports.begin(), open_ports.end());
    std::cout << "Open ports:" << std::endl;
    for (int port : open_ports)
    {
        std::cout << addr << ":" << port << " open" << std::endl;
    }

    std::cout << "Time taken: " << costtime << " seconds" << std::endl;
}

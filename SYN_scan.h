#ifndef SYN_SCAN_H
#define SYN_SCAN_H

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

bool is_port_open_syn(char *addr, int port, std::mutex &mutex, std::vector<int> &open_ports);

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

bool is_port_open_syn(char *addr, int port, std::mutex &mutex, std::vector<int> &open_ports)
{
    int sockfd;
    struct sockaddr_in server_addr;
    bool is_open = false;

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0)
    {
        std::cerr << "Error creating socket" << std::endl;
        return false;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return false;
    }

    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, addr, &sin.sin_addr);

    // 构造IP头
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr("10.198.129.72"); 
    iph->daddr = sin.sin_addr.s_addr;

    // 构造TCP头
    tcph->source = htons(54321); // 任意本地端口
    tcph->dest = htons(port);
    tcph->seq = htonl(0);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(14600);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // 伪首部用于TCP校验和
    struct pseudo_header {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t tcp_length;
    } psh;

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char pseudogram[sizeof(psh) + sizeof(struct tcphdr)];
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));

    tcph->check = checksum((unsigned short *)pseudogram, sizeof(pseudogram));

    iph->check = checksum((unsigned short *)datagram, iph->ihl * 4);

    // 发送SYN包
    if (sendto(sockfd, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
        close(sockfd);
        return false;
    }

    // 设置接收超时
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // 接收响应
    char recv_buf[4096];
    while (true) {
        ssize_t len = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
        if (len < 0) break;
        struct iphdr *iph_resp = (struct iphdr *)recv_buf;
        if (iph_resp->protocol != IPPROTO_TCP) continue;
        struct tcphdr *tcph_resp = (struct tcphdr *)(recv_buf + iph_resp->ihl * 4);
        if (tcph_resp->source == htons(port) && tcph_resp->dest == tcph->source) {
            if (tcph_resp->syn && tcph_resp->ack) {
                std::lock_guard<std::mutex> lock(mutex);
                open_ports.push_back(port);
                close(sockfd);
                return true;
            }
            break;
        }
    }

    close(sockfd);
    return is_open;
}

#endif // SYN_SCAN_H
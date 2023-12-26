/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

const Buffer broadcase_host = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;
  std::cerr << "handle packet" << std::endl;
  // FILL THIS IN
    struct ethernet_hdr* ethernetHdr = getEthernetHeader(packet);
    Buffer buffer(ethernetHdr->ether_dhost, ethernetHdr->ether_dhost + 6);
    if(buffer != broadcase_host && findIfaceByMac(buffer) == nullptr ){
        std::cerr << "Ethernet destination is not in this router, ignoring" << std::endl;
        return;
    }


    if(ethernetHdr->ether_type == ntohs(ethertype_ip)) {
        handleIPV4Packet(packet, inIface, ethernetHdr);
    }

    if(ethernetHdr->ether_type == ntohs(ethertype_arp)) {
        handleARPPacket(packet, inIface, ethernetHdr);
    }
}

struct arp_hdr*
SimpleRouter::getARPHeader(const struct simple_router::ethernet_hdr *ethe_header) {
    return (arp_hdr *)((unsigned char *)ethe_header + sizeof(ethernet_hdr));
}

struct ethernet_hdr*
SimpleRouter::getEthernetHeader(const simple_router::Buffer &packet) {
    return (ethernet_hdr *)packet.data();
}

struct icmp_hdr*
SimpleRouter::getICMPHeader(const struct simple_router::ip_hdr * ip_ptr) {
    return (icmp_hdr *)((unsigned char *)ip_header + sizeof(ip_hdr));
}


struct ip_hdr*
SimpleRouter::getIPV4Header(const struct simple_router::ethernet_hdr *ethe_header) {
    return (ip_hdr *)((unsigned char *)ethe_header + sizeof(ethernet_hdr));
}


void
SimpleRouter::handleARPPacket(const simple_router::Buffer &packet, const std::string &inIface,
                              const struct simple_router::ethernet_hdr *ether_hdr) {
    struct arp_hdr* arpHdr = getARPHeader(ether_hdr);
    const Interface* iface = findIfaceByName(inIface);
    // request
    if(arpHdr->arp_op == ntohs(arp_op_request)){
        if(iface->ip != arpHdr->arp_tip){
          std::cerr << "Interface Ip is not equal to arp target ip, ignoring" << std::endl;
          return;
        }

        struct arp_hdr a_hdr = makeArpHeader(arp_op_reply, arpHdr, iface);
        struct ethernet_hdr e_hdr = makeEthernetHeader(ether_hdr, iface);
        Buffer packet_reply = makeArpPacket(e_hdr, a_hdr);

        print_hdrs(packet_reply);
        sendPacket(packet_reply, inIface);
        std::cerr << "Send Arp packet in request" << std::endl;
        print_hdrs(packet_reply);
    }
    // reply
    else if(arpHdr->arp_op == ntohs(arp_op_reply)){
        Buffer sha(arpHdr->arp_sha, arpHdr->arp_sha + 6);
        std::shared_ptr<simple_router::ArpEntry> arp_entry = m_arp.lookup(arpHdr->arp_sip);
        if (arp_entry == nullptr)
        {
            std::shared_ptr<ArpRequest> arp_req = m_arp.insertArpEntry(sha, arpHdr->arp_sip);
            if(arp_req == nullptr){
                std::cerr << "No pending request" << std::endl;
                return;
            }
            else{
                for (auto it = arp_req->packets.begin(); it != arp_req->packets.end(); it++){
                    ethernet_hdr *ethe_header = (ethernet_hdr *)(it->packet.data());
                    std::copy(sha.begin(), sha.end(), ethe_header->ether_dhost);
                    sendPacket(it->packet, it->iface);
                    std::cerr << "Send Arp packet in reply" << std::endl;
                    print_hdrs(it->packet);
                }
                m_arp.removeRequest(arp_req);
            }
        }
    }
}


void
SimpleRouter::handleIPV4Packet(const Buffer& packet, const std::string& Iface, 
      const struct simple_router::ethernet_hdr* ether_hdr){
    ip_hdr * ipHdr = getIPV4Header(ether_hdr);
    uint16_t ck_sum = getIpSum(ipHdr);
    ipHdr->ip_sum = ip_sum;
    // check sum
    if(ipHdr->ip_sum != ck_sum){
        std::cerr << ck_sum << ' ' << ipHdr->ip_sum << std::endl;
        std::cerr << "sum not correct";
        return;
    }

    // check if destined to the router
    const Interface *iface = findIfaceByIp(ipHdr->ip_dst);

    if(iface == nullptr){
        ipHdr->ip_ttl--;
        if(ipHdr->ip_ttl <= 0){
            struct ethernet_hdr ethernetHdr = makeEthernetHeader(ether_hdr, iface);
            struct ip_hdr ipHdr1 = makeIPV4Header(ip_protocol_icmp, ipHdr, iface);
            struct icmp_t3_hdr icmpT3Hdr = makeIcmpT3Header(icmp_type_time_exceeded, icmp_code_time_exceeded, (uint8_t*)ipHdr);

            ipHdr1.ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
            ipHdr1.ip_sum = getIpSum(&ipHdr1);

            Buffer buffer_reply = makeIcmpT3Packet(ethernetHdr, ipHdr1, icmpT3Hdr);
            sendPacket(buffer_reply, Iface);
            std::cerr << "Send Icmp t3 packet in time exceed" << std::endl;
            print_hdrs(packet);
            return;
        }
        else{
            RoutingTableEntry route_entry = m_routingTable.lookup(ntohl(ipHdr->ip_dst));
            ipHdr->ip_sum = getIpSum(&ipHdr);
            const Interface * iface_ptr = findIfaceByName(route_entry.ifName);

            std::copy(ether_hdr->ether_shost, ether_hdr->ether_shost + 6, ether_hdr->ether_dhost);
            std::copy(iface_ptr->addr.begin(), iface_ptr->addr.end(), ether_hdr->ether_shost);

            std::shared_ptr<simple_router::ArpEntry> arp_entry;
            uint32_t targetIp;
            // TODO ??? why need this
            if(route_entry.ifName=="sw0-eth3"){
                arp_entry = m_arp.lookup(route_entry.gw);
                targetIp = route_entry.gw;
            }
            else{
                arp_entry = m_arp.lookup(ip_header->ip_dst);
                targetIp = ip_header->ip_dst;
            }

            if(arp_entry == nullptr){
                m_arp.queueRequest(targetIp, packet, route_entry.ifName);
            }
            else{
                std::copy(arp_entry->mac.begin(), arp_entry->mac.end(), ether_hdr->ether_dhost);
                sendPacket(packet, route_entry.ifName);
                std::cerr << "Send IPv4 in iface is nullptr" << std::endl;
                print_hdrs(packet);
            }
        }

    }
    else{
        if(ipHdr->ip_p == ip_protocol_icmp){
            icmp_hdr* icmp_ptr = getICMPHeader(ipHdr);
            // TODO why need to minus 20
            if(icmp_ptr->icmp_type == icmp_type_echo_request){
                const uint16_t icmp_size = ntohs(ipHdr->ip_len) - 20;
                uint16_t ck_sum = getIcmpSum(icmp_ptr, icmp_size);

                if(ck_sum != icmp_ptr->icmp_sum){
                    std::cerr<<"sum not correct in icmp"<<std::endl;
                    return;
                }

                icmp_ptr->icmp_type = icmp_type_echo_reply;
                icmp_ptr->icmp_sum = getIcmpSum(icmp_ptr, icmp_size);
                uint32_t dst = ipHdr->ip_dst;
                ipHdr->ip_dst = ipHdr->ip_src;
                ipHdr->ip_src = dst;
                ipHdr->ip_ttl = 64;

                std::copy(ether_hdr->ether_shost, ether_hdr->ether_shost + 6, ether_hdr->ether_dhost);
                std::copy(iface->addr.begin(), iface->addr.end(), ether_hdr->ether_shost);

                ipHdr->ip_sum = getIpSum(ipHdr);

                sendPacket(packet, Iface);
                std::cerr << "Send Icmp in iface is not nullptr" << std::endl;
                print_hdrs(packet);
            }
        }
        else if(ipHdr->ip_p == ip_protocol_tcp || ipHdr->ip_p == ip_protocol_udp){
            struct ethernet_hdr ethernetHdr = makeEthernetHeader(ether_hdr, iface);
            struct ip_hdr ipHdr1 = makeIPV4Header(ip_protocol_icmp, ipHdr, iface);
            struct icmp_t3_hdr icmpT3Hdr = makeIcmpT3Header(icmp_type_port_unreachable, icmp_code_destination_port_unreachable, (uint8_t*)ipHdr);

            ipHdr1.ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
            ipHdr1.ip_sum = getIpSum(&ipHdr1);

            Buffer buffer_reply = makeIcmpT3Packet(ethernetHdr, ipHdr1, icmpT3Hdr);
            sendPacket(buffer_reply, Iface);
            std::cerr << "Send Icmp t3 packet in time exceed" << std::endl;
            print_hdrs(packet);
            return;
        }
    }
}


arp_hdr 
SimpleRouter::makeArpHeader(enum arp_opcode type, const arp_hdr* a_ptr, const Interface* iface){
  arp_hdr a_hdr(*a_ptr);
  a_hdr.arp_op = ntohs(type);
  a_hdr.arp_tip = a_ptr->arp_sip;
  a_hdr.arp_sip = iface->ip;
  a_hdr.arp_tha = a_ptr->arp_sha;
  a_hdr.arp_sha = (iface->addr).data();

  return a_hdr;
}

ethernet_hdr
SimpleRouter::makeEthernetHeader(const ethernet_hdr* e_ptr, const Interface* iface){
    ethernet_hdr ether_hdr(*e_ptr);
    ether_hdr.ether_dhost = e_ptr->ether_shost;
    ether_hdr.ether_shost = (iface->addr).data()

    return ether_hdr;
}

ip_hdr
SimpleRouter::makeIPV4Header(enum simple_router::ip_protocol ip_p, const simple_router::ip_hdr *ip_ptr,
                             const simple_router::Interface *iface) {
    ip_hdr ipHdr(*ip_ptr);
    ipHdr.ip_p = ip_p;
    ipHdr.ip_src = iface->ip;
    ipHdr.ip_dst = ip_ptr->ip_src;

    return  ipHdr;
}

icmp_hdr
SimpleRouter::makeIcmpHeader(enum simple_router::icmptype type, enum simple_router::icmpcode code,
                             const uint8_t * ip_ptr) {

}

icmp_t3_hdr
SimpleRouter::makeIcmpT3Header(enum simple_router::icmptype type, enum simple_router::icmpcode code,
                               const uint8_t * data) {
    icmp_t3_hdr icmpT3Hdr;
    icmpT3Hdr.icmp_code = code;
    icmpT3Hdr.icmp_type = type;
    std::copy(data, data + ICMP_DATA_SIZE, icmpT3Hdr.data);
    icmpT3Hdr.icmp_sum = getIcmpT3Sum(&icmpT3Hdr);

    return icmpT3Hdr;
}

Buffer 
SimpleRouter::makeArpPacket(ethernet_hdr ethe_request, arp_hdr arp_request){
    Buffer packet;
    packet.insert(packet.end(), (unsigned char *)&ethe_request, (unsigned char *)&ethe_request + sizeof(ethe_request));
    packet.insert(packet.end(), (unsigned char *)&arp_request, (unsigned char *)&arp_request + sizeof(arp_request));
    return packet;
}

Buffer
SimpleRouter::makeIcmpT3Packet(simple_router::ethernet_hdr ethernetHdr, simple_router::ip_hdr ipHdr,
                               simple_router::icmp_t3_hdr icmpT3Hdr) {
    Buffer packet;
    packet.insert(packet.end(), (unsigned char *)&ethernetHdr, (unsigned char *)&ethernetHdr + sizeof(ethernet_hdr));
    packet.insert(packet.end(), (unsigned char *)&ipHdr, (unsigned char *)&ipHdr + sizeof(ip_hdr));
    packet.insert(packet.end(), (unsigned char *)&icmpT3Hdr, (unsigned char *)&icmpT3Hdr + sizeof(icmp_t3_hdr));
    return packet;
}

uint16_t
SimpleRouter::getIpSum(simple_router::ip_hdr * ip_ptr, int len) {
    uint16_t ip_sum = ip_ptr->ip_sum;
    ipHdr->ip_sum = 0x0000;
    uint16_t ck_sum = cksum(ip_ptr, len);
    ip_ptr->ip_sum = ip_sum;
    return ck_sum;
}


uint16_t
SimpleRouter::getIcmpT3Sum(simple_router::icmp_t3_hdr * icmp_t3_ptr) {
    uint16_t icmp_sum = icmp_t3_ptr->icmp_sum;
    icmp_t3_ptr->icmp_sum = 0x0000;
    uint16_t ck_sum = cksum(icmp_t3_ptr, sizeof(icmp_t3_hdr));
    icmp_t3_ptr->icmp_sum = icmp_sum;
    return ck_sum;
}

uint16_t
SimpleRouter::getIcmpSum(simple_router::icmp_hdr * icmp_ptr) {
    uint16_t icmp_sum = icmp_ptr->icmp_sum;
    icmp_ptr->icmp_sum = 0x0000;
    uint16_t ck_sum = cksum(icmp_t3_ptr, sizeof(icmp_hdr));
    icmp_ptr->icmp_sum = icmp_sum;
    return ck_sum;
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {

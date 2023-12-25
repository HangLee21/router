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

  // FILL THIS IN
    struct ethernet_hdr* ethernetHdr = getEthernetHeader(packet);
    Buffer buffer(ethernetHdr->ether_dhost, ethernetHdr->ether_dhost + 6)
    if(buffer != broadcase_host && findIfaceByMac(buffer) == nullptr ){
        std::cerr << "Ethernet destination is not in this router, ignoring" << std::endl;
        return;
    }


    if(etherHdr->ether_type == ntohs(ethertype_ip)) {
        handleIPV4Packet(packet, inIface, ether_hdr);
    }

    if(etherHdr->ether_type == ntohs(ethertype_arp)) {
        handleARPPacket(packet, inIface, ether_hdr);
    }
}

struct arp_hdr*
SimpleRouter::getARPHeader(struct simple_router::ethernet_hdr *ethe_header) {
    return (arp_hdr *)((unsigned char *)ethe_header + sizeof(ethernet_hdr));
}

struct ethernet_hdr*
SimpleRouter::getEthernetHeader(const simple_router::Buffer &packet) {
    return (ethernet_hdr *)packet.data();
}


struct ip_hdr*
SimpleRouter::getIPV4Header(struct simple_router::ethernet_hdr *ethe_header) {
    return (ip_hdr *)((unsigned char *)ethe_header + sizeof(ethernet_hdr));
}


void
SimpleRouter::handleARPPacket(const simple_router::Buffer &packet, const std::string &inIface,
                              struct simple_router::ethernet_hdr *ether_hdr) {
    struct arp_hdr* arpHdr = getARPHeader(ether_hdr);
    const Interface* iface = findIfaceByName(inIface);
    // request
    if(arpHdr->arp_op == ntohs(arp_op_request)){
        if(iface->ip != arpHdr->arp_tip){
          std::cerr << "Interface Ip is not equal to arp target ip, ignoring" << std::endl;
          return;
        }

        struct a_hdr = makeArpHeader(arp_op_reply, arpHdr, iface);
        struct e_hdr = makeEthernetHeader(ether_hdr, iface);
        Buffer packet_reply = makeArpPacket(e_hdr, a_hdr);

        print_hdrs(packet_reply);
        sendPacket(packet_reply, inIface);
    }
    // reply
    else if(arpHdr->arp_op == ntohs(arp_op_reply)){
        Buffer sha(arpHdr->arp_sha, arpHdr->arp_sha + 6);
        std::shared_ptr<ArpRequest> arp_entry = m_arp.lookup(arpHdr->arp_sip);
        if (arp_entry == nullptr)
        {
            std::shared_ptr<ArpRequest> arp_req = m_arp.insertArpEntry(*sha, arpHdr.arp_sip);
            if(arp_req == nullptr){
                std::cerr << "No pending request" << std::endl;
                return;
            }
            else{
                for (auto it = arp_req->packets.begin(); it != arp_req->packets.end(); it++){
                    ethernet_hdr *ethe_header = (ethernet_hdr *)(it->packet.data());
                    std::copy(sha->begin(), sha->end(), ethe_header->ether_dhost);
                    sendPacket(it->packet, it->iface);
                    std::cerr << "Send Packet" << std::endl;
                    print_hdrs(it->packet);
                }
                m_arp.removeRequest(arp_req);
            }
        }
    }
}


void
SimpleRouter::handleIPv4Packet(const simple_router::Buffer &packet, const std::string &Iface,
                               struct simple_router::ethernet_hdr *ether_hdr) {

}


arp_hdr 
SimpleRouter::makeArpHeader(enum arp_opcode type, arp_hdr* a_ptr, Interface* iface){
  arp_hdr arp_hdr(*a_ptr);
  arp_hdr.arp_op = ntohs(type);
  memcpy(&a_hdr.arp_tip, &a_hdr.arp_sip, sizeof(a_hdr.arp_tip));
  memcpy(a_hdr.arp_tha, a_hdr.arp_sha, sizeof(a_hdr.arp_tha));
  memcpy(&a_hdr.arp_sip, &iface->ip, sizeof(a_hdr.arp_sip));
  memcpy(a_hdr.arp_sha, (iface->addr).data(), sizeof(a_hdr.arp_sha));

  return arp_hdr;
}

ethernet_hdr
SimpleRouter::makeEthernetHeader(ethernet_hdr* e_ptr, Interface* iface){
    ethernet_hdr ether_hdr(*e_ptr);

    memcpy(ether_hdr.ether_dhost, ether_hdr.ether_shost, sizeof(ether_hdr.ether_dhost));
    memcpy(ether_hdr.ether_shost, (iface->addr).data(), sizeof(ether_hdr.ether_shost));

    return ethernet_hdr;
}

Buffer 
SimpleRouter::makeArpPacket(ethernet_hdr ethe_request, arp_hdr arp_request){
    Buffer packet;
    packet.insert(packet.end(), (unsigned char *)&ethe_request, (unsigned char *)&ethe_request + sizeof(ethe_request));
    packet.insert(packet.end(), (unsigned char *)&arp_request, (unsigned char *)&arp_request + sizeof(arp_request));
    return packet;
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

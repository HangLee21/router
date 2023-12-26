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

#ifndef SIMPLE_ROUTER_SIMPLE_ROUTER_HPP
#define SIMPLE_ROUTER_SIMPLE_ROUTER_HPP

#include "arp-cache.hpp"
#include "routing-table.hpp"
#include "core/protocol.hpp"
#include "core/interface.hpp"

#include "pox.hpp"

namespace simple_router {

class SimpleRouter
{
public:

  SimpleRouter();

  /**
   * IMPLEMENT THIS METHOD
   *
   * This method is called each time the router receives a packet on
   * the interface.  The packet buffer \p packet and the receiving
   * interface \p inIface are passed in as parameters. The packet is
   * complete with ethernet headers.
   */
  void
  handlePacket(const Buffer& packet, const std::string& inIface);

  /**
   * USE THIS METHOD TO SEND PACKETS
   *
   * Call this method to send packet \p packt from the router on interface \p outIface
   */
  void
  sendPacket(const Buffer& packet, const std::string& outIface);

  /**
   * Load routing table information from \p rtConfig file
   */
  bool
  loadRoutingTable(const std::string& rtConfig);

  /**
   * Load local interface configuration
   */
  void
  loadIfconfig(const std::string& ifconfig);

  /**
   * Get routing table
   */
  const RoutingTable&
  getRoutingTable() const;

  /**
   * Get ARP table
   */
  const ArpCache&
  getArp() const;

  /**
   * Print router interfaces
   */
  void
  printIfaces(std::ostream& os);

  /**
   * Reset ARP cache and interface list (e.g., when mininet restarted)
   */
  void
  reset(const pox::Ifaces& ports);

  /**
   * Find interface based on interface's IP address
   */
  const Interface*
  findIfaceByIp(uint32_t ip) const;

  /**
   * Find interface based on interface's MAC address
   */
  const Interface*
  findIfaceByMac(const Buffer& mac) const;

  /**
   * Find interface based on interface's name
   */
  const Interface*
  findIfaceByName(const std::string& name) const;
  //==========Custom Functions==========//
    /**
     * Get Ethernet header
     */
    struct ethernet_hdr*
    getEthernetHeader(const Buffer& packet);

    /**
     * Get Ethernet header
     */
    struct ip_hdr*
    getIPV4Header(const struct simple_router::ethernet_hdr *ethe_header);

    /**
     * Get ARP header
     */
    struct arp_hdr*
    getARPHeader(const struct simple_router::ethernet_hdr *ethe_header);
    /**
     * handle IPv4 packet
     */
    void
    handleIPV4Packet(const Buffer& packet, const std::string& Iface, const struct simple_router::ethernet_hdr* ether_hdr);

    /**
     * handle ARP packet
     */
    void
    handleARPPacket(const Buffer& packet, const std::string& inIface, const struct ethernet_hdr* ether_hdr);
    /**
     * make ARP header
     */
    arp_hdr 
    makeArpHeader(enum arp_opcode type, const arp_hdr* a_hdr, const Interface* iface);
    /**
     * make Ethernet header
     */
    ethernet_hdr 
    makeEthernetHeader(const ethernet_hdr* e_hdr, const Interface* iface);
    /**
     * make IPV4 header
     */
     ip_hdr
     makeIPV4Header(enum ip_protocol, const ip_hdr* ipHdr, const Interface* iface);
    /**
     * make Icmp header
     */
     icmp_hdr
     makeIcmpHeader(enum icmptype, enum icmpcode, const uint8_t* );
    /**
     * make Icmp header
     */
     icmp_t3_hdr
     makeIcmpT3Header(enum icmptype, enum icmpcode, const uint8_t* );
    /**
     * make ARP packet
     */
     Buffer
     makeArpPacket(ethernet_hdr ethe_request, arp_hdr arp_request);
    /**
     * make ARP packet
     */
     Buffer
     makeIcmpT3Packet(ethernet_hdr, ip_hdr, icmp_t3_hdr);
    /**
     * make ARP packet
     */
     uint16_t
     getIpSum(ip_hdr*);
    /**
     * make ARP packet
     */
     uint16_t
     getIcmpT3Sum(icmp_t3_hdr*);




private:
  ArpCache m_arp;
  RoutingTable m_routingTable;
  std::set<Interface> m_ifaces;
  std::map<std::string, uint32_t> m_ifNameToIpMap;

  friend class Router;
  pox::PacketInjectorPrx m_pox;
};

inline const RoutingTable&
SimpleRouter::getRoutingTable() const
{
  return m_routingTable;
}

inline const ArpCache&
SimpleRouter::getArp() const
{
  return m_arp;
}

} // namespace simple_router

#endif // SIMPLE_ROUTER_SIMPLE_ROUTER_HPP

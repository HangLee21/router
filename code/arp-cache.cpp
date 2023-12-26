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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
    for(auto it = m_cacheEntries.begin(); it != m_cacheEntries.end(); it++){
        auto entry = *it;
        if(!entry->isValid){
            m_cacheEntries.erase(it);
        }
    }

    for(auto request: m_arpRequests){
        if(request->nTimesSent >= 5){
            std::cout << "Arp not received, removing request" << std::endl;
            for(auto it = request->packets.begin(); it != request->packets.end(); it++){
                ethernet_hdr*ether_hdr = m_router.getEthernetHeader(it->packet);
                ip_hdr* ipHdr = m_router.getIPV4Header(it->packet);
                RoutingTableEntry route_entry = m_router.getRoutingTable().lookup(ntohl(ipHdr->ip_src));
                const Interface* iface = m_router.findIfaceByName(route_entry.ifName);
                struct ethernet_hdr ethernetHdr = makeEthernetHeader(ether_hdr, iface);
                struct ip_hdr ipHdr1 = makeIPV4Header(ip_protocol_icmp, ipHdr, iface);
                struct icmp_t3_hdr icmpT3Hdr = makeIcmpT3Header(icmp_type_time_exceeded, icmp_code_time_exceeded, (uint8_t*)ipHdr);

                ipHdr1.ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
                ipHdr1.ip_sum = getIpSum(&ipHdr1);

                Buffer buffer_reply = makeIcmpT3Packet(ethernetHdr, ipHdr1, icmpT3Hdr);
                sendPacket(buffer_reply, Iface);
                std::cerr << "Send Icmp t3 packet in Arp Cache" << std::endl;
                print_hdrs(packet);
            }
            m_arpRequests.remove(request);
        }
        else{
            request->timeSent = std::chrono::steady_clock::now();
            request->nTimesSent++;

            RoutingTableEntry route_entry = m_router.getRoutingTable().lookup(ntohl(request->ip));
            const Interface* iface = m_router.findIfaceByName(route_entry.ifName);
            unsigned char tha[6] = {0, 0, 0, 0, 0, 0};
            arp_hdr arpHdr;
            arpHdr.arp_hrd = htons(arp_hrd_ethernet);
            arpHdr.arp_pro = htons(ethertype_ip);
            arpHdr.arp_op = htons(arp_op_request);
            arpHdr.arp_hln = 0x06;
            arpHdr.arp_pln = 0x04;
            std::copy(iface->addr.data(), iface->addr.data() + 6, arpHdr.arp_sha);
            arpHdr.arp_sip = iface->ip;
            std::copy(tha, tha + 6, arpHdr.arp_tha);
            arpHdr.arp_tip = request->ip;

            const Buffer broadcast_host = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            ethernet_hdr ethernetHdr;
            ethernetHdr.ether_type = ethertype_arp;
            std::copy(iface->addr.data(), iface->addr.data() + 6, ethernetHdr.ether_shost);
            std::copy(broadcast_host.data(), broadcast_host.data() + 6, ethernetHdr.ether_dhost);

            Buffer packet = m_router.makeArpPacket(ethernetHdr, arpHdr);
            m_router.sendPacket(packet, iface->name);
            std:cerr << "Send Packet in Arp Cache" << std::endl;
            print_hdrs(packet);
        }
    }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router

import logging
import asyncio

_logger = logging.getLogger(__name__)

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_RA,
    ICMPv6NDOptSrcLLAddr,
    ICMPv6NDOptPrefixInfo,
)

async def tc_basic_choice(dut):
    mac1 = dut.alloc_mac()
    ll1 = dut.create_ll(mac1)

    pkt = dut.ethhdr(mac1) / IPv6(src=ll1, dst="ff02::1")
    pkt /= ICMPv6ND_RA(routerlifetime=300)
    pkt /= ICMPv6NDOptSrcLLAddr(lladdr=mac1)
    pkt /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:2226::",
    )
    dut.ipv6sock.send(pkt)

    mac2 = dut.alloc_mac()
    ll2 = dut.create_ll(mac2)

    pkt = dut.ethhdr(mac2) / IPv6(src=ll2, dst="ff02::1")
    pkt /= ICMPv6ND_RA(routerlifetime=300)
    pkt /= ICMPv6NDOptSrcLLAddr(lladdr=mac2)
    pkt /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:aaa6::",
    )
    dut.ipv6sock.send(pkt)

    async def check(addr):
        dut.make_local(addr)

        await dut._ws.send_str(f"connect http://[{addr}]/sink")

        async def ws_wait():
            result = await dut._ws.receive_str()
            _logger.info("connect to %r: %r", addr, result)
            return result

        async def packet_watch():
            while pkt := await dut.v6_packet():
                ipv6 = pkt.getlayer(IPv6)
                eth = pkt.getlayer(Ether)
                if not (ipv6 and eth):
                    continue
                if ipv6.dst == addr:
                    _logger.info("pkt %r -> %r used GW %r", ipv6.src, ipv6.dst, eth.dst)
                    return (ipv6.src, eth.dst)

        result = await asyncio.gather(ws_wait(), packet_watch())
        _logger.info("result: %r", result)

    await check("2001:db8:2226:3333::1")
    await check("2001:db8:aaa6:bbbb::1")

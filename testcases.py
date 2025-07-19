import logging
import asyncio
import ipaddress

_logger = logging.getLogger(__name__)

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_RA,
    ICMPv6NDOptSrcLLAddr,
    ICMPv6NDOptPrefixInfo,
)

class PassFail:
    def __init__(self, src=None, mac=None):
        self.src = ipaddress.IPv6Network(src or "::/0")
        self.mac = mac
        self.explainer = ""

    def explain(self, text):
        self.explainer = text
        return self

    def __call__(self, src, mac):
        if ipaddress.IPv6Address(src) not in self.src:
            return False
        if self.mac not in [None, mac]:
            return False
        return True

class Pass(PassFail):
    color = "\033[92;1mPASS\033[m"

class Fail(PassFail):
    color = "\033[91;1mFAIL\033[m"

class Warn(PassFail):
    color = "\033[94;1mWARN\033[m"


manual_mode = False
http_mode = False

async def check(dut, addr, conds=[]):
    dut.make_local(addr)

    if manual_mode:
        await dut._ws.send_str(f"manual {addr}")
    elif http_mode:
        await dut._ws.send_str(f"connect http://[{addr}]/sink")
    else:
        await dut._ws.send_str(f"ws-connect ws://[{addr}]/flow")

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

    gather = [packet_watch()]
    if not manual_mode:
        gather.append(ws_wait())
    result = await asyncio.gather(*gather)
    cond_match = None

    if manual_mode:
        await dut._ws.send_str(f"manual-clear")

    src, dst = result[0]

    for cond in conds:
        if cond(src, dst):
            cond_match = cond
            break

    if cond_match is None:
        _logger.info("\033[93;1munrecognized\033[m result: %r", result)
    else:
        _logger.info("%s: %r \033[97m%s\033[m", cond_match.color, result, cond_match.explainer)

    if not manual_mode and not http_mode:
        # websocket connection number
        return src, dst, int(result[1].split()[1])
    return src, dst, None

async def check_ws(dut, num, addr, conds):
    if num is None:
        return

    await dut._ws.send_str(f"ws-ping {num}")

    async def packet_watch():
        while pkt := await dut.v6_packet():
            ipv6 = pkt.getlayer(IPv6)
            eth = pkt.getlayer(Ether)
            if not (ipv6 and eth):
                continue
            if ipv6.dst == addr:
                _logger.info("pkt %r -> %r used GW %r", ipv6.src, ipv6.dst, eth.dst)
                return (ipv6.src, eth.dst)

    gather = [packet_watch()]
    result = await asyncio.gather(*gather)
    cond_match = None

    for cond in conds:
        if cond(*result[0]):
            cond_match = cond
            break

    if cond_match is None:
        _logger.info("\033[93;1munrecognized\033[m result: %r", result)
    else:
        _logger.info("%s: %r \033[97m%s\033[m", cond_match.color, result, cond_match.explainer)


async def ws_close(dut, num):
    if num is not None:
        await dut._ws.send_str(f"ws-close {num}")

async def tc_basic_choice(dut):
    mac1 = dut.alloc_mac()
    ll1 = dut.create_ll(mac1)

    pkt = dut.ethhdr(mac1) / IPv6(src=ll1, dst="ff02::1")
    pkt /= ICMPv6ND_RA(
        routerlifetime=300,
    )
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
    pkt /= ICMPv6ND_RA(
        routerlifetime=300,
        prf="Low",
    )
    pkt /= ICMPv6NDOptSrcLLAddr(lladdr=mac2)
    pkt /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:aaa6::",
    )
    dut.ipv6sock.send(pkt)

    await dut._ws.send_str(f"message 2.5s delay for DAD")
    await asyncio.sleep(2.5)

    src1, _, ws1 = await check(dut, "2001:db8:2226:3333::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong gateway for source"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong gateway for source"),
    ])
    src2, _, ws2 = await check(dut, "2001:db8:aaa6:bbbb::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1).explain("suboptimal choice - required by RA prio"),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong gateway for source"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong gateway for source"),
    ])

    pkt = dut.ethhdr(mac1) / IPv6(src=ll1, dst="ff02::1")
    pkt /= ICMPv6ND_RA(
        routerlifetime=0,
    )
    pkt /= ICMPv6NDOptSrcLLAddr(lladdr=mac1)
    pkt /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:2226::",
    )
    dut.ipv6sock.send(pkt)

    await asyncio.sleep(0.5)

    expectation = [
        Pass(src=f"{src1}/128", mac=mac2).explain("correctly moved to remaining GW"),
        Fail(src=f"{src1}/128", mac=mac1).explain("trying to use dead gateway"),
        Fail(src="2001:db8:aaa6::/64").explain("TCP magically jumped source addresses?"),
    ]
    await check_ws(dut, ws1, "2001:db8:2226:3333::1", expectation)
    await check_ws(dut, ws2, "2001:db8:aaa6:bbbb::1", expectation)

    expectation = [
        Pass(src="2001:db8:aaa6::/64", mac=mac2),
        Fail(src="2001:db8:2226::/64", mac=mac1).explain("RA deprecation ignored"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong gateway for source"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong gateway for source"),
    ]
    _, _, ws3 = await check(dut, "2001:db8:2226:3333::2", expectation)
    _, _, ws4 = await check(dut, "2001:db8:aaa6:bbbb::2", expectation)

    await ws_close(dut, ws1)
    await ws_close(dut, ws2)
    await ws_close(dut, ws3)
    await ws_close(dut, ws4)

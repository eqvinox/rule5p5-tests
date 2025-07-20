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
    ICMPv6NDOptRouteInfo,
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

async def check(dut, addr, conds=[], ws_possible=True):
    dut.make_local(addr)

    if manual_mode:
        await dut._ws.send_str(f"manual {addr}")
    elif http_mode or not ws_possible:
        await dut._ws.send_str(f"connect http://[{addr}]/sink")
    else:
        await dut._ws.send_str(f"ws-connect ws://[{addr}]/flow")

    async def ws_wait():
        async with asyncio.timeout(4.0):
            result = await dut._ws.receive_str()
            _logger.info("connect to %r: %r", addr, result)
        return result

    async def packet_watch():
        async with asyncio.timeout(4.0):
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
    try:
        result = await asyncio.gather(*gather)
    except TimeoutError:
        _logger.info("\033[95;1mTIMEOUT\033[m")
        return None, None, None

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
        _logger.info("%s: %r \033[30;107m %s \033[m", cond_match.color, result, cond_match.explainer)

    if not manual_mode and not http_mode and ws_possible:
        # websocket connection number
        return src, dst, int(result[1].split()[1])
    return src, dst, None

async def check_ws(dut, num, addr, conds):
    if num is None:
        return

    await dut._ws.send_str(f"ws-send {num}")

    async def packet_watch():
        async with asyncio.timeout(4.0):
            while pkt := await dut.v6_packet():
                print(pkt)
                ipv6 = pkt.getlayer(IPv6)
                eth = pkt.getlayer(Ether)
                if not (ipv6 and eth):
                    continue
                if ipv6.dst == addr:
                    _logger.info("pkt %r -> %r used GW %r", ipv6.src, ipv6.dst, eth.dst)
                    return (ipv6.src, eth.dst)

    gather = [packet_watch()]
    try:
        result = await asyncio.gather(*gather)
    except TimeoutError:
        _logger.info("\033[95;1mTIMEOUT\033[m")
        breakpoint()
        return

    cond_match = None

    for cond in conds:
        if cond(*result[0]):
            cond_match = cond
            break

    if cond_match is None:
        _logger.info("\033[93;1munrecognized\033[m result: %r", result)
    else:
        _logger.info("%s: %r \033[30;107m %s \033[m", cond_match.color, result, cond_match.explainer)


async def ws_close(dut, num):
    if num is not None:
        await dut._ws.send_str(f"ws-close {num}")


def deprecate_ra_lifetime_0(pkt):
    newpkt = pkt.copy()
    newpkt.getlayer(ICMPv6ND_RA).routerlifetime = 0
    return newpkt

def deprecate_pio_lifetime_0(pkt):
    newpkt = pkt.copy()
    pio = newpkt.getlayer(ICMPv6NDOptPrefixInfo)
    pio.validlifetime = 0
    pio.preferredlifetime = 0
    return newpkt

async def part1_basic(dut, deprecation_func):
    mac1 = dut.alloc_mac()
    ll1 = dut.create_ll(mac1)

    pkt1 = dut.ethhdr(mac1) / IPv6(src=ll1, dst="ff02::1")
    pkt1 /= ICMPv6ND_RA(
        routerlifetime=300,
    )
    pkt1 /= ICMPv6NDOptSrcLLAddr(lladdr=mac1)
    pkt1 /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:2226::",
    )
    dut.ipv6sock.send(pkt1)

    mac2 = dut.alloc_mac()
    ll2 = dut.create_ll(mac2)

    pkt2 = dut.ethhdr(mac2) / IPv6(src=ll2, dst="ff02::1")
    pkt2 /= ICMPv6ND_RA(
        routerlifetime=300,
        prf="Low",
    )
    pkt2 /= ICMPv6NDOptSrcLLAddr(lladdr=mac2)
    pkt2 /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:aaa6::",
    )
    dut.ipv6sock.send(pkt2)

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

    _logger.info("%r: deprecating RA", dut)

    deprecated1 = deprecation_func(pkt1)
    dut.ipv6sock.send(deprecated1)

    await asyncio.sleep(1.5)
    _logger.info("%r: deprecating RA - done sleeping", dut)

    expectation = [
        Pass(src=f"{src1}/128", mac=mac2).explain("correctly moved to remaining GW"),
        Fail(src=f"{src1}/128", mac=mac1).explain("trying to use dead gateway"),
    ]
    await check_ws(dut, ws1, "2001:db8:2226:3333::1", expectation)
    expectation = [
        Pass(src=f"{src2}/128", mac=mac2).explain("correctly moved to remaining GW"),
        Fail(src=f"{src2}/128", mac=mac1).explain("trying to use dead gateway"),
    ]
    await check_ws(dut, ws2, "2001:db8:aaa6:bbbb::1", expectation)

    await dut._ws.send_str(f"message extra delay here")
    await asyncio.sleep(2.5)

    expectation = [
        Pass(src="2001:db8:aaa6::/64", mac=mac2),
        Pass(src="2001:db8:2226::/64", mac=mac2).explain("correctly moved to remaining GW"),
        Fail(src="2001:db8:2226::/64", mac=mac1).explain("RA deprecation ignored"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong gateway for source"),
    ]
    _, _, ws3 = await check(dut, "2001:db8:2226:3333::2", expectation, ws_possible=False)
    _, _, ws4 = await check(dut, "2001:db8:aaa6:bbbb::2", expectation, ws_possible=False)

    dut.ipv6sock.send(pkt2)

    await dut._ws.send_str(f"message retrying with low-prio RA")
    await asyncio.sleep(0.5)

    _, _, ws3 = await check(dut, "2001:db8:2226:3333::2", expectation, ws_possible=False)
    _, _, ws4 = await check(dut, "2001:db8:aaa6:bbbb::2", expectation, ws_possible=False)

    await asyncio.sleep(1.0)

    _logger.info("%r: reactivating RA", dut)

    dut.ipv6sock.send(pkt1)

    await dut._ws.send_str(f"message 2.5s delay for DAD")
    src1, _, ws5 = await check(dut, "2001:db8:2226:3333::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong gateway for source"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong gateway for source"),
    ])
    src2, _, ws6 = await check(dut, "2001:db8:aaa6:bbbb::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1).explain("suboptimal choice - required by RA prio"),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong gateway for source"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong gateway for source"),
    ])

    await ws_close(dut, ws1)
    await ws_close(dut, ws2)
    await ws_close(dut, ws3)
    await ws_close(dut, ws4)
    await ws_close(dut, ws5)
    await ws_close(dut, ws6)

async def tc_basic_ra_life_0(dut):
    """Units 1.1, 1.2 and 1.3 (1.3 incomplete)"""
    return await part1_basic(dut, deprecate_ra_lifetime_0)

async def tc_basic_pio_life_0(dut):
    """Units 1.4 and 1.5"""
    return await part1_basic(dut, deprecate_pio_lifetime_0)


async def _tc_with_rio(dut):
    mac1 = dut.alloc_mac()
    ll1 = dut.create_ll(mac1)

    pkt1 = dut.ethhdr(mac1) / IPv6(src=ll1, dst="ff02::1")
    pkt1 /= ICMPv6ND_RA(
        routerlifetime=300,
    )
    pkt1 /= ICMPv6NDOptSrcLLAddr(lladdr=mac1)
    pkt1 /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:2226::",
    )
    dut.ipv6sock.send(pkt1)

    mac2 = dut.alloc_mac()
    ll2 = dut.create_ll(mac2)

    pkt2 = dut.ethhdr(mac2) / IPv6(src=ll2, dst="ff02::1")
    pkt2 /= ICMPv6ND_RA(
        routerlifetime=300,
        prf="Low",
    )
    pkt2 /= ICMPv6NDOptSrcLLAddr(lladdr=mac2)
    pkt2 /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:aaa6::",
    )
    pkt2 /= ICMPv6NDOptRouteInfo(
    )
    dut.ipv6sock.send(pkt2)

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


async def tc_router_nud(dut):
    """Units 3.x, incomplete"""

    mac1 = dut.alloc_mac()
    ll1 = dut.create_ll(mac1)

    pkt1 = dut.ethhdr(mac1) / IPv6(src=ll1, dst="ff02::1")
    pkt1 /= ICMPv6ND_RA(
        routerlifetime=300,
    )
    pkt1 /= ICMPv6NDOptSrcLLAddr(lladdr=mac1)
    pkt1 /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:2226::",
    )
    dut.ipv6sock.send(pkt1)

    mac2 = dut.alloc_mac()
    ll2 = dut.create_ll(mac2)

    pkt2 = dut.ethhdr(mac2) / IPv6(src=ll2, dst="ff02::1")
    pkt2 /= ICMPv6ND_RA(
        routerlifetime=300,
        prf="Low",
    )
    pkt2 /= ICMPv6NDOptSrcLLAddr(lladdr=mac2)
    pkt2 /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:aaa6::",
    )
    dut.ipv6sock.send(pkt2)

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

    _logger.info(f"disabling NA replies for {ll1} & waiting")
    del dut.local_addrs[ll1]

    await dut._ws.send_str(f"message 35s wait on NUD")
    await asyncio.sleep(35)
    _logger.info(f"disabling NA replies for {ll1} & waiting: done")

    src1, _, ws1 = await check(dut, "2001:db8:2226:3333::2", [
        Fail(mac=mac1).explain("dead gateway"),
        Pass(src="2001:db8:aaa6::/64", mac=mac2),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong gateway for source"),
    ])
    src2, _, ws2 = await check(dut, "2001:db8:aaa6:bbbb::2", [
        Fail(mac=mac1).explain("dead gateway"),
        Pass(src="2001:db8:aaa6::/64", mac=mac2),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong gateway for source"),
    ])

    await asyncio.sleep(8.5)

    src1, _, ws1 = await check(dut, "2001:db8:2226:3333::3", [
        Fail(mac=mac1).explain("dead gateway"),
        Pass(src="2001:db8:aaa6::/64", mac=mac2),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong gateway for source"),
    ])
    src2, _, ws2 = await check(dut, "2001:db8:aaa6:bbbb::3", [
        Fail(mac=mac1).explain("dead gateway"),
        Pass(src="2001:db8:aaa6::/64", mac=mac2),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong gateway for source"),
    ])

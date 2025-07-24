# SPDX-License-Identifier: ISC
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
    name = "pass"

class Fail(PassFail):
    color = "\033[91;1mFAIL\033[m"
    name = "fail"

class Warn(PassFail):
    color = "\033[94;1mWARN\033[m"
    name = "warn"


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
        await dut._ws.send_str(f"passfail timeout")
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
        await dut._ws.send_str(f"message unrecognized behavior, cached/old network state?")
    else:
        _logger.info("%s: %r \033[30;107m %s \033[m", cond_match.color, result, cond_match.explainer)
        await dut._ws.send_str(f"passfail {cond_match.name} {cond_match.explainer}")

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
        await dut._ws.send_str(f"passfail timeout")
        return

    cond_match = None

    for cond in conds:
        if cond(*result[0]):
            cond_match = cond
            break

    if cond_match is None:
        _logger.info("\033[93;1munrecognized\033[m result: %r", result)
        await dut._ws.send_str(f"message unrecognized behavior, cached/old network state?")
    else:
        _logger.info("%s: %r \033[30;107m %s \033[m", cond_match.color, result, cond_match.explainer)
        await dut._ws.send_str(f"passfail {cond_match.name} {cond_match.explainer}")


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

def deprecate_rio_lifetime_0(pkt):
    newpkt = pkt.copy()
    newpkt.getlayer(ICMPv6NDOptRouteInfo).rtlifetime = 0
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
    await dut.sleep(2.5)

    #
    # part1
    #
    src1, _, ws1 = await check(dut, "2001:db8:2226:3333::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
    ])
    src2, _, ws2 = await check(dut, "2001:db8:aaa6:bbbb::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1).explain("suboptimal choice - required by RA prio"),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
    ])

    _logger.info("%r: deprecating RA", dut)

    deprecated1 = deprecation_func(pkt1)
    dut.ipv6sock.send(deprecated1)

    await dut.sleep(1.5)
    _logger.info("%r: deprecating RA - done sleeping", dut)

    #
    # part2 existing conn
    #

    if deprecation_func == deprecate_pio_lifetime_0:
        expectation = [
            Pass(src=f"{src1}/128", mac=mac1),
            Fail(src=f"{src1}/128", mac=mac2).explain("deprecated addr should still use old GW"),
            Fail(src=f"{src2}/128").explain("TCP connection jumped gateways?"),
        ]
    else:
        expectation = [
            Pass(src=f"{src1}/128", mac=mac2).explain("correctly moved to remaining GW"),
            Fail(src=f"{src1}/128", mac=mac1).explain("trying to use dead gateway"),
            Fail(src=f"{src2}/128").explain("TCP connection jumped gateways?"),
        ]
    await check_ws(dut, ws1, "2001:db8:2226:3333::1", expectation)

    if deprecation_func == deprecate_pio_lifetime_0:
        expectation = [
            Pass(src=f"{src2}/128", mac=mac1).explain("suboptimal choice - required by RA prio"),
            Fail(src=f"{src2}/128", mac=mac2).explain("RA preference ignored"),
            Fail(src=f"{src1}/128").explain("TCP connection jumped gateways?"),
        ]
    else:
        expectation = [
            Pass(src=f"{src2}/128", mac=mac2),
            Fail(src=f"{src2}/128", mac=mac1).explain("trying to use dead gateway"),
            Fail(src=f"{src1}/128").explain("TCP connection jumped gateways?"),
        ]
    await check_ws(dut, ws2, "2001:db8:aaa6:bbbb::1", expectation)

    await dut._ws.send_str(f"message extra delay here")
    await dut.sleep(2.5)

    #
    # part2 new conn
    #

    if deprecation_func == deprecate_pio_lifetime_0:
        expectation = [
            Pass(src="2001:db8:aaa6::/64", mac=mac1),
            Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("RA preference ignored"),
            Fail(src="2001:db8:2226::/64").explain("using deprecated address for new connection"),
        ]
    else:
        expectation = [
            Pass(src="2001:db8:aaa6::/64", mac=mac2),
            Warn(src="2001:db8:2226::/64", mac=mac2).explain("possible issue with leftover PIO"),
            Fail(src="2001:db8:2226::/64", mac=mac1).explain("RA deprecation ignored"),
            Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for dead gateway"),
        ]
    await check(dut, "2001:db8:2226:3333::2", expectation, ws_possible=False)
    await check(dut, "2001:db8:aaa6:bbbb::2", expectation, ws_possible=False)

    dut.ipv6sock.send(pkt2)

    await dut._ws.send_str(f"message retrying with low-prio RA")
    await dut.sleep(0.5)

    #
    # part2 new conn with OSX bug workaround
    #

    src3, _, ws3 = await check(dut, "2001:db8:2226:3333::2", expectation)
    src4, _, ws4 = await check(dut, "2001:db8:aaa6:bbbb::2", expectation)

    await dut.sleep(1.0)

    _logger.info("%r: reactivating RA", dut)

    dut.ipv6sock.send(pkt1)

    #
    # part3 existing conn
    #

    await dut._ws.send_str(f"message 2.5s delay for DAD")

    if deprecation_func == deprecate_pio_lifetime_0:
        expectation = [
            Warn().explain("pass/fail condition not in code yet"),
        ]
    else:
        if src3.startswith("2001:db8:aaa6:"):
            expectation = [
                Pass(src=f"2001:db8:aaa6::/64", mac=mac2).explain("correct RFC8028/SADR"),
                Warn(src=f"2001:db8:aaa6::/64", mac=mac1).explain("no RFC8028/SADR"),
                Fail().explain("wtf?"),
            ]
        else:
            expectation = [
                Pass(src=f"2001:db8:2226::/64", mac=mac1),
                Fail(src=f"2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
                Fail().explain("wtf?"),
            ]
    await check_ws(dut, ws3, "2001:db8:2226:3333::2", expectation)

    if deprecation_func == deprecate_pio_lifetime_0:
        expectation = [
            Warn().explain("pass/fail condition not in code yet"),
        ]
    else:
        expectation = [
            Pass(src=f"{src4}/128", mac=mac2).explain("correct RFC8028/SADR"),
            Warn(src=f"{src4}/128", mac=mac1).explain("no RFC8028/SADR routing"),
            Fail(src=f"{src3}/128").explain("TCP connection jumped gateways?"),
        ]
    await check_ws(dut, ws4, "2001:db8:aaa6:bbbb::2", expectation)

    #
    # part3 new conn
    #

    src1, _, ws5 = await check(dut, "2001:db8:2226:3333::3", [
        Pass(src="2001:db8:2226::/64", mac=mac1),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
    ])
    src2, _, ws6 = await check(dut, "2001:db8:aaa6:bbbb::3", [
        Pass(src="2001:db8:2226::/64", mac=mac1).explain("suboptimal choice - required by RA prio"),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
    ])

    await ws_close(dut, ws1)
    await ws_close(dut, ws2)
    await ws_close(dut, ws3)
    await ws_close(dut, ws4)
    await ws_close(dut, ws5)
    await ws_close(dut, ws6)

    # try to clear state
    dut.ipv6sock.send(deprecate_pio_lifetime_0(deprecate_ra_lifetime_0(pkt1)))
    dut.ipv6sock.send(deprecate_pio_lifetime_0(deprecate_ra_lifetime_0(pkt2)))

async def tc_basic_ra_life_0(dut):
    """Units 1.1, 1.2 and 1.3 (1.3 incomplete)"""
    return await part1_basic(dut, deprecate_ra_lifetime_0)

async def tc_basic_pio_life_0(dut):
    """Units 1.4 and 1.5"""
    return await part1_basic(dut, deprecate_pio_lifetime_0)

async def tc_with_rio(dut, rio_only=False):
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
        routerlifetime=300 if not rio_only else 0,
        prf="Low",
    )
    pkt2 /= ICMPv6NDOptSrcLLAddr(lladdr=mac2)
    pkt2 /= ICMPv6NDOptPrefixInfo(
        validlifetime=600,
        preferredlifetime=600,
        prefix="2001:db8:aaa6::",
    )
    pkt2 /= ICMPv6NDOptRouteInfo(
        plen=48,
        rtlifetime=600,
        prefix="2001:db8:aaa6::",
    )
    dut.ipv6sock.send(pkt2)

    await dut._ws.send_str(f"message 2.5s delay for DAD")
    await dut.sleep(2.5)

    src1, _, ws1 = await check(dut, "2001:db8:2226:3333::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
    ])
    src2, _, ws2 = await check(dut, "2001:db8:aaa6:bbbb::1", [
        Pass(src="2001:db8:aaa6::/64", mac=mac2).explain("correct more specific GW from RIO"),
        Fail(src="2001:db8:2226::/64", mac=mac1).explain("RIO ignored for GW and source"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("right gateway but wrong source"),
    ])

    deprecated2 = deprecate_rio_lifetime_0(pkt2)
    dut.ipv6sock.send(deprecated2)

    await dut.sleep(1.5)
    _logger.info("%r: deprecating RIO - done sleeping", dut)

    expectation = [
        Pass(src=f"{src1}/128", mac=mac1),
        Fail(src=f"{src1}/128", mac=mac2).explain("???"),
        Fail(src=f"{src2}/128").explain("TCP connection jumped sources?"),
    ]
    await check_ws(dut, ws1, "2001:db8:2226:3333::1", expectation)
    expectation = [
        Warn(src=f"{src2}/128", mac=mac1).explain("non SADR routing"),
        Pass(src=f"{src2}/128", mac=mac2).explain("correct SADR gateway"),
        Fail(src=f"{src1}/128").explain("TCP connection jumped sources?"),
    ]
    await check_ws(dut, ws2, "2001:db8:aaa6:bbbb::1", expectation)

    expectation = [
        Pass(src="2001:db8:2226::/64", mac=mac1),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("rule 8 ignored"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway and wrong GW"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
    ]
    _, _, ws3 = await check(dut, "2001:db8:2226:3333::2", expectation, ws_possible=False)
    expectation = [
        Pass(src="2001:db8:2226::/64", mac=mac1).explain("suboptimal choice forced by RA prio"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("no rule 5.5"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway and wrong GW"),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("RA preference ignored"),
    ]
    _, _, ws4 = await check(dut, "2001:db8:aaa6:bbbb::2", expectation, ws_possible=False)

    await ws_close(dut, ws1)
    await ws_close(dut, ws2)

async def tc_with_rio_nodefault(dut):
    await tc_with_rio(dut, rio_only=True)

async def _ignore(dut):
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
    await dut.sleep(2.5)

    src1, _, ws1 = await check(dut, "2001:db8:2226:3333::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
    ])
    src2, _, ws2 = await check(dut, "2001:db8:aaa6:bbbb::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1).explain("suboptimal choice - required by RA prio"),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
    ])


async def tc_router_nud(dut, rio_only=False):
    """Units 3.x, incomplete"""

    mac1 = dut.alloc_mac()
    ll1 = dut.create_ll(mac1)

    pkt1 = dut.ethhdr(mac1) / IPv6(src=ll1, dst="ff02::1")
    pkt1 /= ICMPv6ND_RA(
        routerlifetime=300,
        reachabletime=30000,
        retranstimer=1000,
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
        reachabletime=30000,
        retranstimer=1000,
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
    await dut.sleep(2.5)

    src1, _, ws1 = await check(dut, "2001:db8:2226:3333::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
    ])
    src2, _, ws2 = await check(dut, "2001:db8:aaa6:bbbb::1", [
        Pass(src="2001:db8:2226::/64", mac=mac1).explain("suboptimal choice - required by RA prio"),
        Fail(src="2001:db8:aaa6::/64", mac=mac2).explain("wrong gateway, used low preference (wrong) RA"),
        Fail(src="2001:db8:aaa6::/64", mac=mac1).explain("wrong source for gateway"),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
    ])

    _logger.info(f"disabling NA replies for {ll1} & waiting")
    dut.local_addrs[ll1]["enabled"] = False

    await dut._ws.send_str(f"message 35s wait on NUD")
    await dut.sleep(35)
    _logger.info(f"disabling NA replies for {ll1} & waiting: done")

    src1, _, ws1 = await check(dut, "2001:db8:2226:3333::2", [
        Fail(mac=mac1).explain("dead gateway"),
        Pass(src="2001:db8:aaa6::/64", mac=mac2),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
    ])
    src2, _, ws2 = await check(dut, "2001:db8:aaa6:bbbb::2", [
        Fail(mac=mac1).explain("dead gateway"),
        Pass(src="2001:db8:aaa6::/64", mac=mac2),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
    ])

    await dut.sleep(20)

    src1, _, ws1 = await check(dut, "2001:db8:2226:3333::3", [
        Fail(mac=mac1).explain("dead gateway"),
        Pass(src="2001:db8:aaa6::/64", mac=mac2),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
    ])
    src2, _, ws2 = await check(dut, "2001:db8:aaa6:bbbb::3", [
        Fail(mac=mac1).explain("dead gateway"),
        Pass(src="2001:db8:aaa6::/64", mac=mac2),
        Fail(src="2001:db8:2226::/64", mac=mac2).explain("wrong source for gateway"),
    ])

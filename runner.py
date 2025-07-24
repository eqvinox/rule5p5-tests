import os
import ipaddress
import logging
import argparse
import importlib
import inspect
import traceback
import shlex
import subprocess
import random
import time
from pathlib import Path

import scapy
from scapy.arch.linux import L2Socket
from scapy.data import (
    ETH_P_ALL,
    ETH_P_IP,
    ETH_P_IPV6,
)
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6NDOptDstLLAddr
)

import asyncio
import aiohttp
from aiohttp import web

from typing import (
    Any,
    ClassVar,
    Optional,
)

_bridge_settings = [
    "forward_delay",
    "0",
    "mcast_snooping",
    "0",
    "nf_call_iptables",
    "0",
    "nf_call_ip6tables",
    "0",
    "nf_call_arptables",
    "0",
]

runner_ip = "192.0.2.0"

_logger = logging.getLogger(__name__)

logging.basicConfig(
        datefmt='%Y-%m-%d %H:%M:%S', 
        format='%(asctime)s [%(levelname)s] %(message)s', 
        encoding='utf-8', 
        level=logging.DEBUG,
)

def check_call(cmd, *args, **kwa):
    _logger.info("executing: %s", shlex.join(cmd))
    subprocess.check_call(cmd, *args, **kwa)


def get_testcases():
    # just continuously reload so we can keep the server running
    testcases = importlib.import_module("testcases")
    testcases = importlib.reload(testcases)

    ret = {}
    for item in dir(testcases):
        if item.startswith("_"):
            continue
        if not item.startswith("tc_"):
            continue

        func = getattr(testcases, item)
        if not inspect.iscoroutinefunction(func):
            _logger.error("function %s in testcases module is not a coroutine!", item)
            continue
        ret[item] = func

    return ret

class DUT:
    _by_ip4: ClassVar[dict[ipaddress.IPv4Address, "DUT"]] = {}
    _by_mac: ClassVar[dict[str, "DUT"]] = {}

    _mac: Optional[str]
    _ip4: Optional[ipaddress.IPv4Address]

    _ws: Optional[web.WebSocketResponse]
    _ws_task: Optional[asyncio.Task]

    ipv6_pkts: asyncio.Queue[Packet]
    state: str

    local_addrs: dict[str, Any]

    def __init__(self):
        self._mac = None
        self._ip4 = None
        self._ws = None
        self._ws_task = None
        self.ipv6_pkts = asyncio.Queue()
        self.state = "WS-WAIT"
        self.local_addrs = {}
        self.requested_test = None

    def __repr__(self):
        return f"DUT(mac={self._mac!r}, ip4={self._ip4!r}, state={self.state!r})"

    # global state management

    mac_used: ClassVar[dict[str, Any]] = {}
    ll_used: ClassVar[dict[str, Any]] = {}

    @classmethod
    def alloc_mac(cls):
        while True:
            mac = "00:80:41:%02x:%02x:%02x" % (
                random.randint(0, 256),
                random.randint(0, 256),
                random.randint(0, 256),
            )
            if mac not in cls.mac_used:
                break

        _logger.info("allocated MAC: %s", mac)
        cls.mac_used[mac] = True
        return mac

    @classmethod
    def alloc_ll(cls):
        while True:
            chunks = [random.randint(0, 65536) for i in range(0, 4)]
            addr = ":".join("%x" % i for i in chunks)
            addr = f"fe80::{addr}"

            if addr not in cls.ll_used:
                break

        _logger.info("allocated LL: %s", addr)
        cls.ll_used[addr] = True
        return addr

    @property
    def mac(self) -> Optional[str]:
        return self._mac

    @mac.setter
    def mac(self, mac):
        assert not self._mac
        self._mac = mac
        DUT._by_mac[self._mac] = self

    @classmethod
    def by_mac(cls, mac: str) -> "DUT":
        if mac not in cls._by_mac:
            new = DUT()
            new.mac = mac
        return cls._by_mac[mac]

    @property
    def ip4(self) -> Optional[ipaddress.IPv4Address]:
        return self._ip4

    @ip4.setter
    def ip4(self, ip4):
        if self._ip4:
            del DUT._by_ip4[self._ip4]
        self._ip4 = ip4
        DUT._by_ip4[self._ip4] = self

    @classmethod
    def by_ip4(cls, ip4: ipaddress.IPv4Address) -> "DUT":
        if ip4 not in cls._by_ip4:
            new = DUT()
            new.ip4 = ip4
        return cls._by_ip4[ip4]

    @classmethod
    async def tie_by_packets(cls, pkts):
        while pkt := await pkts.next():
            mac = str(pkt.getlayer(Ether).src)
            ip4 = ipaddress.IPv4Address(pkt.getlayer(IP).src)

            dut_ip4 = cls._by_ip4.get(ip4)
            dut_mac = cls._by_mac.get(mac)
            assert dut_ip4 is None or dut_mac is None or dut_ip4 is dut_mac
            dut = dut_ip4 or dut_mac or DUT()
            if not dut_ip4:
                dut.ip4 = ip4
            if not dut_mac:
                dut.mac = mac

    @classmethod
    async def watch_ipv6(cls, pkts):
        while pkt := await pkts.next():
            mac = str(pkt.getlayer(Ether).src)
            dut_mac = cls._by_mac.get(mac)

            if dut_mac is None:
                #_logger.info("discarding packet from unknown MAC %r: %r", mac, pkt)
                continue

            await dut_mac.ipv6_pkts.put(pkt)

    async def online(self, ws):
        if self._ws_task is not None:
            self._ws_task.cancel("bumped by new websocket connection")
            await self._ws_task

        assert self._ws_task is None
        assert self._ws is None

        self._ws = ws
        self._ws_task = asyncio.current_task()
        try:
            self.state = "WS-UP"

            init_msg = await self._ws.receive_str()

            _logger.info("%r: websocket up (%r)", self, init_msg)

            try:
                while True:
                    self.ipv6_pkts.get_nowait()
            except asyncio.QueueEmpty:
                pass

            tcs = get_testcases()
            tc = self.requested_test

            if tc not in tcs:
                _logger.warning("%r: unknown test %r", self, tc)
                return

            tc_func = tcs[self.requested_test]
            _logger.info("%r: running %r", self, tc)

            try:
                await tc_func(self)
            except:
                _logger.error("testcase function exception:")
                traceback.print_exc()
   
        finally:
            print('websocket connection closed')
            self._ws_task = None
            self._ws = None
            self.state = "WS-WAIT"

    def create_ll(self, mac, ll=None, announce=False, R=True):
        if ll is None:
            ll = self.alloc_ll()
        self.local_addrs[ll] = {
            "mac": mac,
            "enabled": True,
            "R": R,
        }

        if announce:
            pkt = dut.ethhdr(mac) / IPv6(src=ll, dst="ff02::2")
            pkt /= ICMPv6ND_NA(R=int(R), O=0, tgt=ll)
            pkt /= ICMPv6NDOptDstLLAddr(lladdr=mac)
            self.ipv6sock.send(pkt)

        return ll

    async def v6_packet(self):
        pkt = await self.ipv6_pkts.get()

        nd_ns = pkt.getlayer(ICMPv6ND_NS)
        if nd_ns:
            v6 = pkt.getlayer(IPv6)

            use = self.local_addrs.get(nd_ns.tgt)
            if use is None:
                _logger.warning("NS for unknown address %r", nd_ns.tgt)
            elif not use["enabled"]:
                _logger.info("NS for local address %r - \033[33maddress is disabled for NA\033[m", nd_ns.tgt)
            else:
                _logger.info("NS for local address %r, MAC %r", nd_ns.tgt, use["mac"])
                pkt = self.ethhdr(use["mac"]) / IPv6(src=nd_ns.tgt, dst=v6.src)
                pkt /= ICMPv6ND_NA(R=int(use["R"]), O=0, S=1, tgt=nd_ns.tgt)
                pkt /= ICMPv6NDOptDstLLAddr(lladdr=use["mac"])
                self.ipv6sock.send(pkt)

        # check IPv6 NA
        return pkt

    async def sleep(self, duration: Optional[float]):
        try:
            async with asyncio.timeout(duration):
                while True:
                    await self.v6_packet()
        except TimeoutError:
            pass

    def make_local(self, addr):
        check_call(["ip", "route", "replace", "local", addr, "dev", DUT.info["bridge"]["name"]])

    def ethhdr(self, src=None):
        return Ether(src=src or DUT.info["bridge"]["mac"], dst=self.mac)


class AsyncPackets:
    pq: Optional[asyncio.Queue[Packet]]

    def __init__(self, iface: str, filter: Optional[str]):
        self.pq = None
        self._sock = L2Socket(iface, type=ETH_P_ALL, promisc=True, filter=filter)
        self._sock.ins.setblocking(False)
        self._sock.nonblocking_socket = True

    def _read(self):
        pkt = self._sock.recv()
        if pkt is None:
            return
        self.pq.put_nowait(pkt)

    async def next(self) -> Packet:
        return await self.pq.get()

    async def start(self):
        self.pq = asyncio.Queue()
        loop = asyncio.get_running_loop()
        loop.add_reader(self._sock.ins, self._read)


async def handle_index(request: web.Request):
    tcs = get_testcases()

    items = []
    for name, func in tcs.items():
        items.append(f'<div><a href="/test/{name}">{name}</a> {func.__doc__}</div>')
    items = "\n".join(items)

    text = f"""<html><head><title>saddr test</title>
<link rel="stylesheet" type="text/css" href="/static/test.css?t={time.time()}"></head><body>
<h1>index</h1>
{items}
</body></html>"""
    rsp = web.Response(text=text, content_type="text/html")
    rsp.headers["Access-Control-Allow-Origin"] = "*"
    return rsp

async def handle(request: web.Request):
    test = request.match_info.get("test")
    ip4 = ipaddress.IPv4Address(request.remote)
    dut = DUT.by_ip4(ip4)
    dut.requested_test = test

    _logger.info(f"{ip4}: {dut!r} index")

    text = f"""<html><head><title>saddr test</title>
<link rel="stylesheet" type="text/css" href="/static/test.css?t={time.time()}"></head><body>
<script type="text/javascript" src="/static/test.js?t={time.time()}"></script>
<h1>{test}</h1>
<div><a href="/">back</a></div>
<div id="manual"></div>
<pre id="journal"></pre>
</body></html>"""
    rsp = web.Response(text=text, content_type="text/html")
    rsp.headers["Access-Control-Allow-Origin"] = "*"
    return rsp


async def handle_sink(request):
    _logger.info(f"sinking: %r", request.remote)

    rsp = web.Response(text="nothing here", content_type="text/plain")
    rsp.headers["Access-Control-Allow-Origin"] = "*"
    return rsp

async def ws_handler(request):
    ip4 = ipaddress.IPv4Address(request.remote)
    dut = DUT.by_ip4(ip4)

    _logger.info(f"{ip4}: {dut!r} WS")

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    await dut.online(ws)

    _logger.info(f"{ip4}: {dut!r} closing WS")
    return ws


async def ws_flow(request):
    _logger.info(f"WS flow from %r", request.remote)

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            await ws.send_str("echo " + msg.data)
        elif msg.type == aiohttp.WSMsgType.ERROR:
            _logger.info(f"WS flow from %r closed with error", request.remote)
            break
        elif msg.type == aiohttp.WSMsgType.CLOSE:
            _logger.info(f"WS flow from %r closed clean", request.remote)
            break

    return ws

app = web.Application()
app.add_routes([
    web.get('/', handle_index),
    web.get('/test/{test}', handle),
    web.get('/sink', handle_sink),
    web.get('/ws', ws_handler),
    web.get('/flow', ws_flow),
    web.static('/static', os.path.dirname(os.path.abspath(__file__))),
])

async def main(args, app, info):
    tasks = []

    DUT.info = info #haxx

    http_pkts = AsyncPackets(args.downlink, "ip and tcp port 80 and tcp[tcpflags] & tcp-syn != 0")
    await http_pkts.start()
    tasks.append(DUT.tie_by_packets(http_pkts))

    ipv6_pkts = AsyncPackets(args.downlink, "ether proto 0x86dd")
    await ipv6_pkts.start()
    tasks.append(DUT.watch_ipv6(ipv6_pkts))

    DUT.ipv6sock = ipv6_pkts._sock

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, port=80)
    await site.start()

    await asyncio.gather(*tasks)

def net_setup(args):
    devs = {
        "uplink": {
            "name": args.uplink,
        },
        "downlink": {
            "name": args.downlink,
        },
    }
    mdevs = set()

    sys_class_net = Path("/sys/class/net")
    proc_sys_net_ipv6_conf = Path("/proc/sys/net/ipv6/conf")

    for data in devs.values():
        subdir = sys_class_net / data["name"]
        if not subdir.is_dir():
            sys.stderr.write(f"{data['name']} does not appear to exist as network device\n")
            sys.exit(1)

        with open(subdir / "address", "r") as fd:
            data["mac"] = fd.read().strip()

        master = subdir / "master"
        if master.exists():
            data["master"] = master.readlink().name
            mdevs.add(data["master"])

            if not (subdir / "brport").exists():
                sys.stderr.write(f"{data['name']} is enslaved to a non-bridge\n")
        else:
            data["master"] = None

    if len(mdevs) > 1:
        sys.stderr.write(f"devices {args.uplink} and {args.downlink} are in different bridges\n")
        sys.exit(1)

    if len(mdevs) == 1:
        bridge = list(mdevs)[0]
    else:
        bridge = "testbr"
        check_call(["ip", "link", "add", "name", bridge, "type", "bridge"])

    check_call(["ip", "link", "set", bridge, "up", "type", "bridge"] + _bridge_settings)

    with open(sys_class_net / bridge / "address", "r") as fd:
        br_mac = fd.read().strip()

    for data in devs.values():
        if not data["master"]:
            check_call(["ip", "link", "set", data["name"], "master", bridge])

        with open(proc_sys_net_ipv6_conf / data["name"] / "disable_ipv6", "w") as fd:
            fd.write("1\n")

        check_call(["ip", "link", "set", data["name"], "up"])
        check_call(["ip", "addr", "flush", data["name"]])

    check_call(["ip", "addr", "flush", "scope", "global"])
    check_call(["ip", "addr", "add", f"{runner_ip}/32", "dev", "lo"])
    check_call(["ip", "route", "replace", "2001:db8::/32", "dev", bridge])

    check_call(["ip", "route", "replace", "0.0.0.0/0", "dev", bridge])

    try:
        check_call(["nft", "flush", "table", "bridge", "filter"])
    except subprocess.CalledProcessError:
        _logger.info("nftables flush failed, table probably wasn't created yet (this is normal for first run)")

    nft_ruleset = """
table bridge filter {
	chain prerouting {
		type filter hook prerouting priority 0; policy accept;
		ether type ip6 iif UPLINK counter packets 0 bytes 0 drop
		ip daddr RUNNER_IP/32 meta pkttype set host ether daddr set BR_MAC counter
		ether daddr 00:80:41:00:00:00/24 meta pkttype set host ether daddr set BR_MAC counter
	}
	chain forward {
		type filter hook forward priority 0; policy accept;
		ether type ip6 counter packets 0 bytes 0 drop
	}
	chain output {
		type filter hook output priority 0; policy accept;
		ether type ip6 oif UPLINK counter packets 0 bytes 0 drop
	}
}
""".replace("RUNNER_IP", runner_ip).replace("BR_MAC", br_mac).replace("UPLINK", args.uplink)

    _logger.info("piping into: nft -f /dev/stdin")
    nft = subprocess.Popen(["nft", "-f", "/dev/stdin"], stdin=subprocess.PIPE)
    nft.communicate(nft_ruleset.encode("UTF-8"))
    nft.wait()

    devs["bridge"] = {
        "name": bridge,
        "mac": br_mac,
    }
    return devs

if __name__ == '__main__':
    argp = argparse.ArgumentParser(description="RFC6724 rule 5.5 tester")
    argp.add_argument("--uplink", type=str, required=True)
    argp.add_argument("--downlink", type=str, required=True)

    args = argp.parse_args()

    info = net_setup(args)

    asyncio.run(main(args, app, info))

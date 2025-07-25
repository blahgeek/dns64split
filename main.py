#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import collections
import functools
import os
import asyncio
import logging
import time
import typing as tp
import ipaddress
import dataclasses

import geoip2.database
import geoip2.errors
import dns.name
import dns.message
import dns.rdata
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rcode
import dns.rdtypes.svcbbase
import dns.rdtypes.IN.AAAA
import dns.rdtypes.IN.HTTPS
import dns.asyncquery


_GEOLITE2_COUNTRY_DB_PATH = os.path.join(os.path.dirname(__file__), 'data/GeoLite2-Country.mmdb')
_CHINA_DOMAIN_LIST_PATH = os.path.join(os.path.dirname(__file__), 'data/china-domain-list.txt')

_SERVER_TIMEOUT = 5.0

logger = logging.getLogger('dns64split')


@dataclasses.dataclass
class DomainPolicy:
    country: str | None = ''
    ignore_native_ipv6: bool = False
    upstream: str | None = None

    def is_known_cn_domain(self):
        return self.country and self.country.lower() == 'cn'

    def is_known_global_domain(self):
        return self.country and self.country.lower() != 'cn'


def _parse_domain_policies_from_config(config_path: str | None) -> dict[str, DomainPolicy]:
    result = collections.defaultdict(lambda: DomainPolicy())
    # 1. special china domain list file
    result['cn'].country = 'cn'
    with open(_CHINA_DOMAIN_LIST_PATH) as f:
        logger.info(f'Reading china domain list from {_CHINA_DOMAIN_LIST_PATH}')
        for line in f.readlines():
            line = line.strip()
            if line:
                result[line].country = 'cn'
    # 2. config file
    # each line format:
    # <domain>:<attr1>,<attr2=val2>
    if config_path and os.path.exists(config_path):
        logger.info(f'Reading config from {config_path}')
        with open(config_path) as f:
            for line in f.readlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                domain, _, kvs = line.partition(':')
                for kv in kvs.split(','):
                    kv_fields = kv.split('=', 1)
                    if len(kv_fields) == 1:
                        setattr(result[domain], kv_fields[0], True)
                    else:
                        setattr(result[domain], kv_fields[0], kv_fields[1])
    return dict(result)

@functools.cache
def get_geoip2_db() -> geoip2.database.Reader:
    return geoip2.database.Reader(_GEOLITE2_COUNTRY_DB_PATH)


def _is_cn_ip(ip: str) -> bool:
    try:
        res = get_geoip2_db().country(ip)
        return res.country.iso_code == 'CN'
    except geoip2.errors.AddressNotFoundError:
        return False


def _has_cn_ip(answer: list[dns.rrset.RRset]) -> bool:
    for ans in answer:
        if ans.rdclass == dns.rdataclass.IN \
            and ans.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) \
            and any(_is_cn_ip(x.address) for x in ans):
            return True
    return False


def _is_nat64_domain(name: dns.name.Name) -> str | None:
    """
    Check if domain is in format x.x.x.x.nat64 and return the IPv4 address if valid.
    Returns None if not a valid nat64 domain.
    """
    labels = [x.decode().lower() for x in name.labels if x]
    if len(labels) >= 5 and labels[-1] == 'nat64':
        # Try to parse the first 4 labels as IPv4 octets
        try:
            octets = labels[-5:-1]  # Get the 4 labels before 'nat64'
            ip_str = '.'.join(octets)
            # Validate it's a proper IPv4 address
            ipaddress.IPv4Address(ip_str)
            return ip_str
        except (ValueError, ipaddress.AddressValueError):
            pass
    return None


def _is_nat64_ptr_query(name: dns.name.Name, dns64_prefix: str) -> str | None:
    """
    Check if this is a PTR query for an IPv6 address that matches our DNS64 prefix.
    Returns the embedded IPv4 address if it matches, None otherwise.
    """
    labels = [x.decode().lower() for x in name.labels if x]

    # PTR queries for IPv6 are in ip6.arpa format
    if len(labels) < 34 or labels[-2:] != ['ip6', 'arpa']:
        return None

    # Extract the 32 hex digits (each label is one hex digit)
    hex_digits = labels[-34:-2]  # Skip 'ip6.arpa'
    if len(hex_digits) != 32:
        return None

    try:
        # Reverse the order and join to form IPv6 address
        hex_str = ''.join(reversed(hex_digits))
        # Insert colons every 4 characters
        ipv6_str = ':'.join(hex_str[i:i+4] for i in range(0, 32, 4))
        ipv6_addr = ipaddress.IPv6Address(ipv6_str)

        # Check if this IPv6 address starts with our DNS64 prefix
        prefix_addr = ipaddress.IPv6Address(dns64_prefix + '0.0.0.0')
        prefix_network = ipaddress.IPv6Network(f"{prefix_addr}/{96}")

        if ipv6_addr in prefix_network:
            # Extract the last 32 bits as IPv4 address
            ipv4_int = int(ipv6_addr) & 0xFFFFFFFF
            ipv4_addr = ipaddress.IPv4Address(ipv4_int)
            return str(ipv4_addr)

    except (ValueError, ipaddress.AddressValueError):
        pass

    return None


def _strip_cname(question_name: dns.name.Name, answer: list[dns.rrset.RRset]) -> list[dns.rrset.RRset]:
    """
    If the answer contains CNAME result for question_name and other result for the cname domain,
    remove the CNAME answer and change other result's name to the question_name
    """
    # Find CNAME record for the question name
    cname_target: dns.name.Name | None = None
    for rrset in answer:
        if (rrset.name == question_name and rrset.rdtype == dns.rdatatype.CNAME):
            # Get the CNAME target
            if len(rrset) > 0:
                cname_target = rrset[0].target
            break

    # Remove CNAME and rename target records to question name
    result = []
    for rrset in answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            # Skip the CNAME record
            continue
        elif rrset.name == cname_target:
            # Rename target records to question name
            new_rrset = dns.rrset.RRset(question_name, rrset.rdclass, rrset.rdtype, rrset.covers)
            new_rrset.ttl = rrset.ttl
            for rdata in rrset:
                new_rrset.add(rdata)
            result.append(new_rrset)
        elif rrset.name == question_name:
            # Keep other records as-is, only if it's for the question
            result.append(rrset)

    return result


def _map_rr(fn: tp.Callable[[dns.rdata.Rdata], dns.rdata.Rdata | None], answers: list[dns.rrset.RRset]) -> list[dns.rrset.RRset]:
    final_answers: list[dns.rrset.RRset] = []
    for rrset in answers:
        final_rrset = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype, rrset.covers)
        for rr in rrset:
            if final_rr := fn(rr):
                final_rrset.add(final_rr)
                final_answers.append(final_rrset)
    return final_answers


TP_K = tp.TypeVar('TP_K')
TP_V = tp.TypeVar('TP_V')

class CacheMap(tp.Generic[TP_K, TP_V]):
    '''
    Cache map, Size and/or Timed bound, asyncio-safe.
    '''
    def __init__(self, *,
                 max_cache_size: int = 16 * 1024,
                 max_cache_duration: float = 24 * 3600):
        self._max_cache_size = max_cache_size
        self._max_cache_duration = max_cache_duration
        # key -> (value, expire_timestamp). Also lru ordered
        self._kv: collections.OrderedDict[TP_K, tuple[TP_V, float]] = collections.OrderedDict()
        self._kv_fn: dict[TP_K, asyncio.Future[TP_V]] = {}
        self._lock = asyncio.Lock()

    def _get_locked(self, k: TP_K) -> TP_V:
        if k in self._kv:
            if self._kv[k][1] > time.monotonic():
                return self._kv[k][0]
        raise KeyError(f'Key not found: {k}')

    def _set_locked(self, k: TP_K, v: TP_V):
        now = time.monotonic()
        self._kv[k] = (v, now + self._max_cache_duration)
        while self._kv and (len(self._kv) > self._max_cache_size or
                            next(iter(self._kv.values()))[1] < now):
            self._kv.popitem(last=False)

    async def get_or_set(self, k: TP_K, v: TP_V) -> TP_V:
        '''
        If k exists in map, return its value;
        otherwise, set v as its value and return.
        '''
        async with self._lock:
            try:
                return self._get_locked(k)
            except KeyError:
                self._set_locked(k, v)
                return v

    async def get_or_set_by_fn(self, k: TP_K, fn: tp.Callable[[], tp.Coroutine[None, None, TP_V]]) -> TP_V:
        '''
        If k exists in map, return its value;
        otherwise, execute fn() and return its value; but if another job for the same key is already running, wait for it instead.
        '''
        future: asyncio.Future[TP_V] | None = None
        is_owner = False
        async with self._lock:
            try:
                return self._get_locked(k)
            except KeyError:
                future = self._kv_fn.get(k)
                if not future:
                    future = asyncio.create_task(fn())
                    self._kv_fn[k] = future
                    is_owner = True

        try:
            result = await future
        except asyncio.CancelledError:
            future.cancel()
            raise asyncio.TimeoutError()

        if is_owner:
            async with self._lock:
                del self._kv_fn[k]
                self._set_locked(k, result)

        return result


class DualStackResult(tp.NamedTuple):
    a: list[dns.rrset.RRset]
    aaaa: list[dns.rrset.RRset]


class Server:
    def __init__(self, *, dns64_prefix: str, config_path: str | None):
        self._domain_policies = _parse_domain_policies_from_config(config_path)
        self._resolve_dual_stack_cache: CacheMap[dns.name.Name, DualStackResult] = \
            CacheMap(max_cache_duration=30)

        self._dns64_prefix = dns64_prefix
        assert self._dns64_prefix.endswith('::')

        self._cn_upstream = '114.114.114.114'
        # Our VPS may have different isp for v4 and v6 network (e.g. due to tunneling),
        # so use v4 and v6 dns server for A and AAAA queries respectively.
        # For v4 dns server, use nat64 ip so that it is always sent through the nat64 gateway (not affected by ipv6 routes)
        # Use cloudflare because it does not use edns-client-subnet,
        # which means that our ipv6 source (yikai-net) does not affect the result of the geo-resolve.
        # e.g. using google ipv6 public dns service, google.com would point to an IP in Australia
        self._global_upstream_v4 = dns64_prefix + '1.1.1.1'
        self._global_upstream_v6 = '2606:4700:4700::1111'

    def _get_domain_policy(self, name: dns.name.Name) -> DomainPolicy:
        labels = [x.decode().lower() for x in name.labels if x]
        for i in range(1, len(labels)+1):
            suffix = '.'.join(labels[-i:])
            if res := self._domain_policies.get(suffix):
                return res
        return DomainPolicy()

    async def _resolve_dual_stack_cached(self, name: dns.name.Name) -> DualStackResult:
        return await self._resolve_dual_stack_cache.get_or_set_by_fn(name, lambda: self._resolve_dual_stack(name))

    async def _resolve_dual_stack(self, name: dns.name.Name) -> DualStackResult:
        """
        Resolve A and AAAA for domain at once.
        """
        policy = self._get_domain_policy(name)

        # Check if this is a nat64 domain (e.g., 1.2.3.4.nat64)
        if ipv4_addr := _is_nat64_domain(name):
            # Create synthetic AAAA record with DNS64 prefix + IPv4 address
            dns64_ans = dns.rrset.from_rdata_list(
                name, 300,  # 5 minute TTL
                [dns.rdtypes.IN.AAAA.AAAA(
                    dns.rdataclass.IN, dns.rdatatype.AAAA,
                    self._dns64_prefix + ipv4_addr,
                )])
            return DualStackResult(a=[], aaaa=[dns64_ans])

        # is_known_cn, forward to cn upstream
        if policy.is_known_cn_domain():
            resp = await dns.asyncquery.udp(
                dns.message.make_query(name, dns.rdatatype.A),
                policy.upstream or self._cn_upstream
            )
            return DualStackResult(a=resp.answer, aaaa=[])

        a_resp, aaaa_resp = await asyncio.gather(
            dns.asyncquery.udp(
                dns.message.make_query(name, dns.rdatatype.A),
                policy.upstream or self._global_upstream_v4,
            ),
            dns.asyncquery.udp(
                dns.message.make_query(name, dns.rdatatype.AAAA),
                policy.upstream or self._global_upstream_v6,
            ),
        )
        # guessed is cn, return ipv4 result
        is_cn = not policy.is_known_global_domain() and _has_cn_ip(a_resp.answer)
        if is_cn:
            return DualStackResult(a=a_resp.answer, aaaa=[])

        # global:

        # return native ipv6 if exists
        if not policy.ignore_native_ipv6 and \
           any(ans.rdclass == dns.rdataclass.IN and ans.rdtype == dns.rdatatype.AAAA
               and any(x.address != '::' for x in ans)
               for ans in aaaa_resp.answer):
            return DualStackResult(a=[], aaaa=aaaa_resp.answer)

        # return nat64 result
        result: list[dns.rrset.RRset] = []
        for ans in a_resp.answer:
            if ans.rdclass == dns.rdataclass.IN and ans.rdtype == dns.rdatatype.A:
                dns64_ans = dns.rrset.from_rdata_list(
                    ans.name, ans.ttl,
                    [dns.rdtypes.IN.AAAA.AAAA(
                        dns.rdataclass.IN, dns.rdatatype.AAAA,
                        self._dns64_prefix + data.address,
                    ) for data in ans])
                result.append(dns64_ans)
            else:
                result.append(ans)
        return DualStackResult(a=[], aaaa=result)

    async def _handle_query_a(self, question: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        result = await self._resolve_dual_stack_cached(question.name)
        return _strip_cname(question.name, result.a)

    async def _handle_query_aaaa(self, question: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        result = await self._resolve_dual_stack_cached(question.name)
        return _strip_cname(question.name, result.aaaa)

    async def _handle_query_ptr(self, question: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        """
        Handle PTR queries, including synthetic responses for nat64 domains.
        """
        # Check if this is a PTR query for a synthetic IPv6 address
        if ipv4_addr := _is_nat64_ptr_query(question.name, self._dns64_prefix):
            # Create synthetic PTR record pointing to .nat64 domain
            nat64_domain = f"{ipv4_addr}.nat64."
            ptr_ans = dns.rrset.from_rdata_list(
                question.name, 300,  # 5 minute TTL
                [dns.rdata.from_text(
                    dns.rdataclass.IN, dns.rdatatype.PTR,
                    nat64_domain,
                )])
            return [ptr_ans]

        # For regular PTR queries, forward to upstream
        resp = await dns.asyncquery.udp(
            dns.message.make_query(question.name, dns.rdatatype.PTR),
            self._global_upstream_v4,
        )
        return resp.answer

    async def _handle_query_https(self, question: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        upstream_response = await dns.asyncquery.udp(
            dns.message.make_query(question.name, dns.rdatatype.HTTPS),
            self._global_upstream_v4,
        )
        def _remove_address(rr: dns.rdata.Rdata) -> dns.rdata.Rdata:
            if rr.rdclass == dns.rdataclass.IN and rr.rdtype == dns.rdatatype.HTTPS:
                # Remove ipv4hint and ipv6hint from HTTPS answers
                rr = tp.cast(dns.rdtypes.IN.HTTPS.HTTPS, rr)
                return dns.rdtypes.IN.HTTPS.HTTPS(
                    rr.rdclass, rr.rdtype,
                    priority=rr.priority,
                    target=rr.target,
                    params=dict(kv for kv in rr.params.items()
                                if kv[0] not in (dns.rdtypes.svcbbase.ParamKey.IPV4HINT,
                                                dns.rdtypes.svcbbase.ParamKey.IPV6HINT))
                )
            return rr
        result = _map_rr(_remove_address, upstream_response.answer)
        return _strip_cname(question.name, result)

    async def _handle_query(self, request: dns.message.Message) -> dns.message.Message:
        question = request.question[0]
        logger.debug(f'Handling question {question}, domain policy {self._get_domain_policy(question.name)}')

        # Handle special record types
        answers: list[dns.rrset.RRset] | None = None
        if question.rdclass == dns.rdataclass.IN:
            if question.rdtype == dns.rdatatype.A:
                answers = await self._handle_query_a(question)
            elif question.rdtype == dns.rdatatype.AAAA:
                answers = await self._handle_query_aaaa(question)
            elif question.rdtype == dns.rdatatype.PTR:
                answers = await self._handle_query_ptr(question)
            elif question.rdtype == dns.rdatatype.HTTPS:
                answers = await self._handle_query_https(question)

        if answers is not None:
            response = dns.message.make_response(request, recursion_available=True)
            response.answer = answers
            return response

        # Forward all other queries to upstream
        return await dns.asyncquery.udp(request, self._global_upstream_v4)

    async def handle_query(self, request: dns.message.Message) -> dns.message.Message:
        try:
            async with asyncio.timeout(_SERVER_TIMEOUT):
                # note: on timeout, internal tasks would be cancelled, so they will not keep sockets (from asyncquery.udp) forever
                return await self._handle_query(request)
        except TimeoutError:
            response = dns.message.make_response(request, recursion_available=True)
            response.set_rcode(dns.rcode.SERVFAIL)
            return response


class Protocol(asyncio.DatagramProtocol):
    def __init__(self, server: Server):
        self._server = server
        self._transport: asyncio.transports.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.transports.DatagramTransport):
        self._transport = transport

    def datagram_received(self, data, addr):
        async def _handle():
            if not self._transport:
                return
            request = dns.message.from_wire(data)
            response = await self._server.handle_query(request)
            self._transport.sendto(response.to_wire(), addr)
        asyncio.get_running_loop().create_task(_handle())


async def main(server: Server, port: int):
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: Protocol(server),
        local_addr=('127.0.0.1', port),
    )
    try:
        await loop.create_future()
    finally:
        transport.close()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=53)
    parser.add_argument('--config')
    parser.add_argument('--dns64-prefix', type=str, default='64:ff9b::')
    parser.add_argument('--verbose', '-v', action='store_true', help='Increase verbosity')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    server = Server(dns64_prefix=args.dns64_prefix, config_path=args.config)
    asyncio.run(main(server, args.port))

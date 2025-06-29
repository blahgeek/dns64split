#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import collections
import functools
import os
import asyncio
import logging
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
    cn_domain: bool = False
    ignore_native_ipv6: bool = False
    upstream: str | None = None


def _parse_domain_policies_from_config(config_path: str | None) -> dict[str, DomainPolicy]:
    result = collections.defaultdict(lambda: DomainPolicy())
    # 1. special china domain list file
    result['cn'].cn_domain = True  # ".cn"
    with open(_CHINA_DOMAIN_LIST_PATH) as f:
        logger.info(f'Reading china domain list from {_CHINA_DOMAIN_LIST_PATH}')
        for line in f.readlines():
            line = line.strip()
            if line:
                result[line].cn_domain = True
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


TP_K = tp.TypeVar('TP_K')
TP_V = tp.TypeVar('TP_V')

class LruCacheMap(tp.Generic[TP_K, TP_V]):
    '''
    Lru cache map, asyncio-safe.
    '''
    def __init__(self, max_size: int):
        self._max_size = max_size
        self._kv: collections.OrderedDict[TP_K, TP_V] = collections.OrderedDict()
        self._lock = asyncio.Lock()

    async def get_or_set(self, k: TP_K, v: TP_V) -> TP_V:
        '''
        If k exists in map, return its value;
        otherwise, set v as its value and return.
        '''
        async with self._lock:
            if k in self._kv:
                self._kv.move_to_end(k)
                return self._kv[k]
            self._kv[k] = v
            if len(self._kv) > self._max_size:
                self._kv.popitem(last=False)
            return v


class Server:
    def __init__(self, *, dns64_prefix: str, config_path: str | None):
        self._domain_policies = _parse_domain_policies_from_config(config_path)
        # The result of "_has_cn_ip_answer" for a domain should be cached
        # because it needs to be consistant.
        # If, during an A query, the domain is treated as non-CN-ip-answer-domain,
        # and during an AAAA query, the domain is treated as yes,
        # then both responses would be empty.
        self._has_cn_ip_answer_domain_cache: \
            LruCacheMap[dns.name.Name, bool] = LruCacheMap(16 * 1024)

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

    def _is_cn_ip(self, ip: str) -> bool:
        try:
            res = get_geoip2_db().country(ip)
            return res.country.iso_code == 'CN'
        except geoip2.errors.AddressNotFoundError:
            return False

    def _is_nat64_domain(self, name: dns.name.Name) -> str | None:
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

    def _is_nat64_ptr_query(self, name: dns.name.Name) -> str | None:
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
            prefix_addr = ipaddress.IPv6Address(self._dns64_prefix + '0.0.0.0')
            prefix_network = ipaddress.IPv6Network(f"{prefix_addr}/{96}")

            if ipv6_addr in prefix_network:
                # Extract the last 32 bits as IPv4 address
                ipv4_int = int(ipv6_addr) & 0xFFFFFFFF
                ipv4_addr = ipaddress.IPv4Address(ipv4_int)
                return str(ipv4_addr)

        except (ValueError, ipaddress.AddressValueError):
            pass

        return None

    async def _has_cn_ip_answer(self, domain: dns.name.Name, answer: list[dns.rrset.RRset]) -> bool:
        result = False
        for ans in answer:
            if ans.rdclass == dns.rdataclass.IN \
               and ans.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) \
               and any(self._is_cn_ip(x.address) for x in ans):
                result = True
        return await self._has_cn_ip_answer_domain_cache.get_or_set(domain, result)

    async def _handle_query_a(self, question: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        '''
        Return A response as-is only if it's from CN
        '''
        if self._is_nat64_domain(question.name):
            return []

        policy = self._get_domain_policy(question.name)
        if policy.cn_domain:
            resp = await dns.asyncquery.udp(
                dns.message.make_query(question.name, dns.rdatatype.A),
                policy.upstream or self._cn_upstream
            )
            return resp.answer

        resp = await dns.asyncquery.udp(
            dns.message.make_query(question.name, dns.rdatatype.A),
            policy.upstream or self._global_upstream_v4,
        )
        if await self._has_cn_ip_answer(question.name, resp.answer):
            return resp.answer
        # hack: sleep for a short period of time before returning empty result
        # hopefully resolve an issue (firefox bug?) where NXDOMAIN error is shown in firefox
        await asyncio.sleep(0.1)
        return []

    async def _handle_query_aaaa(self, question: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        # Check if this is a nat64 domain (e.g., 1.2.3.4.nat64)
        if ipv4_addr := self._is_nat64_domain(question.name):
            # Create synthetic AAAA record with DNS64 prefix + IPv4 address
            dns64_ans = dns.rrset.from_rdata_list(
                question.name, 300,  # 5 minute TTL
                [dns.rdtypes.IN.AAAA.AAAA(
                    dns.rdataclass.IN, dns.rdatatype.AAAA,
                    self._dns64_prefix + ipv4_addr,
                )])
            return [dns64_ans]

        policy = self._get_domain_policy(question.name)
        if policy.cn_domain:
            return []

        a_resp, aaaa_resp = await asyncio.gather(
            dns.asyncquery.udp(
                dns.message.make_query(question.name, dns.rdatatype.A),
                policy.upstream or self._global_upstream_v4,
            ),
            dns.asyncquery.udp(
                dns.message.make_query(question.name, dns.rdatatype.AAAA),
                policy.upstream or self._global_upstream_v6,
            ),
        )

        if await self._has_cn_ip_answer(question.name, a_resp.answer):
            return []

        if not policy.ignore_native_ipv6 and \
           any(ans.rdclass == dns.rdataclass.IN and ans.rdtype == dns.rdatatype.AAAA
               for ans in aaaa_resp.answer):
            return aaaa_resp.answer

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
        return result

    async def _handle_query_ptr(self, question: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        """
        Handle PTR queries, including synthetic responses for nat64 domains.
        """
        # Check if this is a PTR query for a synthetic IPv6 address
        if ipv4_addr := self._is_nat64_ptr_query(question.name):
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

    def _filter_special_answer_rr(self, rr: dns.rdata.Rdata) -> dns.rdata.Rdata | None:
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

    def _filter_special_answer(self, answers: list[dns.rrset.RRset]) -> list[dns.rrset.RRset]:
        '''
        Filter answers that is not A or AAAA.
        '''
        final_answers: list[dns.rrset.RRset] = []
        for rrset in answers:
            final_rrset = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype, rrset.covers)
            for rr in rrset:
                if final_rr := self._filter_special_answer_rr(rr):
                    final_rrset.add(final_rr)
                    final_answers.append(final_rrset)
        return final_answers

    async def _handle_query(self, request: dns.message.Message) -> dns.message.Message:
        question = request.question[0]
        logger.debug(f'Handling question {question}, domain policy {self._get_domain_policy(question.name)}')

        # Handle special record types (A, AAAA, PTR) for IN class
        if question.rdclass == dns.rdataclass.IN and question.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.PTR):
            response = dns.message.make_response(request, recursion_available=True)
            if question.rdtype == dns.rdatatype.A:
                response.answer = await self._handle_query_a(question)
            elif question.rdtype == dns.rdatatype.AAAA:
                response.answer = await self._handle_query_aaaa(question)
            elif question.rdtype == dns.rdatatype.PTR:
                response.answer = await self._handle_query_ptr(question)
            return response

        # Forward all other queries to upstream
        response = await dns.asyncquery.udp(request, self._global_upstream_v4)
        response.answer = self._filter_special_answer(response.answer)
        return response

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
        local_addr=('0.0.0.0', port),
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

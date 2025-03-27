#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import collections
import enum
import functools
import os
import asyncio
import logging

import geoip2.database
import geoip2.errors
import dns.name
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.query
import dns.rrset
import dns.rcode
import dns.rdtypes.IN.AAAA
import dns.asyncquery


_GEOLITE2_COUNTRY_DB_PATH = os.path.join(os.path.dirname(__file__), 'data/GeoLite2-Country.mmdb')
_CHINA_DOMAIN_LIST_PATH = os.path.join(os.path.dirname(__file__), 'data/china-domain-list.txt')

# use one.one.one.one because it does not use edns-client-subnet,
# which means that our ipv6 source (yikai-net) does not affect the result of the geo-resolve.
# e.g. using google ipv6 public dns service, google.com would point to an IP in Australia
_GLOBAL_UPSTREAM = '2606:4700:4700::1111'
_CN_UPSTREAM = '114.114.114.114'

_SERVER_TIMEOUT = 5.0

logger = logging.getLogger('dns64split')


class DomainPolicy(enum.Flag):
    CN_DOMAIN = enum.auto()
    IGNORE_NATIVE_IPV6 = enum.auto()


def _parse_domain_policies_from_config(config_path: str | None) -> dict[str, DomainPolicy]:
    result = collections.defaultdict(lambda: DomainPolicy(0))
    # 1. special china domain list file
    result['cn'] |= DomainPolicy.CN_DOMAIN  # ".cn"
    with open(_CHINA_DOMAIN_LIST_PATH) as f:
        logger.info(f'Reading china domain list from {_CHINA_DOMAIN_LIST_PATH}')
        for line in f.readlines():
            line = line.strip()
            if line:
                result[line] |= DomainPolicy.CN_DOMAIN
    # 2. config file
    # each line format:
    # <domain>:<policy1>,<policy2>
    if config_path and os.path.exists(config_path):
        logger.info(f'Reading config from {config_path}')
        with open(config_path) as f:
            for line in f.readlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                domain, _, policies = line.partition(':')
                for policy in policies.split(','):
                    result[domain] |= getattr(DomainPolicy, policy.upper())
    return dict(result)

@functools.cache
def get_geoip2_db() -> geoip2.database.Reader:
    return geoip2.database.Reader(_GEOLITE2_COUNTRY_DB_PATH)


class Server:
    def __init__(self, *, dns64_prefix: str, config_path: str | None):
        self._domain_policies = _parse_domain_policies_from_config(config_path)
        self._dns64_prefix = dns64_prefix
        assert self._dns64_prefix.endswith(':')

    def _get_domain_policy(self, name: dns.name.Name) -> DomainPolicy:
        labels = [x.decode().lower() for x in name.labels if x]
        for i in range(1, len(labels)+1):
            suffix = '.'.join(labels[-i:])
            if res := self._domain_policies.get(suffix):
                return res
        return DomainPolicy(0)

    def _is_cn_ip(self, ip: str) -> bool:
        try:
            res = get_geoip2_db().country(ip)
            return res.country.iso_code == 'CN'
        except geoip2.errors.AddressNotFoundError:
            return False

    def _is_cn_ip_answer(self, answer: list[dns.rrset.RRset]) -> bool:
        for ans in answer:
            if ans.rdclass == dns.rdataclass.IN \
               and ans.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) \
               and any(self._is_cn_ip(x.address) for x in ans):
                return True
        return False

    async def _handle_query_a(self, question: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        '''
        Return A response as-is only if it's from CN
        '''
        policy = self._get_domain_policy(question.name)
        resp = await dns.asyncquery.udp(
            dns.message.make_query(question.name, dns.rdatatype.A),
            _CN_UPSTREAM if DomainPolicy.CN_DOMAIN in policy else _GLOBAL_UPSTREAM,
        )
        return resp.answer if DomainPolicy.CN_DOMAIN in policy or self._is_cn_ip_answer(resp.answer) else []

    async def _handle_query_aaaa(self, question: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        policy = self._get_domain_policy(question.name)
        if DomainPolicy.CN_DOMAIN in policy:
            return []

        a_resp, aaaa_resp = await asyncio.gather(
            dns.asyncquery.udp(
                dns.message.make_query(question.name, dns.rdatatype.A),
                _GLOBAL_UPSTREAM,
            ),
            dns.asyncquery.udp(
                dns.message.make_query(question.name, dns.rdatatype.AAAA),
                _GLOBAL_UPSTREAM,
            ),
        )

        if self._is_cn_ip_answer(a_resp.answer):
            return []

        if DomainPolicy.IGNORE_NATIVE_IPV6 not in policy and \
           any(ans.rdclass == dns.rdataclass.IN and ans.rdtype == dns.rdatatype.AAAA
               for ans in aaaa_resp.answer):
            return aaaa_resp.answer

        result: list[dns.rrset.RRset] = []
        for ans in a_resp.answer:
            if ans.rdclass == dns.rdataclass.IN and ans.rdtype == dns.rdatatype.A:
                dns64_ans = dns.rrset.RRset(ans.name, dns.rdataclass.IN, dns.rdatatype.AAAA)
                for data in ans:
                    dns64_ans.add(dns.rdtypes.IN.AAAA.AAAA(
                        dns.rdataclass.IN, dns.rdatatype.AAAA,
                        self._dns64_prefix + data.address,
                    ))
                result.append(dns64_ans)
            else:
                result.append(ans)
        return result

    async def _handle_query(self, request: dns.message.Message) -> dns.message.Message:
        question = request.question[0]
        logger.debug(f'Handling question {question}, domain policy {self._get_domain_policy(question.name)}')
        if question.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA) or \
           question.rdclass != dns.rdataclass.IN:
            return await dns.asyncquery.udp(request, _GLOBAL_UPSTREAM)

        response = dns.message.make_response(request, recursion_available=True)
        response.answer = await (
            self._handle_query_a(question) if question.rdtype == dns.rdatatype.A
            else self._handle_query_aaaa(question)
        )
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


def run_forever(server: Server, port: int):
    loop = asyncio.new_event_loop()
    loop.create_task(loop.create_datagram_endpoint(
        lambda: Protocol(server),
        local_addr=('0.0.0.0', port),
    ))
    loop.run_forever()


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
    run_forever(server, args.port)

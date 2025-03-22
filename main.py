#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import asyncio

import geoip2.database
import dns.name
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.query
import dns.rrset
import dns.rdtypes.IN.AAAA
import dns.asyncquery


_GEOLITE2_COUNTRY_DB_PATH = os.path.join(os.path.dirname(__file__), 'data/GeoLite2-Country.mmdb')
_CHINA_DOMAIN_LIST_PATH = os.path.join(os.path.dirname(__file__), 'data/china-domain-list.txt')

_GLOBAL_UPSTREAM = '8.8.8.8'
_CN_UPSTREAM = '114.114.114.114'

class Server:
    def __init__(self, *, dns64_prefix: str):
        self._geoip_db = geoip2.database.Reader(_GEOLITE2_COUNTRY_DB_PATH)
        self._dns64_prefix = dns64_prefix
        assert self._dns64_prefix.endswith(':')

        with open(_CHINA_DOMAIN_LIST_PATH) as f:
            self._china_domain_list = set(line.strip() for line in f.readlines() if line.strip())

    def _is_cn_domain(self, name: dns.name.Name) -> bool:
        labels = [x.decode().lower() for x in name.labels if x]
        if labels and labels[-1] == 'cn':
            return True
        for i in range(1, len(labels)):
            suffix = '.'.join(labels[-i:])
            if suffix in self._china_domain_list:
                return True
        return False

    def _is_cn_ip(self, ip: str) -> bool:
        res = self._geoip_db.country(ip)
        return res.country.iso_code == 'CN'

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
        resp = await dns.asyncquery.udp(
            dns.message.make_query(question.name, dns.rdatatype.A),
            _CN_UPSTREAM if self._is_cn_domain(question.name) else _GLOBAL_UPSTREAM,
        )
        return resp.answer if self._is_cn_ip_answer(resp.answer) else []

    async def _handle_query_aaaa(self, question: dns.rrset.RRset) -> list[dns.rrset.RRset]:
        if self._is_cn_domain(question.name):
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

        if aaaa_resp.get_rrset(dns.message.ANSWER, question.name, dns.rdataclass.IN, dns.rdatatype.AAAA):
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

    async def handle_query(self, request: dns.message.Message) -> dns.message.Message:
        question = request.question[0]
        if question.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA) or \
           question.rdclass != dns.rdataclass.IN:
            return await dns.asyncquery.udp(request, _GLOBAL_UPSTREAM)

        response = dns.message.make_response(request, recursion_available=True)
        response.answer = await (
            self._handle_query_a(question) if question.rdtype == dns.rdatatype.A
            else self._handle_query_aaaa(question)
        )
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
    parser.add_argument('--dns64-prefix', type=str, default='64:ff9b::')
    args = parser.parse_args()

    server = Server(dns64_prefix=args.dns64_prefix)
    run_forever(server, args.port)

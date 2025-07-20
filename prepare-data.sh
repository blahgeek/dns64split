#!/bin/bash

cd "$(dirname "$0")"

curl -L -o data/GeoLite2-Country.mmdb https://git.io/GeoLite2-Country.mmdb

curl -L -o - https://github.com/felixonmars/dnsmasq-china-list/raw/refs/heads/master/accelerated-domains.china.conf \
     | sed -E 's/server=\/([^\/]+)\/.*/\1/' > data/china-domain-list.txt
curl -L -o - https://github.com/felixonmars/dnsmasq-china-list/raw/refs/heads/master/apple.china.conf \
     | sed -E 's/server=\/([^\/]+)\/.*/\1/' >> data/china-domain-list.txt


# https://github.com/felixonmars/dnsmasq-china-list/issues/682
SED="sed"
# if it's macos, use gsed. use uname
if [[ "$(uname)" == "Darwin" ]]; then
    SED="gsed"
fi

"$SED" -i '/^top$/d' data/china-domain-list.txt


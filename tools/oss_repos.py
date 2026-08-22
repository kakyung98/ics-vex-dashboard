#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Component -> upstream repository / release map for the Data Processor (paper §3.1.1).

For each OSS component in tools/generate_ics_sbom.py:OSS, declare how to locate the
vulnerable version's *source*: a GitHub repo (archive-zip by tag) and/or a release
tarball URL, plus the tag-naming templates that project uses. `closed=True` marks
software with no obtainable public source (the honest ceiling).

Tag templates use two forms of the version:
  {v} = dotted     e.g. 1.1.1g, 3.31.1, 2.9.10
  {u} = underscore e.g. 1_1_1g, 3_31_1, 2_9_10
The resolver tries each template, verifies the tag really exists (GitHub refs API),
and falls back to listing+fuzzy-matching tags.
"""

# gh   : "owner/repo" (GitHub archive zip = https://github.com/<gh>/archive/refs/tags/<tag>.zip)
# tags : list of tag templates (first that resolves wins)
# tarball : optional non-GitHub source tarball URL template ({v} dotted)
# closed : no public source
OSS_REPOS = {
    "openssl":    dict(gh="openssl/openssl",            tags=["OpenSSL_{u}", "openssl-{v}"]),
    "libcurl":    dict(gh="curl/curl",                  tags=["curl-{u}", "curl-{v}"]),
    "busybox":    dict(gh="mirror/busybox",             tags=["{u}", "1_{u}"],
                       tarball="https://busybox.net/downloads/busybox-{v}.tar.bz2"),
    "libxml2":    dict(gh="GNOME/libxml2",              tags=["v{v}", "v{v}-1"]),
    "expat":      dict(gh="libexpat/libexpat",          tags=["R_{u}"]),
    "sqlite":     dict(gh="sqlite/sqlite",              tags=["version-{v}"]),
    "glibc":      dict(gh="bminor/glibc",               tags=["glibc-{v}"]),
    "openssh":    dict(gh="openssh/openssh-portable",   tags=["V_{u}"]),   # 9_3_P1 style handled in resolver
    "net_snmp":   dict(gh="net-snmp/net-snmp",          tags=["v{v}", "net-snmp-{v}"]),
    "goahead":    dict(gh="embedthis/goahead",          tags=["v{v}"]),
    "nginx":      dict(gh="nginx/nginx",                tags=["release-{v}"]),
    "u_boot":     dict(gh="u-boot/u-boot",              tags=["v{v}"]),
    "openvpn":    dict(gh="OpenVPN/openvpn",            tags=["v{v}"]),
    "libssh2":    dict(gh="libssh2/libssh2",            tags=["libssh2-{v}"]),
    "dropbear":   dict(gh="mkj/dropbear",               tags=["DROPBEAR_{v}", "DROPBEAR_{u}"]),
    "log4j":      dict(gh="apache/logging-log4j2",      tags=["rel/{v}", "log4j-{v}"]),
    "spring":     dict(gh="spring-projects/spring-framework", tags=["v{v}"]),
    "linux_kernel": dict(gh="gregkh/linux",             tags=["v{v}"], huge=True,
                       tarball="https://cdn.kernel.org/pub/linux/kernel/v{maj}.x/linux-{v}.tar.gz"),
    # non-GitHub upstreams (tarball only; cve-genie cache needs a .zip so these stay snapshot-only)
    "dnsmasq":    dict(tarball="https://thekelleys.org.uk/dnsmasq/dnsmasq-{v}.tar.gz"),
    "wpa_supplicant": dict(tarball="https://w1.fi/releases/wpa_supplicant-{v}.tar.gz"),
    "ntp":        dict(tarball="https://downloads.ntp.org/ntp/ntp-{v}.tar.gz"),
    # closed source — honest ceiling
    "codesys_rt":        dict(closed=True),
    "ipnet":             dict(closed=True),   # Wind River / Interpeak
    "treck_tcpip":       dict(closed=True),
    "sqlserver_express": dict(closed=True),
    "dotnet":            dict(closed=True),   # .NET Framework 4.8 (closed)
}

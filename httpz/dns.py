#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# httpz/dns.py

import asyncio
import os
import aiohttp
import dns.asyncresolver
import dns.query
import dns.resolver
import dns.zone

from .utils import debug, info, SILENT_MODE

async def resolve_all_dns(domain: str, timeout: int = 5, nameserver: str = None, check_axfr: bool = False) -> tuple:
    '''
    Resolve all DNS records for a domain
    
    :param domain: Domain to resolve
    :param timeout: Timeout in seconds
    :param nameserver: Specific nameserver to use
    :param check_axfr: Whether to attempt zone transfer
    '''
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    if nameserver:
        resolver.nameservers = [nameserver]
    
    results = await asyncio.gather(*[resolver.resolve(domain, rtype) 
                                   for rtype in ('NS', 'A', 'AAAA', 'CNAME')], 
                                 return_exceptions=True)
    
    nameservers = [str(ns).rstrip('.') for ns in results[0]] if isinstance(results[0], dns.resolver.Answer) else []
    ips = ([str(ip) for ip in results[1]] if isinstance(results[1], dns.resolver.Answer) else []) + \
          ([str(ip) for ip in results[2]] if isinstance(results[2], dns.resolver.Answer) else [])
    cname = str(results[3][0].target).rstrip('.') if isinstance(results[3], dns.resolver.Answer) else None
    
    ns_ips = {}
    if nameservers:
        ns_results = await asyncio.gather(*[resolver.resolve(ns, rtype) 
                                          for ns in nameservers 
                                          for rtype in ('A', 'AAAA')], 
                                        return_exceptions=True)
        for i, ns in enumerate(nameservers):
            ns_ips[ns] = [str(ip) for records in ns_results[i*2:i*2+2] 
                         if isinstance(records, dns.resolver.Answer) 
                         for ip in records]

    if check_axfr:
        await attempt_axfr(domain, ns_ips, timeout)

    return sorted(set(ips)), cname, nameservers, ns_ips

async def attempt_axfr(domain: str, ns_ips: dict, timeout: int = 5) -> None:
    '''
    Attempt zone transfer for a domain
    
    :param domain: Domain to attempt AXFR transfer
    :param ns_ips: Dictionary of nameserver hostnames to their IPs
    :param timeout: Timeout in seconds
    '''
    try:
        os.makedirs('axfrout', exist_ok=True)
        
        for ns_host, ips in ns_ips.items():
            for ns_ip in ips:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=timeout))
                    with open(f'axfrout/{domain}_{ns_ip}.zone', 'w') as f:
                        zone.to_text(f)
                    info(f'[AXFR SUCCESS] {domain} from {ns_host} ({ns_ip})')
                except Exception as e:
                    debug(f'AXFR failed for {domain} from {ns_ip}: {str(e)}')
    except Exception as e:
        debug(f'Failed AXFR for {domain}: {str(e)}')

async def load_resolvers(resolver_file: str = None) -> list:
    '''
    Load DNS resolvers from file or default source
    
    :param resolver_file: Path to file containing resolver IPs
    :return: List of resolver IPs
    '''
    if resolver_file:
        try:
            with open(resolver_file) as f:
                resolvers = [line.strip() for line in f if line.strip()]
            if resolvers:
                return resolvers
        except Exception as e:
            debug(f'Error loading resolvers from {resolver_file}: {str(e)}')

    async with aiohttp.ClientSession() as session:
        async with session.get('https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt') as response:
            resolvers = await response.text()
            if not SILENT_MODE:
                info(f'Loaded {len(resolvers.splitlines()):,} resolvers.')
            return [resolver.strip() for resolver in resolvers.splitlines()] 
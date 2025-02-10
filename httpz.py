#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)

'''
BCUZ FUCK PROJECT DISCOVERY PYTHON STILL GO HARD
REAL BAY SHIT FOR REAL BAY MOTHER FUCKERS
'''

import argparse
import asyncio
import itertools
import json
import logging
from pathlib import Path
import sys
import os
import dns.zone
import dns.query
import dns.resolver

try:
	import aiohttp
except ImportError:
	raise ImportError('missing \'aiohttp\' library (pip install aiohttp)')

try:
	import apv
except ImportError:
	raise ImportError('missing \'apv\' library (pip install apv)')

try:
	import bs4
except ImportError:
	raise ImportError('missing \'bs4\' library (pip install beautifulsoup4)')

try:
	from cryptography                   import x509
	from cryptography.hazmat.primitives import hashes
	from cryptography.x509.oid          import NameOID
except ImportError:
	raise ImportError('missing \'cryptography\' library (pip install cryptography)')

try:
	import dns.asyncresolver
except ImportError:
	raise ImportError('missing \'dns\' library (pip install dnspython)')

try:
	import mmh3
except ImportError:
	raise ImportError('missing \'mmh3\' library (pip install mmh3)')


class Colors:
	'''ANSI color codes for terminal output'''

	HEADER     = '\033[95m' # Light purple
	BLUE       = '\033[94m'
	GREEN      = '\033[92m'
	YELLOW     = '\033[93m'
	RED        = '\033[91m'
	BOLD       = '\033[1m'
	UNDERLINE  = '\033[4m'
	RESET      = '\033[0m'
	PURPLE     = '\033[35m'       # Dark purple
	LIGHT_RED  = '\033[38;5;203m' # Light red
	DARK_GREEN = '\033[38;5;22m'  # Dark green
	PINK       = '\033[38;5;198m' # Bright pink


_SILENT_MODE = False

def debug(msg: str) -> None:
	'''Print debug message if not in silent mode'''
	if not _SILENT_MODE:
		logging.debug(msg)

def error(msg: str) -> None:
	'''Print error message if not in silent mode'''
	if not _SILENT_MODE:
		logging.error(msg)

def info(msg: str) -> None:
	'''Print info message if not in silent mode'''
	if not _SILENT_MODE:
		logging.info(msg)


async def resolve_dns(domain: str) -> tuple:
	'''
	Resolve A, AAAA, and CNAME records for a domain
	
	:param domain: domain to resolve
	:return: tuple of (ips, cname)
	'''

	resolver = dns.asyncresolver.Resolver()
	ips      = []
	cname    = None

	try:
		# Check for CNAME first
		cname_result = await resolver.resolve(domain, 'CNAME')
		cname        = str(cname_result[0].target).rstrip('.')
	except Exception:
		pass

	try:
		# Query A records
		a_result = await resolver.resolve(domain, 'A')
		ips.extend(str(ip) for ip in a_result)
	except Exception as e:
		debug(f'Error resolving A records for {domain}: {str(e)}')

	try:
		# Query AAAA records
		aaaa_result = await resolver.resolve(domain, 'AAAA')
		ips.extend(str(ip) for ip in aaaa_result)
	except Exception as e:
		debug(f'Error resolving AAAA records for {domain}: {str(e)}')

	return sorted(set(ips)), cname


async def get_favicon_hash(session: aiohttp.ClientSession, base_url: str, html: str) -> str:
	'''
	Get favicon hash from a webpage
	
	:param session: aiohttp client session
	:param base_url: base URL of the website
	:param html: HTML content of the page
	'''

	try:
		soup = bs4.BeautifulSoup(html, 'html.parser')
		
		# Try to find favicon in link tags
		favicon_url = None
		for link in soup.find_all('link'):
			if link.get('rel') and any(x.lower() == 'icon' for x in link.get('rel')):
				favicon_url = link.get('href')
				break
		
		if not favicon_url:
			# Try default location
			favicon_url = '/favicon.ico'
		
		# Handle relative URLs
		if favicon_url.startswith('//'):
			favicon_url = 'https:' + favicon_url
		elif favicon_url.startswith('/'):
			favicon_url = base_url + favicon_url
		elif not favicon_url.startswith(('http://', 'https://')):
			favicon_url = base_url + '/' + favicon_url

		async with session.get(favicon_url, timeout=10) as response:
			if response.status == 200:
				content = await response.read()
				if len(content) <= 1024*1024:  # Check if favicon is <= 1MB
					hash_value = mmh3.hash64(content)[0]
					# Only return hash if it's not 0 (likely invalid favicon)
					if hash_value != 0:
						return str(hash_value)
	except Exception as e:
		debug(f'Error getting favicon for {base_url}: {str(e)}')
	
	return None


async def get_cert_info(session: aiohttp.ClientSession, url: str) -> dict:
	'''
	Get SSL certificate information for a domain
	
	:param session: aiohttp client session
	:param url: URL to check
	'''

	try:
		async with session.get(url, timeout=10) as response:
			# Get the SSL context from the connection
			ssl_object = response.connection.transport.get_extra_info('ssl_object')
			if not ssl_object:
				return None
				
			cert_bin = ssl_object.getpeercert(binary_form=True)
			cert      = x509.load_der_x509_certificate(cert_bin)
			
			# Get certificate details
			cert_info = {
				'fingerprint' : cert.fingerprint(hashes.SHA256()).hex(),
				'subject'     : cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
				'issuer'      : cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
				'alt_names'   : [],
				'not_before'  : cert.not_valid_before_utc.isoformat(),
				'not_after'   : cert.not_valid_after_utc.isoformat()
			}
			
			# Get Subject Alternative Names
			try:
				ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
				cert_info['alt_names'] = [name.value for name in ext.value]
			except x509.ExtensionNotFound:
				pass
			
			return cert_info
	except Exception as e:
		debug(f'Error getting certificate info for {url}: {str(e)}')
		return None


async def check_domain(session: aiohttp.ClientSession, domain: str, follow_redirects: bool = False, timeout: int = 5, check_axfr: bool = False) -> dict:
	'''
	Check a single domain for its status code, title, and body preview
	
	:param session: aiohttp client session
	:param domain: domain to check
	:param follow_redirects: whether to follow redirects
	:param timeout: timeout in seconds
	:param check_axfr: whether to check for AXFR
	'''

	if not domain.startswith(('http://', 'https://')):
		protocols = ['https://', 'http://']
		base_domain = domain
	else:
		protocols = [domain]
		base_domain = domain.split('://')[-1].split('/')[0]

	result = {
		'domain'         : base_domain,
		'status'         : 0,
		'title'          : None,
		'body'           : None,
		'content_type'   : None,
		'url'            : f"https://{base_domain}" if base_domain else domain,
		'ips'            : [],
		'cname'          : None,
		'favicon_hash'   : None,
		'headers'        : {},
		'content_length' : None,
		'redirect_chain' : [],
		'tls'            : None
	}

	# Resolve DNS records
	result['ips'], result['cname'] = await resolve_dns(base_domain)

	for protocol in protocols:
		url = f'{protocol}{base_domain}'
		try:
			max_redirects = 10 if follow_redirects else 0
			async with session.get(url, timeout=timeout, allow_redirects=follow_redirects, max_redirects=max_redirects) as response:
				result['status']         = response.status
				result['url']            = str(response.url)
				result['headers']        = dict(response.headers)
				result['content_type']   = response.headers.get('content-type', '').split(';')[0]
				result['content_length'] = response.headers.get('content-length')
				
				# Track redirect chain
				if follow_redirects:
					result['redirect_chain'] = [str(h.url) for h in response.history]
					if result['redirect_chain']:
						result['redirect_chain'].append(str(response.url))

				# Get TLS info if HTTPS
				if url.startswith('https://'):
					result['tls'] = await get_cert_info(session, url)

				if response.status == 200:
					html = (await response.text())[:1024*1024]
					soup = bs4.BeautifulSoup(html, 'html.parser')
					if soup.title:
						title = ' '.join(soup.title.string.strip().split()) if soup.title.string else ''
						result['title'] = title[:300]
					if soup.get_text():
						body = ' '.join(soup.get_text().split())
						result['body'] = body[:500]
					result['favicon_hash'] = await get_favicon_hash(session, url, html)
					break
		except Exception as e:
			debug(f'Error checking {url}: {str(e)}')
			result['status'] = -1
			continue

	if check_axfr:
		await try_axfr(base_domain)

	return result


def domain_generator(input_source: str):
	'''
	Generator function to yield domains from file or stdin
	
	:param input_source: path to file containing domains, or None for stdin
	'''

	if input_source == '-' or input_source is None:
		for line in sys.stdin:
			if line.strip():
				yield line.strip()
	else:
		with open(input_source, 'r') as f:
			for line in f:
				if line.strip():
					yield line.strip()


def human_size(size_bytes: int) -> str:
	'''
	Convert bytes to human readable string
	
	:param size_bytes: Size in bytes
	'''

	if not size_bytes:
		return '0B'
	
	units = ('B', 'KB', 'MB', 'GB')
	size = float(size_bytes)
	unit_index = 0
	
	while size >= 1024 and unit_index < len(units) - 1:
		size /= 1024
		unit_index += 1
	
	return f"{size:.1f}{units[unit_index]}"


def parse_status_codes(codes_str: str) -> set:
	'''
	Parse comma-separated status codes into a set of integers
	
	:param codes_str: Comma-separated status codes
	'''

	try:
		return {int(code.strip()) for code in codes_str.split(',')}
	except ValueError:
		raise argparse.ArgumentTypeError('Status codes must be comma-separated numbers (e.g., 200,301,404)')


def format_status_output(result: dict, debug: bool = False, show_fields: dict = None, match_codes: set = None, exclude_codes: set = None) -> str:
	'''
	Format the output with colored sections
	
	:param result: Dictionary containing domain check results
	:param debug: Whether to show error states
	:param show_fields: Dictionary of fields to show
	:param match_codes: Set of status codes to match
	:param exclude_codes: Set of status codes to exclude
	'''

	# Skip errors unless in debug mode
	if result['status'] < 0 and not debug:
		return ''
		
	# Skip if status code doesn't match filters
	if match_codes and result['status'] not in match_codes:
		return ''
	if exclude_codes and result['status'] in exclude_codes:
		return ''

	parts = []
	
	# Status code
	if show_fields['status_code']:
		if result['status'] < 0:
			status = f"{Colors.RED}[{result['status']}]{Colors.RESET}"
		elif 200 <= result['status'] < 300:
			status = f"{Colors.GREEN}[{result['status']}]{Colors.RESET}"
		elif 300 <= result['status'] < 400:
			status = f"{Colors.YELLOW}[{result['status']}]{Colors.RESET}"
		else:  # 400+ and 500+ codes
			status = f"{Colors.RED}[{result['status']}]{Colors.RESET}"
		parts.append(status)
	
	# Domain (always shown)
	parts.append(f"[{result['url']}]")
	
	# Title
	if show_fields['title'] and result['title']:
		parts.append(f"{Colors.DARK_GREEN}[{result['title']}]{Colors.RESET}")
	
	# Body
	if show_fields['body'] and result['body']:
		body = result['body'][:100] + ('...' if len(result['body']) > 100 else '')
		parts.append(f"{Colors.BLUE}[{body}]{Colors.RESET}")
	
	# IPs
	if show_fields['ip'] and result['ips']:
		ips_text = ', '.join(result['ips'])
		parts.append(f"{Colors.YELLOW}[{ips_text}]{Colors.RESET}")

	# Favicon hash
	if show_fields['favicon'] and result['favicon_hash']:
		parts.append(f"{Colors.PURPLE}[{result['favicon_hash']}]{Colors.RESET}")

	# Headers (includes content-type and content-length)
	if show_fields['headers'] and result['headers']:
		headers_text = []
		for k, v in result['headers'].items():
			headers_text.append(f"{k}: {v}")
		parts.append(f"{Colors.LIGHT_RED}[{', '.join(headers_text)}]{Colors.RESET}")
	else:
		# Only show content-type and content-length if headers aren't shown
		if show_fields['content_type'] and result['content_type']:
			parts.append(f"{Colors.HEADER}[{result['content_type']}]{Colors.RESET}")
		
		if show_fields['content_length'] and result['content_length']:
			try:
				size = human_size(int(result['content_length']))
				parts.append(f"{Colors.PINK}[{size}]{Colors.RESET}")
			except (ValueError, TypeError):
				parts.append(f"{Colors.PINK}[{result['content_length']}]{Colors.RESET}")
	
	# CNAME
	if show_fields['cname'] and result['cname']:
		parts.append(f"{Colors.PURPLE}[CNAME: {result['cname']}]{Colors.RESET}")
	
	# Redirect Chain
	if show_fields['follow_redirects'] and result['redirect_chain']:
		chain = ' -> '.join(result['redirect_chain'])
		parts.append(f"{Colors.YELLOW}[Redirects: {chain}]{Colors.RESET}")

	# TLS Certificate Info
	if show_fields['tls'] and result['tls']:
		cert = result['tls']
		tls_parts = []
		tls_parts.append(f"Fingerprint: {cert['fingerprint']}")
		tls_parts.append(f"Subject: {cert['subject']}")
		tls_parts.append(f"Issuer: {cert['issuer']}")
		if cert['alt_names']:
			tls_parts.append(f"SANs: {', '.join(cert['alt_names'])}")
		tls_parts.append(f"Valid: {cert['not_before']} to {cert['not_after']}")
		parts.append(f"{Colors.GREEN}[{' | '.join(tls_parts)}]{Colors.RESET}")

	return ' '.join(parts)


def count_domains(input_source: str = None) -> int:
	'''
	Count total number of domains from file or stdin
	
	:param input_source: path to file containing domains, or None for stdin
	'''
	if input_source == '-' or input_source is None:
		# Can't count lines from stdin without consuming them
		return 0
	else:
		with open(input_source, 'r') as f:
			return sum(1 for line in f if line.strip())


async def process_domains(input_source: str = None, debug: bool = False, concurrent_limit: int = 100, show_fields: dict = None, output_file: str = None, jsonl: bool = None, timeout: int = 5, match_codes: set = None, exclude_codes: set = None, show_progress: bool = False, check_axfr: bool = False):
	'''
	Process domains from a file or stdin with concurrent requests
	
	:param input_source: path to file containing domains, or None for stdin
	:param debug: Whether to show error states
	:param concurrent_limit: maximum number of concurrent requests
	:param show_fields: Dictionary of fields to show
	:param output_file: Path to output file (JSONL format)
	:param timeout: Request timeout in seconds
	:param match_codes: Set of status codes to match
	:param exclude_codes: Set of status codes to exclude
	:param show_progress: Whether to show progress counter
	:param check_axfr: Whether to check for AXFR
	'''

	if input_source and input_source != '-' and not Path(input_source).exists():
		raise FileNotFoundError(f'Domain file not found: {input_source}')

	# Get total domain count if showing progress (only works for files)
	total_domains     = count_domains(input_source) if show_progress else 0
	processed_domains = 0

	# Clear the output file if specified
	if output_file:
		open(output_file, 'w').close()

	tasks = set()
	
	async def write_result(result: dict):
		'''Write a single result to the output file'''
		nonlocal processed_domains
		
		# Create JSON output dict
		output_dict = {'url': result['url'], 'domain': result['domain'], 'status': result['status']}
		
		# Add optional fields if they exist
		if result['title']:
			output_dict['title'] = result['title']
		if result['body']:
			output_dict['body'] = result['body']
		if result['ips']:
			output_dict['ips'] = result['ips']
		if result['favicon_hash']:
			output_dict['favicon_hash'] = result['favicon_hash']
		if result['headers']:
			output_dict['headers'] = result['headers']
		if result['cname']:
			output_dict['cname'] = result['cname']
		if result['redirect_chain']:
			output_dict['redirect_chain'] = result['redirect_chain']
		if result['tls']:
			output_dict['tls'] = result['tls']

		# Get formatted output based on filters
		formatted = format_status_output(result, debug, show_fields, match_codes, exclude_codes)
		if formatted:
			# Write to file if specified
			if output_file:
				if (not match_codes or result['status'] in match_codes) and (not exclude_codes or result['status'] not in exclude_codes):
					with open(output_file, 'a') as f:
						json.dump(output_dict, f, ensure_ascii=False)
						f.write('\n')
			
			# Console output
			if jsonl:
				# Pure JSON Lines output without any logging prefixes
				print(json.dumps(output_dict))
			else:
				if show_progress:
					processed_domains += 1
					info(f"{Colors.BOLD}[{processed_domains}/{total_domains}]{Colors.RESET} {formatted}")
				else:
					info(formatted)

	async with aiohttp.ClientSession() as session:
		# Start initial batch of tasks
		for domain in itertools.islice(domain_generator(input_source), concurrent_limit):
			task = asyncio.create_task(check_domain(session, domain, 
												  follow_redirects=show_fields['follow_redirects'], 
												  timeout=timeout,
												  check_axfr=check_axfr))
			tasks.add(task)
		
		# Process remaining domains, maintaining concurrent_limit active tasks
		domains_iter = domain_generator(input_source)
		next(itertools.islice(domains_iter, concurrent_limit, concurrent_limit), None)  # Skip first concurrent_limit domains
		
		for domain in domains_iter:
			done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
			tasks = pending
			
			for task in done:
				result = await task
				await write_result(result)
			
			task = asyncio.create_task(check_domain(session, domain, 
												  follow_redirects=show_fields['follow_redirects'], 
												  timeout=timeout,
												  check_axfr=check_axfr))
			tasks.add(task)
		
		# Wait for remaining tasks
		if tasks:
			done, _ = await asyncio.wait(tasks)
			for task in done:
				result = await task
				await write_result(result)


async def try_axfr(domain: str) -> None:
	'''
	Try AXFR transfer for a domain against all its nameservers
	
	:param domain: Domain to attempt AXFR transfer
	'''
	
	try:
		# Ensure output directory exists
		os.makedirs('axfrout', exist_ok=True)
		
		# Get nameservers
		resolver = dns.asyncresolver.Resolver()
		nameservers = await resolver.resolve(domain, 'NS')
		
		# Try AXFR against each nameserver
		for ns in nameservers:
			ns_host = str(ns).rstrip('.')
			try:
				# Get nameserver IP
				ns_ips = await resolver.resolve(ns_host, 'A')
				for ns_ip in ns_ips:
					ns_ip = str(ns_ip)
					try:
						# Attempt zone transfer
						zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
						
						# Save successful transfer
						filename = f'axfrout/{domain}_{ns_ip}.zone'
						with open(filename, 'w') as f:
							zone.to_text(f)
						info(f'{Colors.RED}[AXFR SUCCESS] {domain} from {ns_host} ({ns_ip}){Colors.RESET}')
					except Exception as e:
						debug(f'AXFR failed for {domain} from {ns_ip}: {str(e)}')
			except Exception as e:
				debug(f'Failed to resolve {ns_host}: {str(e)}')
	except Exception as e:
		debug(f'Failed to get nameservers for {domain}: {str(e)}')


def main():
	'''Main function to handle command line arguments and run the domain checker'''
	global _SILENT_MODE
	
	parser = argparse.ArgumentParser(description=f'{Colors.GREEN}Hyper-fast HTTP Scraping Tool{Colors.RESET}', formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('file', nargs='?', default='-', help='File containing domains to check (one per line), use - for stdin')
	parser.add_argument('-d', '--debug', action='store_true', help='Show error states and debug information')
	parser.add_argument('-c', '--concurrent', type=int, default=100, help='Number of concurrent checks')
	parser.add_argument('-o', '--output', help='Output file path (JSONL format)')
	parser.add_argument('-j', '--jsonl', action='store_true', help='Output JSON Lines format to console')
	
	# Add all-flags argument
	parser.add_argument('-all', '--all-flags', action='store_true', help='Enable all output flags')
	
	# Output field flags
	parser.add_argument('-sc',  '--status-code', action='store_true', help='Show status code')
	parser.add_argument('-ct',  '--content-type', action='store_true', help='Show content type')
	parser.add_argument('-ti',  '--title', action='store_true', help='Show page title')
	parser.add_argument('-b',   '--body', action='store_true', help='Show body preview')
	parser.add_argument('-i',   '--ip', action='store_true', help='Show IP addresses')
	parser.add_argument('-f',   '--favicon', action='store_true', help='Show favicon hash')
	parser.add_argument('-hr',  '--headers', action='store_true', help='Show response headers')
	parser.add_argument('-cl',  '--content-length', action='store_true', help='Show content length')
	parser.add_argument('-fr',  '--follow-redirects', action='store_true', help='Follow redirects (max 10)')
	parser.add_argument('-cn',  '--cname', action='store_true', help='Show CNAME records')
	parser.add_argument('-tls', '--tls-info', action='store_true', help='Show TLS certificate information')
	
	# Other arguments
	parser.add_argument('-to', '--timeout', type=int, default=5, help='Request timeout in seconds')
	parser.add_argument('-mc', '--match-codes', type=parse_status_codes, help='Only show these status codes (comma-separated, e.g., 200,301,404)')
	parser.add_argument('-ec', '--exclude-codes', type=parse_status_codes, help='Exclude these status codes (comma-separated, e.g., 404,500)')
	parser.add_argument('-p', '--progress', action='store_true', help='Show progress counter')
	parser.add_argument('-ax', '--axfr', action='store_true', help='Try AXFR transfer against nameservers')
	
	args = parser.parse_args()

	# Set silent mode based on jsonl argument
	_SILENT_MODE = args.jsonl

	# Only setup logging if we're not in silent mode
	if not _SILENT_MODE:
		apv.setup_logging(level='DEBUG' if args.debug else 'INFO')
		info(f'{Colors.BOLD}Starting domain checker...{Colors.RESET}')
		if args.file == '-':
			info('Reading domains from stdin')
		else:
			info(f'Processing file: {Colors.UNDERLINE}{args.file}{Colors.RESET}')
		info(f'Concurrent checks: {args.concurrent}')

	show_fields = {
		'status_code'      : args.all_flags or args.status_code,
		'content_type'     : args.all_flags or args.content_type,
		'title'            : args.all_flags or args.title,
		'body'             : args.all_flags or args.body,
		'ip'               : args.all_flags or args.ip,
		'favicon'          : args.all_flags or args.favicon,
		'headers'          : args.all_flags or args.headers,
		'content_length'   : args.all_flags or args.content_length,
		'follow_redirects' : args.all_flags or args.follow_redirects,
		'cname'            : args.all_flags or args.cname,
		'tls'              : args.all_flags or args.tls_info
	}

	# If no fields specified and no -all flag, show all (maintain existing behavior)
	if not any(show_fields.values()):
		show_fields = {k: True for k in show_fields}

	try:
		asyncio.run(process_domains(args.file, args.debug, args.concurrent, show_fields, args.output, args.jsonl, args.timeout, args.match_codes, args.exclude_codes, args.progress, check_axfr=args.axfr))
	except KeyboardInterrupt:
		logging.warning(f'{Colors.YELLOW}Process interrupted by user{Colors.RESET}')
		sys.exit(1)
	except Exception as e:
		logging.error(f'{Colors.RED}An error occurred: {str(e)}{Colors.RESET}')
		sys.exit(1)


if __name__ == '__main__':
	main() 
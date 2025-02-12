#!/usr/bin/env python3
# HTTPZ Web Scanner - Developed by acidvegas in Python (https://github.com/acidvegas/httpz)
# setup.py

from setuptools import setup, find_packages


with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='httpz_scanner',
    version='2.1.2',
    author='acidvegas',
    author_email='acid.vegas@acid.vegas',
    description='Hyper-fast HTTP Scraping Tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/acidvegas/httpz',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Security',
    ],
    python_requires='>=3.8',
    install_requires=[
        'aiohttp>=3.8.0',
        'beautifulsoup4>=4.9.3',
        'cryptography>=3.4.7',
        'dnspython>=2.1.0',
        'mmh3>=3.0.0',
    ],
    entry_points={
        'console_scripts': [
            'httpz=httpz_scanner.cli:run',
        ],
    },
) 
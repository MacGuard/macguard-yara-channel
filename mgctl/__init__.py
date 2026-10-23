"""mgctl: the canonical command of the MacGuard suite.

mgctl is a front end. It parses arguments and delegates every security check to the engines that already exist
(macguard-audit for files and YARA rules, scripts/verify_public_release.py for public releases). It re-implements none of them.
"""
VERSION = "0.1.0"
CONTRACT = 1          # version of the command tree and of the JSON documents mgctl prints

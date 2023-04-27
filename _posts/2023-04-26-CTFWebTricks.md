---
title: CTF tricks for web expliotation
date: 2023-04-26 03:30:00 +/-0200
categories: [CTF notes, Web exploitaion]
tags: [enumeration, easy]     # TAG names should always be lowercase
---


# CTF WEB Tricks for enumeration
- Different HTTP methods
- access middle redirect pages via open redirect vulnerability +
- Checking cookies content
- Modifying cookies
- The poor cookie admin authentication 
- Inspection of the website HTML/CSS/JS file
- Inspect every page after every action
- Ctrl + F with the flag format
- Check out available paths via Gobuster
- bruteforce with the normal admin:admin
- file trace by looking through static imports(html,css,js,imgs)
- flag can be scattered in the client side
- Checking out robots.txt/.htaccess/.DS_Store
- Any sus long string can be base64(may need to respect its multi-line)
- md5 checks
- JS obfuscation (may god help u with it)
- WebAssembly 
- HTTP Headers(User-Agent,Accept-Language,referer,Date,DNT,X-Forwarded-For,etc...)
- Command Injection(system command)(don't forget to URL encode specializes)
- Command Injection(language command - php, node, python etc.. -)
- SQL Injection
- Blind SQL Injection
- SQL Injection filters bypass
- SQL database server access and querying
- ~Sometimes Burpsuite sucks~
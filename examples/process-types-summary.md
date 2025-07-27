# Comprehensive Process Detection & Classification

Takakrypt supports comprehensive process detection and classification for fine-grained access control beyond just database files. The system can detect and classify virtually any type of process running on the system.

## Supported Process Types

### 🗄️ Database Processes
- **MySQL/MariaDB**: `mysqld`, `mariadbd` 
- **PostgreSQL**: `postgres`, `postmaster`
- **MongoDB**: `mongod`, `mongodb`
- **Redis**: `redis-server`
- **Oracle**: Basic pattern detection
- **Detection**: Process names, executable paths, environment variables, data/config paths

### 🌐 Web Server Processes  
- **Apache**: `apache2`, `httpd`
- **Nginx**: `nginx`
- **Detection**: Process names, configuration files, worker processes

### ☕ Java Applications
- **Application Servers**: `tomcat`, `catalina`
- **Generic Java**: `java`, `javaw`
- **Elasticsearch**: Java-based search engine
- **Detection**: Process names, JAR files, JVM arguments

### 🟢 Node.js Applications
- **Runtime**: `node`, `nodejs`
- **Package Managers**: `npm`, `yarn`
- **Detection**: Process names, executable paths, Node modules

### 🐍 Python Applications
- **Interpreters**: `python`, `python3`
- **Web Servers**: `gunicorn`, `uwsgi`
- **Task Queues**: `celery`
- **Detection**: Process names, virtual environments, Python modules

### 🐳 Container & Orchestration
- **Docker**: `dockerd`, `docker`, `containerd`, `runc`
- **Kubernetes**: `kubelet`, `kube-proxy`, `kube-apiserver`, `etcd`
- **Detection**: Process hierarchies, container runtimes

### 📨 Messaging & Queues
- **RabbitMQ**: `rabbitmq-server`, `beam.smp` (Erlang VM)
- **Apache Kafka**: `kafka`
- **Detection**: Message broker patterns, configuration files

### 💾 Cache Systems
- **Memcached**: `memcached`
- **Elasticsearch**: Search and analytics engine
- **Detection**: Cache-specific patterns and configurations

### 🔒 Security Tools
- **Intrusion Detection**: `fail2ban`, `ossec`, `wazuh`
- **Antivirus**: `clamd`, `freshclam`, `clamav`
- **Log Shippers**: `filebeat`, `metricbeat`
- **Audit**: `auditd`
- **Detection**: Security tool patterns and configurations

### 💾 Backup Tools
- **File Sync**: `rsync`, `tar`, `gzip`
- **Database Backup**: `mysqldump`, `pg_dump`
- **Enterprise Backup**: `bacula`, `amanda`
- **Detection**: Backup-specific command patterns

### 👨‍💻 Development Tools
- **Version Control**: `git`, `svn`
- **Compilers**: `gcc`, `make`, `cmake`
- **Build Tools**: `gradle`, `maven`
- **IDEs**: `code` (VS Code), `idea` (IntelliJ), `eclipse`
- **Editors**: `vim`, `emacs`, `nano`
- **Package Managers**: `pip`, `npm`
- **Detection**: Development workflow patterns

### 🔄 File Sync & Transfer
- **Cloud Sync**: `dropbox`, `onedrive`, `googledrive`
- **Local Sync**: `syncthing`, `nextcloud`
- **FTP Servers**: `vsftpd`, `proftpd`, `pure-ftpd`
- **Detection**: Sync patterns and configuration files

### 🎵 Media Processing
- **Video/Audio**: `ffmpeg`, `vlc`, `gstreamer`
- **Audio System**: `pulseaudio`, `alsa`
- **Detection**: Media processing patterns

### 🌐 Network Tools
- **Monitoring**: `netstat`, `ss`, `iftop`, `tcpdump`
- **Analysis**: `wireshark`, `nmap`
- **Transfer**: `curl`, `wget`
- **Detection**: Network utility patterns

### 🔐 VPN Services
- **OpenVPN**: `openvpn`
- **WireGuard**: `wireguard`
- **IPSec**: `strongswan`
- **Detection**: VPN configuration patterns

### 🐚 Shell Processes
- **Shells**: `bash`, `sh`, `zsh`, `fish`, `csh`, `tcsh`
- **Terminal Multiplexers**: `tmux`, `screen`
- **Detection**: Shell process hierarchies

### ⚙️ System Processes
- **Init Systems**: `systemd`, `init`
- **Kernel Threads**: `kthread`, `ksoftirqd`, `migration`
- **System Services**: `sshd`, `rsyslog`
- **Detection**: System-level process patterns

## Process Detection Methods

### 1. Process Name Matching
- Exact name matches: `mysqld`, `nginx`, `java`
- Partial name matches: `kube-*`, `rcu_*`
- Pattern-based matching with wildcards

### 2. Executable Path Analysis
- Full path matching: `/usr/sbin/nginx`, `/usr/bin/python3`
- Directory-based matching: `/opt/*`, `/usr/local/*`
- Wildcard pattern support

### 3. Command Line Argument Analysis
- JVM arguments: `-jar`, `-Dcatalina.base=`
- Python modules: `django`, `flask`, `celery`
- Configuration files: `--config=`, `--datadir=`

### 4. Environment Variable Detection
- Database variables: `MYSQL_ROOT_PASSWORD`, `PGDATA`
- Application variables: `JAVA_HOME`, `NODE_ENV`
- Container variables: `DOCKER_HOST`

### 5. Process Hierarchy Analysis
- Parent-child relationships
- Process tree analysis for service architectures
- Worker process detection

## Configuration Examples

### Basic Process Set
```yaml
web_servers:
  name: "web_servers"
  processes: ["nginx", "apache2", "httpd"]
  process_types: ["webserver"]
  require_all: false
```

### Advanced Process Set with Database Rules
```yaml
mysql_processes:
  name: "mysql_processes"
  processes: ["mysqld", "mariadbd"]
  database_rules:
    - database_types: ["mysql", "mariadb"]
      listen_ports: [3306, 3307]
      data_paths: ["/var/lib/mysql"]
  process_types: ["mysql", "mariadb"]
  require_all: false
```

### Process Hierarchy Matching
```yaml
java_stack:
  name: "java_stack"
  processes: ["java", "tomcat"]
  children_of: ["java"]  # Include Java child processes
  process_types: ["java"]
  require_all: false
```

### Multi-Criteria Process Set
```yaml
development_environment:
  name: "development_environment"
  processes: ["git", "code", "node", "python"]
  process_paths: ["/opt/vscode/*", "*/node_modules/.bin/*"]
  process_types: ["development", "nodejs", "python"]
  require_all: false  # OR logic - any match counts
```

## Security Rules for Different Process Types

### Web Application Stack
```yaml
- order: 1
  resource_set: "web_content"
  process_set: "web_servers"
  actions: ["f_rd", "f_wr"]
  effects: ["permit", "audit"]
  description: "Web servers access web content"

- order: 2
  resource_set: "web_content"  
  process_set: "java_applications"
  actions: ["f_rd", "f_wr", "f_cre"]
  effects: ["permit", "audit"]
  description: "Java apps can manage web content"
```

### Development Environment
```yaml
- order: 3
  resource_set: "source_code"
  process_set: "development_tools"
  actions: ["f_rd", "f_wr", "f_cre", "f_rm"]
  effects: ["permit", "audit"]
  description: "Development tools access source code"

- order: 4
  resource_set: "build_artifacts"
  process_set: "java_applications"
  actions: ["f_cre", "f_wr"]
  effects: ["permit", "audit"]
  description: "Java build processes create artifacts"
```

### System Administration
```yaml
- order: 5
  resource_set: "system_configs"
  process_set: "system_critical"
  actions: ["f_rd", "f_rd_att"]
  effects: ["permit", "audit"]
  description: "System processes read configs"

- order: 6
  resource_set: "application_logs"
  process_set: "security_tools"
  actions: ["f_rd", "f_rd_att"]
  effects: ["permit", "audit"]
  description: "Security tools analyze logs"
```

## Performance Characteristics

- **Detection Speed**: 94.7µs cold cache, 126ns warm cache
- **Cache Effectiveness**: 749x speedup with intelligent caching
- **Memory Usage**: TTL-based cache with configurable retention
- **Scalability**: Handles hundreds of processes efficiently
- **Accuracy**: Multi-method detection for high precision

## Use Cases

### 1. Application Stack Protection
Protect entire application stacks (web server + application server + database) with coordinated access controls.

### 2. Development Environment Security
Control access to source code, build artifacts, and development tools based on process type and user context.

### 3. Container Orchestration Security
Manage access for containerized applications with Kubernetes and Docker process awareness.

### 4. System Administration Controls
Fine-grained access control for system administration tools and processes.

### 5. Compliance and Auditing
Comprehensive logging and access control for compliance requirements across all process types.

This comprehensive process detection system enables Takakrypt to provide fine-grained transparent encryption and access control for virtually any type of application or system process, going far beyond just database protection.
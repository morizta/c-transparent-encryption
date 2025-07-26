# Thales CTE Real-World Analysis Report

## Executive Summary

This document contains a comprehensive analysis of a live Thales CipherTrust Transparent Encryption (CTE) deployment, revealing the complete architecture, file structure, policy management, and operational characteristics of production CTE systems.

---

## 1. System Architecture

### 1.1 Directory Structure
```
/opt/vormetric/DataSecurityExpert/agent/
├── secfs/                          # Secure File System (Core encryption engine)
│   ├── .sec/                       # Hidden security configuration
│   │   ├── bin/                    # Protected binaries (--x--x--x permissions)
│   │   ├── conf/                   # Configuration management
│   │   │   ├── conf.YYYY-MM-DD-HH-MM-SS-NNN/  # Versioned configurations
│   │   │   ├── configuration -> conf.XXX/      # Active config symlink
│   │   │   ├── secfs.key           # Encrypted master key (2384 bytes)
│   │   │   └── sig/                # Digital signatures
│   │   ├── .access                 # Access control (336 bytes, 600 perms)
│   │   ├── .hw_sig                 # Hardware signature (782 bytes, 600 perms)
│   │   └── pem/                    # SSL certificates
│   ├── bin/                        # Public binaries
│   ├── tmp/                        # Temporary files and logs
│   └── saphana/                    # SAP HANA integration scripts
└── vmd/                            # Vormetric Management Daemon
    ├── bin/                        # VMD binaries
    ├── etc/                        # Configuration files
    │   ├── agent.conf              # Main configuration
    │   ├── messages.en_US          # Localized messages
    │   └── msgidmap                # Message ID mappings
    ├── pem/                        # Certificates
    └── log -> /var/log/vormetric   # Log symlink
```

### 1.2 Kernel Modules
```bash
# Active CTE kernel modules:
secfs2               3215360  5 secvm2    # Main transparent encryption module
seccrypto             507904  1 secfs2    # Cryptographic operations module
secvm2               (unknown size)       # Secure Virtual Memory protection
```

### 1.3 Running Processes
```bash
# Core CTE daemons:
secfsd               1.8GB memory         # Secure File System Daemon (main engine)
vmd                  55.8MB memory        # Vormetric Management Daemon (CM communication)
secfsd-comm          ~34MB memory         # Communication daemon (ports 7024, 7025)

# Kernel threads (30+ workers):
[secfst]             # Secure FS threads
[secfst:seg2/3]      # Segmented processing threads  
[secfs.ob]           # Object handler
[secfst.aio]         # Async I/O handlers
[vor_tctl]           # Vormetric control thread
```

---

## 2. Configuration Management

### 2.1 Connection Manager Configuration
```bash
# From agent.conf:
URL = https://192.168.50.189

# From secfs_config:
vmd_URL=https://192.168.50.189
vmd_SRV_URLS=https://192.168.50.189:443
vmd_PRIMARY_URL=https://192.168.50.189:443
vmd_SUPPORTS_F8P=TRUE
vmd_SUPPORTS_CR256=TRUE
```

### 2.2 Configuration Versioning System
```bash
# Atomic configuration updates via symlinks:
conf.2025-07-25-10-34-40-558/           # Timestamped configuration snapshot
configuration -> conf.2025-07-25-10-34-40-558/  # Active configuration symlink
```

### 2.3 Quality of Service Settings
```bash
# Performance and scheduling:
QOS_CAP=0                               # No bandwidth cap
QOS_CPU=0                               # No CPU limit
QOS_MODE=sched                          # Scheduled operation mode
QOS_REKEY_RATE=0                        # No rekey rate limit
QOS_SCHED_0_DAY=Sun through QOS_SCHED_6_DAY=Sat  # 24/7 operation
```

### 2.4 Security Configuration
```bash
# Security features:
ptrace_protection=Enabled_For_Authenticators   # Anti-debugging protection
systemd_protection=Disabled                    # Process protection (disabled)
learn_mode=false                               # Not in learning mode
host_mfa_enable=false                          # MFA disabled
concise_logging=false                          # Full audit logging
STRONG_ENTROPY=false                           # Use /dev/urandom
```

---

## 3. Policy Management

### 3.1 Active Policies
Three policies identified in production:

1. **demo_policy** (UUID: f7368f1e-0407-4386-a3c1-20fac6ab5fe8)
   - Version: 30
   - Key Version: 4
   - Type: LDT (Live Data Transformation)
   - Size: 912 bytes (largest policy)

2. **test_guard** (UUID: 930f2f4b-178e-4f68-bc18-5489f7a95df2)
   - Version: 0
   - Key Version: 0
   - Type: LDT
   - Size: 592 bytes

3. **block_db** (UUID: 73f66b34-c1d2-49d6-953f-28ec23eeb720)
   - Version: 104
   - Key Version: 2
   - Type: LDT
   - Size: 704 bytes

### 3.2 Policy File Format
```bash
# Binary encrypted policy objects:
p.{UUID}.po files                       # Policy objects (binary format)
- All files show as "data" (encrypted)
- Variable sizes (592-912 bytes)
- UUID-based naming for unique identification
```

### 3.3 Virtual Machine Configurations
```bash
# VM-specific configurations:
vm0.dat: 352 bytes                      # Main VM config (binary data)
vm1.dat: 272 bytes                      # Secondary VM
vm2.dat: 384 bytes                      # Another VM config
vm3.dat: 112 bytes                      # Minimal VM config
vm4.dat, vm9-11.dat: 0 bytes           # Empty configurations
```

---

## 4. Active Guard Points

### 4.1 Production Guard Points
```bash
# Mounted guard points (secfs2 filesystem):
/opt/vormetric/.../secfs/.sec           # CTE system files (self-protection)
/var/lib/mysql/mamang                   # MySQL database (active protection)
/data-test                              # Test data directory (empty)
/data-thales                            # User data with ACLs (active protection)
```

### 4.2 Mount Options
```bash
secfs2 (rw,relatime)                    # Standard read-write with relative access time
secfs2 (rw,nosuid,relatime)             # Enhanced security: no setuid allowed
```

### 4.3 MySQL Database Protection
**Database**: `mamang`
**Files**:
- `data_penduduk.frm` (833 bytes) - Table structure (encrypted)
- `data_penduduk.ibd` (65KB) - Table data (encrypted)
- `db.opt` (67 bytes) - Database options

**Status**: MariaDB process actively accessing encrypted files but experiencing corruption

---

## 5. Encryption Implementation

### 5.1 Encryption File Format
**Header Analysis** from `/data-thales/1.txt`:
```
Offset    Hex Data                     ASCII
00000000  45 52 4f 56 01 00 14 04     EROV....    # Magic signature
00000010  3d 39 42 cd 08 00 76 3a     =9B...v:    # Encryption parameters
...
00000030  64 65 6d 6f 5f 63 74 65     demo_cte    # Policy identifier
```

**Format Structure**:
- **Magic**: `EROV` (4 bytes) - Vormetric encryption signature
- **Version**: `01 00` (2 bytes) - Format version
- **Metadata**: Encryption parameters and timestamps
- **Policy ID**: `demo_cte` - Policy identifier string
- **Content**: Encrypted file data

### 5.2 Key Management
```bash
# Key storage:
secfs.key: 2384 bytes (binary data)     # Encrypted master key
- File type: "data" (encrypted format)
- Permissions: 644 (world-readable but encrypted)
- Hardware-bound encryption
```

### 5.3 Signature Management
```bash
# Digital signature database:
sig.db: 6656 bytes                     # Signature database
sig.db.tmp: 6656 bytes                 # Temporary signature file
```

---

## 6. Audit and Logging

### 6.1 Audit Trail Analysis
**Sample audit entries**:
```
Policy[demo_policy] User[primasys,uid=1000,gid=1000\primasys,adm,cdrom,sudo,dip,plugdev,users,cteuser\] 
Process[/usr/bin/cat] Action[read_file] Res[/data-thales/1.txt] Key[None] Effect[PERMIT Code (1A,2R,3R,4M)]

Policy[block_db] User[mysql,uid=116,euid=116 (User Not Authenticated)] 
Process[/usr/sbin/mariadbd] Action[read_file] Res[/var/lib/mysql/mamang/data_penduduk.frm] 
Key[None] Effect[PERMIT Code (1A,2P,3M)]
```

### 6.2 Access Control Lists
**Complex ACL structure** on `/data-thales/`:
```bash
# User permissions:
user:root:rwx
user:primasys:rwx
user:fawwaz:rwx
user:nobody:rwx

# Default permissions for new files:
default:user:primasys:rwx
default:user:fawwaz:rwx
default:group:root:rwx
```

### 6.3 Logging Configuration
```bash
# Log settings:
logger_threshold_secfsd=INFO
logger_threshold_CGA=INFO
logger_appender_CGA=Kern_Upload
logger_upload_url=https://192.168.50.189:443/api/v1/transparent-encryption/logupload
```

---

## 7. Issues Identified

### 7.1 Database Corruption
**Problem**: MySQL database experiencing corruption
**Root Cause**: 
- `block_db` policy permits file access but doesn't decrypt data
- MySQL user (uid=116) marked as "(User Not Authenticated)"
- No encryption key provided (`Key[None]`)
- MySQL reads encrypted data as plaintext, causing corruption

**Evidence**:
```bash
ERROR 1033 (HY000): Incorrect information in file: './mamang/data_penduduk.frm'
file data_penduduk.frm: data (should be "MySQL table metadata")
```

### 7.2 Communication Issues
**Problem**: Intermittent connection loss to Connection Manager
**Evidence**:
```
[CGS3321W] LDT-NFS-ALERT: LDT Communication Master is down
```

### 7.3 Authentication Issues
**Problem**: System users not properly authenticated to CTE policies
**Evidence**: Multiple "(User Not Authenticated)" entries in audit logs

---

## 8. Security Architecture

### 8.1 Multi-Layer Protection
1. **Hardware Binding**: `.hw_sig` file prevents key extraction
2. **Process Protection**: Execute-only binaries (`--x--x--x`)
3. **Encrypted Storage**: All sensitive data encrypted at rest
4. **Digital Signatures**: Policy integrity verification
5. **Access Control**: Complex ACL and user mapping system

### 8.2 Certificate Management
```bash
# Certificate infrastructure:
/opt/vormetric/.../pem/                 # SSL certificates for CM communication
logger_cert_dir=/opt/vormetric/.../pem  # Certificate directory for log upload
```

### 8.3 Anti-Tamper Features
- Execute-only binary permissions
- Hardware signature validation
- Encrypted configuration files
- Process protection (when enabled)
- Audit trail integrity

---

## 9. Performance Characteristics

### 9.1 Memory Usage
- **secfsd**: 1.8GB (main encryption engine)
- **vmd**: 55.8MB (management daemon)
- **secfsd-comm**: ~34MB (communication)

### 9.2 Worker Threads
- 30+ kernel threads for parallel processing
- Segmented processing (seg2, seg3)
- Async I/O handlers
- Object processing threads

### 9.3 Network Communication
- Primary: HTTPS/443 to Connection Manager
- Internal: TCP/7024, TCP/7025 for daemon communication
- Heartbeat and policy synchronization

---

## 10. Integration Points

### 10.1 Database Integration
- MySQL/MariaDB transparent encryption
- Real-time data access during operation
- Table-level encryption granularity

### 10.2 Application Integration
- SAP HANA scripts (`fcClientLVMRefinedVTE.py`)
- System service integration
- User application transparency

### 10.3 System Integration
- systemd service management
- Linux ACL integration
- User authentication system
- Mount point management

---

## Conclusions

This analysis reveals Thales CTE as a sophisticated transparent encryption solution with:

1. **Comprehensive Architecture**: Multi-daemon, kernel-module based system
2. **Enterprise Features**: Versioned configuration, audit logging, certificate management
3. **Production Deployment**: Active protection of MySQL databases and user data
4. **Security Focus**: Hardware binding, encrypted storage, process protection
5. **Configuration Issues**: Authentication and policy configuration problems affecting database access

The system demonstrates the complexity required for enterprise-grade transparent encryption and provides a detailed blueprint for implementing similar capabilities.

---

## 11. CipherTrust Manager (CM) Web Interface Analysis

### 11.1 Policy Management Architecture
From comprehensive analysis of 16 CM web interface screenshots, the following enterprise policy management structure was extracted:

#### Policy Types and Versioning
```
CTE Policies:
├── Live Data Transformation (LDT)    # Real encryption policies
│   ├── demo_policy (v30, key v4)    # User data encryption
│   ├── block_db (v104, key v2)      # Database protection  
│   └── test_guard (v0, key v0)      # Test environment
└── Standard                          # Access control only (no encryption)
    ├── rivapolicy (v0)
    ├── PolicyGuardPoint (v0)
    └── FaiPolicy (v0)
```

#### Policy Element Hierarchy
**1. Resource Sets** (What to protect):
- **Directory-based**: `db_mamang` (MySQL), `data` (user files), `engineer` (engineering data)
- **Path Patterns**: `\fdd\*` (directory matching), `*` (wildcard), recursive subfolder inclusion
- **File System Support**: Local File System + HDFS integration
- **Configuration**: Directory path + File pattern + Include/Exclude subfolders

**2. User Sets** (Who can access):
- **System Integration**: `demo_user` contains `primasys` (UID 1000), `Primasys` (manual entry)
- **Database Service**: `akun-mysql` contains MySQL service accounts
- **Enterprise Features**: "Browse users" (OS integration), "Manually add user" (custom entries)
- **Authentication**: OS domain integration for enterprise directory services

**3. Process Sets** (Which applications):
- **Database Protection**: `mariadb-fa` → `/usr/sbin/mariadb` (MariaDB daemon)
- **Text Editors**: `nano` → `/usr/bin/nano`
- **Custom Groups**: `fgfdg`, `GroupProcessPai` (application-specific process groups)
- **Validation Methods**: Directory + File + Signature matching for process identification

**4. Security Rules** (Ordered policy evaluation):
- **Rule Priority**: Order 1, 2, 3, 4... (first match wins, like firewall rules)
- **Rule Components**: Resource Set + User Set + Process Set + Action + Effect + Browsing
- **Evaluation Logic**: Hierarchical rule processing with precedence-based decisions

### 11.2 Advanced Action Granularity
CM reveals sophisticated action permission system beyond basic read/write:

#### Basic Operations
- `read` - Read file operations
- `write` - Write file operations  
- `all_ops` - All file operations
- `key_op` - Key management operations

#### Advanced File Operations
- `f_rd` - Read file
- `f_wr` - Write file
- `f_wr_app` - Write file (append mode)
- `f_cre` - Create file
- `f_ren` - Rename file
- `f_link` - Link file
- `f_rm` - Remove file
- `f_rd_att` - Read file attribute
- `f_chg_att` - Change file attribute
- `f_rd_sec` - Read file security
- `f_chg_sec` - Change file security

#### Directory Operations
- `d_rd` - Read directory
- `d_ren` - Rename directory
- `d_rd_att` - Read directory attribute
- `d_chg_att` - Change directory attribute
- `d_rd_sec` - Read directory security
- `d_chg_sec` - Change directory security
- `d_mkdir` - Make directory
- `d_rmdir` - Remove directory

### 11.3 Effect Permissions Architecture
CM defines three core effects that determine policy behavior:

#### Effect Types
1. **Permit**: "Allows access attempts to the resource. For example, you can specify an effect that allows writing to a directory."
2. **Deny**: "Denies access attempts to the resource. For example, you can specify an effect that denies any attempts to access a resource."

#### Effect Options
1. **ApplyKey**: "Applies an encryption key to the data in a GuardPoint. When applied, the data copied to the GuardPoint is encrypted with the specified key. When the data in the GuardPoint is accessed, it is decrypted using the same key."
2. **Audit**: "Creates a message log entry for each qualifying event that records who is accessing what information and when."

#### Combined Effects
- `permit,applykey` - Allow access with transparent encryption/decryption
- `permit,audit,applykey` - Allow + encrypt + comprehensive audit logging
- `permit,audit` - Allow access with audit logging (no encryption)

### 11.4 Enterprise Database Protection Pattern
Analysis of `block_db` policy reveals the exact MySQL protection configuration:

#### Database Protection Rule Structure
```
Rule 2: Database Access
├── Resource Set: db_mamang (MySQL database directory)
├── User Set: (not specified - inherited from higher rules)  
├── Process Set: mariadb-fa (MariaDB daemon)
├── Action: read,write,key_op,all_ops
├── Effect: permit,audit,applykey
└── Browsing: Yes (allow directory listing)
```

#### Multi-Rule Policy Structure
```
block_db Policy Rules:
├── Rule 1: key_op → permit,applykey (No browsing)
├── Rule 2: db_mamang + mariadb-fa → read,write,key_op,all_ops → permit,audit,applykey (Browsing: Yes)
└── Rule 3: (general) → read → permit,audit (Browsing: Yes)
```

### 11.5 Policy Configuration Management
CM provides enterprise-grade policy management capabilities:

#### Policy Creation and Modification
- **Web-based Interface**: Complete CRUD operations for all policy elements
- **Real-time Updates**: "Any updates to the policy will be applied without confirmation if the policy is not in use by any Enabled/Active GuardPoints"
- **Version Control**: Automatic policy versioning (demo_policy v30, block_db v104)
- **Atomic Operations**: Policy changes applied atomically to prevent inconsistent states

#### Policy Element Management
- **Resource Sets**: 7 sets with directory patterns and file system type specification
- **User Sets**: 4 sets with OS integration and manual user management
- **Process Sets**: 4 sets with executable path and signature validation
- **Signature Sets**: Digital signature validation for process authenticity

#### GuardPoint Integration
- **Active Monitoring**: Real-time status (3 Total GuardPoints, 3 Active, 0 Inactive, 0 Disabled)
- **Mount Management**: Integration with filesystem mounting and protection
- **Policy Assignment**: Dynamic policy assignment to guard points
- **Performance Monitoring**: LDT Progress tracking ("Rekeyed", "N/A")

### 11.6 Key Architecture Insights for Takakrypt Implementation

#### Critical Requirements Identified
1. **Mount-Based Architecture**: GuardPoints are filesystem mounts, not individual file hooks
2. **Hierarchical Rule Evaluation**: Ordered rules with first-match-wins policy  
3. **Granular Action Control**: 20+ specific file/directory operations beyond basic read/write
4. **Multi-Effect System**: Permit/Deny + ApplyKey + Audit combinations
5. **Enterprise Integration**: OS user/group integration, process signature validation
6. **Real-time Management**: Web interface for policy CRUD with immediate application

#### Implementation Blueprint
The CM analysis provides the exact policy structure needed for enterprise-grade Takakrypt:

```yaml
# Required Takakrypt Policy Structure (based on CM analysis)
policies:
  mysql_protection:
    type: "live_data_transformation"
    version: 1
    security_rules:
      - order: 1
        resource_set: "mysql_data"
        user_set: null
        process_set: "mysql_processes" 
        actions: ["key_op"]
        effects: ["permit", "applykey"]
        browsing: false
      - order: 2
        resource_set: "mysql_data"
        user_set: null
        process_set: "mysql_processes"
        actions: ["read", "write", "key_op", "all_ops"]
        effects: ["permit", "audit", "applykey"]  
        browsing: true

resource_sets:
  mysql_data:
    paths: ["/var/lib/mysql/*"]
    include_subfolders: true
    filesystem_type: "local"

process_sets:
  mysql_processes:
    processes:
      - directory: "/usr/sbin/"
        file: "mysqld"
        signature: null
      - directory: "/usr/sbin/"  
        file: "mariadbd"
        signature: null
```

This CM analysis provides the complete enterprise policy management blueprint for implementing production-grade transparent encryption in Takakrypt.
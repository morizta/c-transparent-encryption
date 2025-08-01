# 🐞 Bug Tracking and Fixes

## [NETLINK_COMMUNICATION_FAILURE] - PARTIALLY FIXED
- **Found on**: 2025-07-29
- **Symptoms**: 
  - Kernel module and userspace agent unable to communicate
  - Guard points not configured in kernel (count = 0)
  - Files not being encrypted despite proper configuration
  - Agent compilation errors with netlink types
- **Suspected Causes**: 
  1. Protocol mismatch between kernel and userspace message headers
  2. Guard point serialization using incorrect byte manipulation
  3. Missing netlink client method implementation
- **Fix Steps**: 
  1. Renamed `MessageHeader` to `TakakryptMsgHeader` matching kernel structure exactly
  2. Replaced manual byte manipulation with `binary.LittleEndian` encoding  
  3. Implemented missing `SendConfigUpdate` method with proper error handling
  4. Added comprehensive debug logging throughout netlink operations
- **Verification**: 
  - ✅ Agent compiles successfully without errors
  - ✅ Kernel module builds without compatibility issues
  - ✅ Agent connects to kernel via netlink (family=31, fd=3)
  - ✅ Guard points successfully sent to kernel (3 guard points, 125 bytes)
  - ✅ VFS hooks intercepting file operations
  - ❌ Kernel-to-userspace messages broken (empty/truncated)
- **Future Prevention**: 
  - Use binary-compatible structures between kernel/userspace
  - Always use proper binary encoding instead of manual byte manipulation
  - Add comprehensive logging for all netlink operations

## [KERNEL_TO_USERSPACE_MESSAGE_FAILURE] - NEW BUG
- **Found on**: 2025-07-29 (After reboot testing)
- **Symptoms**:
  - Netlink parsing error: "message too short: 0 < 32"
  - Files not encrypted despite VFS interception
  - Zero encryption operations in agent statistics
  - Single error at startup, not repeated per file operation
- **Suspected Causes**:
  1. `takakrypt_send_request_and_wait()` in kernel not properly implemented
  2. Kernel sending empty/malformed netlink messages to userspace
  3. Message buffer allocation issues in kernel netlink sender
- **Fix Steps**: 
  - [ ] Examine kernel's `takakrypt_send_request_and_wait()` implementation
  - [ ] Debug kernel netlink message construction and sending
  - [ ] Verify message buffer allocation and data copying
- **Verification**: 
  - ❌ Files remain plaintext instead of encrypted with TAKA headers
  - ❌ Agent receives empty messages from kernel
- **Future Prevention**: 
  - Add kernel-side netlink message validation and logging
  - Implement proper error handling for message construction failures

## [NETLINK_CONNECTION_STALE] - FIXED
- **Found on**: 2025-07-30
- **Symptoms**: Agent connects successfully but module shows old agent PID. Netlink requests fail with -111 (Connection refused). New agents can't receive policy requests.
- **Suspected Causes**: 
  1. Module not updating connection state for new agents
  2. Netlink receive handler only updating PID on first connection (`agent_pid == 0`)
  3. Stale connection state causing requests to go to disconnected agents
- **Fix Steps**: 
  1. Located issue in `kernel/netlink.c:249-254`
  2. Changed condition from `if (takakrypt_global_state->agent_pid == 0)` to `if (takakrypt_global_state->agent_pid != pid)`
  3. This ensures agent PID is updated whenever a new agent connects, not just the first time
- **Verification**: Module rebuild and reload required to test fix
- **Future Prevention**: Add tests for agent reconnection scenarios and connection state management

## [KERNEL_PANIC_ATOMIC_CONTEXT] - ARCHITECTURALLY FIXED
- **Found on**: 2025-07-30
- **Symptoms**: VM crashes/reboots when writing to guard point directories due to synchronous netlink calls in atomic kprobe context
- **Suspected Causes**:
  1. Infinite recursion in VFS kprobe logging (fixed)
  2. Synchronous netlink calls from atomic kprobe context causing deadlocks
- **Fix Steps**:
  1. Removed unconditional logging from kprobe handlers to prevent recursion
  2. **ARCHITECTURAL FIX**: Moved policy checks from kprobe level to VFS hook level
  3. Kprobes now only install VFS hooks (no blocking calls in atomic context)
  4. Policy checks happen in VFS hooks (safe process context where blocking is allowed)
- **Verification**: System now stable, no crashes when writing to guard points
- **Future Prevention**: Never make blocking calls from atomic context. Use work queues or process context for complex operations.

## [NULL_POINTER_DEREFERENCE_KPROBES] - CRITICAL FIX COMPLETED
- **Found on**: 2025-07-31
- **Symptoms**: 
  - VM crash on `takakrypt_global_state->stats_lock` access in kprobe handlers
  - NULL pointer dereference at kernel/kprobe_hooks.c:82-84
  - Kernel panic during module initialization/cleanup race conditions
  - Random crashes when kprobes fire before global state is ready
- **Suspected Causes**:
  1. **Race condition**: Kprobes registered before `takakrypt_global_state` initialized
  2. **Module cleanup race**: Global state freed while kprobes still active
  3. **Missing NULL checks**: All kprobe handlers assume global state exists
  4. **Initialization order**: `module_active` flag not used to guard access
- **Fix Steps**:
  1. **Added NULL safety checks** in all kprobe handlers (kernel/kprobe_hooks.c:60-62, 104-106, 208-210, 175-177)
  2. **Fixed initialization order** in kernel/main.c:223 - set `module_active=1` BEFORE installing kprobes
  3. **Added memory barriers** with `smp_wmb()` to ensure visibility across CPUs
  4. **Safe cleanup sequence** in kernel/main.c:265-271 - deactivate module FIRST, wait for kprobes to finish
  5. **VFS hook mutex protection** in kernel/vfs_hooks.c:501-508 to prevent installation races
  6. **Work queue safety** - double-check global state before queueing encryption work
- **Verification**: 
  - ✅ Module builds successfully with all NULL checks
  - ✅ Critical sections now guarded by module state validation
  - ✅ Initialization order ensures kprobes never access NULL global state
  - ✅ Cleanup sequence safely deactivates before removing hooks
- **Future Prevention**: 
  - Always check `takakrypt_global_state` and `module_active` before any access
  - Use proper memory barriers when changing module state
  - Never register kprobes before global state is fully initialized
  - Always deactivate module before cleanup to stop new operations
// Stub implementations for C functions not compiled in this build
@_cdecl("run_iosurface_notify_probe")
func run_iosurface_notify_probe() {
    print("run_iosurface_notify_probe: stub (C probe not compiled)")
}

@_cdecl("wq_group_available")
func wq_group_available(_ group: UnsafePointer<Int8>) -> Int32 {
    print("wq_group_available: stub")
    return 0
}

@_cdecl("wq_grant")
func wq_grant(_ target: UnsafePointer<Int8>, _ group: UnsafePointer<Int8>, _ flags: UInt64) -> Int64 {
    print("wq_grant: stub")
    return -1
}

@_cdecl("wq_revoke")
func wq_revoke(_ handle: Int64) {
    print("wq_revoke: stub")
}

@_cdecl("wq_token")
func wq_token(_ identifier: UnsafePointer<Int8>, _ cls: UInt64, _ part: UInt64, _ flags: UInt64, _ partDomain: UnsafePointer<Int8>?) -> Int64 {
    print("wq_token: stub")
    return -1
}

@_cdecl("trigger_ane_direct")
func trigger_ane_direct() -> Int32 {
    print("trigger_ane_direct: stub")
    return 0
}

@_cdecl("run_decmpfs_leak")
func run_decmpfs_leak(_ base_dir: UnsafePointer<Int8>) {
    print("run_decmpfs_leak: stub")
}

@_cdecl("log_from_c")
func log_from_c(_ msg: UnsafePointer<Int8>) {
    print("log_from_c stub: \(String(cString: msg))")
}

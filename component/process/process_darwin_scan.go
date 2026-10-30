//go:build darwin

package process

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// The socket table sysctl only reports sockets owned by the calling process on
// current macOS, so a proxy that did not open the client socket sees nothing.
// proc_info can enumerate every process's file descriptors for the same user,
// which is how lsof answers the same question, and that covers the apps a
// desktop proxy actually carries. The core is built with cgo off, so the calls
// go through the same syscall mihomo already uses for proc_pidpath.
const (
	procInfoCallListPids = 1
	procInfoCallPidInfo  = 2
	procInfoCallPidFdInfo = 3
	procAllPids          = 1
	procPidListFds       = 1
	procPidFdSocketInfo  = 3
	procPidPathInfo      = 11
	socketFdType         = 2

	sockInfoIn  = 1
	sockInfoTcp = 2

	// struct socket_fdinfo: proc_fileinfo (24) then socket_info. Offsets and
	// the total size are measured from the SDK headers; see the layout notes
	// on scanSocketInfo.
	socketFdInfoSize = 792
	soiKindOffset    = 256
	soiProtoOffset   = 264
	iniLportOffset   = 4
	iniVflagOffset   = 24
	iniLaddrOffset   = 48
	in4AddrOffset    = 12

	scanCacheLifetime = 250 * time.Millisecond
	pathCacheLifetime = 30 * time.Second
)

type socketKey struct {
	port  uint16
	proto string
}

type socketOwner struct {
	path string
	addr netip.Addr
}

type scanCacheEntry struct {
	owners map[socketKey]socketOwner
	at     time.Time
}

type pathCacheEntry struct {
	path string
	at   time.Time
}

var (
	scanMu    sync.Mutex
	scanCache = scanCacheEntry{}
	pathMu    sync.Mutex
	pathCache = map[int32]pathCacheEntry{}
)

// findProcessNameByScan walks every process's sockets looking for the local
// endpoint the tunnel was handed. It backs the sysctl lookup: a miss there
// means "not mine", not "not there".
func findProcessNameByScan(network string, ip netip.Addr, port int) (uint32, string, error) {
	if network != TCP && network != UDP {
		return 0, "", ErrInvalidNetwork
	}
	if port <= 0 || port > 65535 {
		return 0, "", ErrNotFound
	}
	want := socketKey{port: uint16(port), proto: network}
	wantIP := ip.Unmap()

	owner, ok := scanOwner(func(key socketKey, addr netip.Addr) bool {
		if key != want {
			return false
		}
		// A wildcard socket matches any address, and the tunnel hands over
		// an unspecified source for some flows.
		if !wantIP.IsValid() || wantIP.IsUnspecified() ||
			!addr.IsValid() || addr.IsUnspecified() {
			return true
		}
		return addr.Unmap() == wantIP
	})
	if !ok {
		return 0, "", ErrNotFound
	}
	return 0, owner, nil
}

func scanOwner(match func(socketKey, netip.Addr) bool) (string, bool) {
	scanMu.Lock()
	defer scanMu.Unlock()

	if scanCache.owners != nil && time.Since(scanCache.at) < scanCacheLifetime {
		for key, owner := range scanCache.owners {
			if match(key, owner.addr) {
				return owner.path, true
			}
		}
		return "", false
	}

	owners := collectSockets()
	scanCache = scanCacheEntry{owners: owners, at: time.Now()}
	for key, owner := range owners {
		if match(key, owner.addr) {
			return owner.path, true
		}
	}
	return "", false
}

func collectSockets() map[socketKey]socketOwner {
	owners := map[socketKey]socketOwner{}
	const batch = 8192
	buf := make([]byte, batch*4)
	count, err := procInfo(procInfoCallListPids, procAllPids, 0, 0, buf, len(buf))
	if err != nil || count <= 0 {
		return owners
	}
	if count > batch {
		count /= 4
	}
	if count > batch {
		count = batch
	}
	fds := make([]byte, 64*1024)
	info := make([]byte, socketFdInfoSize)
	for index := 0; index < count; index++ {
		pid := int32(binary.LittleEndian.Uint32(buf[index*4:]))
		if pid <= 0 {
			continue
		}
		used, err := procInfo(procInfoCallPidInfo, int(pid), procPidListFds, 0, fds, len(fds))
		if err != nil || used <= 0 {
			continue
		}
		for offset := 0; offset+8 <= used; offset += 8 {
			fdType := binary.LittleEndian.Uint32(fds[offset+4:])
			if fdType != socketFdType {
				continue
			}
			fd := int(int32(binary.LittleEndian.Uint32(fds[offset:])))
			if fd < 0 {
				continue
			}
			if n, err := procInfo(procInfoCallPidFdInfo, int(pid), procPidFdSocketInfo, fd, info, len(info)); err != nil || n <= 0 {
				continue
			}
			key, addr, ok := scanSocketInfo(info)
			if !ok {
				continue
			}
			if _, exists := owners[key]; exists {
				continue
			}
			path, ok := pathOf(pid)
			if !ok || path == "" {
				continue
			}
			owners[key] = socketOwner{path: path, addr: addr}
		}
	}
	return owners
}

// scanSocketInfo reads the local endpoint out of a struct socket_fdinfo:
//
//	proc_fileinfo      24
//	socket_info.soi_kind                232 -> 256
//	socket_info.soi_proto (union)       240 -> 264
//	  in_sockinfo.insi_lport              4 -> 268 (int, network order)
//	  in_sockinfo.insi_vflag             24 -> 288
//	  in_sockinfo.insi_laddr             48 -> 312 (in4in6_addr, addr4 at +12)
func scanSocketInfo(info []byte) (socketKey, netip.Addr, bool) {
	kind := int32(binary.LittleEndian.Uint32(info[soiKindOffset:]))
	var proto string
	switch kind {
	case sockInfoTcp:
		proto = TCP
	case sockInfoIn:
		proto = UDP
	default:
		return socketKey{}, netip.Addr{}, false
	}
	raw := binary.LittleEndian.Uint32(info[soiProtoOffset+iniLportOffset:])
	// The kernel reports the port in network byte order.
	port := uint16(raw&0xff)<<8 | uint16((raw>>8)&0xff)
	if port == 0 {
		return socketKey{}, netip.Addr{}, false
	}
	vflag := info[soiProtoOffset+iniVflagOffset]
	var addr netip.Addr
	if vflag&0x1 != 0 {
		start := soiProtoOffset + iniLaddrOffset + in4AddrOffset
		addr = netip.AddrFrom4([4]byte(info[start : start+4]))
	} else {
		start := soiProtoOffset + iniLaddrOffset
		addr = netip.AddrFrom16([16]byte(info[start : start+16]))
	}
	return socketKey{port: port, proto: proto}, addr, true
}

func procInfo(callnum, pid, flavor, arg int, buf []byte, size int) (int, error) {
	var pointer unsafe.Pointer
	if len(buf) > 0 {
		pointer = unsafe.Pointer(&buf[0])
	}
	result, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		uintptr(callnum),
		uintptr(pid),
		uintptr(flavor),
		uintptr(arg),
		uintptr(pointer),
		uintptr(size),
	)
	if errno != 0 {
		return 0, errno
	}
	if int(result) < 0 {
		return 0, ErrNotFound
	}
	return int(result), nil
}

func pathOf(pid int32) (string, bool) {
	pathMu.Lock()
	if entry, ok := pathCache[pid]; ok && time.Since(entry.at) < pathCacheLifetime {
		pathMu.Unlock()
		return entry.path, true
	}
	pathMu.Unlock()

	buf := make([]byte, 4096)
	// proc_pidpath reports no length of its own; the kernel fills the buffer
	// and answers zero, which is why the bytes are read to their terminator.
	if _, err := procInfo(procInfoCallPidInfo, int(pid), procPidPathInfo, 0, buf, len(buf)); err != nil {
		return "", false
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	if end == 0 {
		return "", false
	}
	path := string(buf[:end])
	pathMu.Lock()
	pathCache[pid] = pathCacheEntry{path: path, at: time.Now()}
	pathMu.Unlock()
	return path, true
}

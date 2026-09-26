# Capture the experimental TLCP PQKEX ClientHello

This capture helper sends one real TLCP ClientHello over TCP loopback by calling
the patched GmSSL `tlcp_send_client_hello()` path. The receiving side uses
GmSSL's generic ClientHello parser and the same `tlcp_process_client_pqkex()`
handler used by the patched TLCP server.

The helper is intentionally capability-only. It does not send a ServerHello,
perform ML-KEM, modify the TLCP master secret, or complete a TLCP handshake.

## Build the patched GmSSL copy

Keep the fixed `third_party/GmSSL` submodule clean by using a temporary
worktree:

```sh
capture_root=$(mktemp -d)
git -C third_party/GmSSL worktree add --detach "$capture_root/GmSSL" HEAD
./scripts/apply_gmssl_patches.sh "$capture_root/GmSSL"
cmake -S "$capture_root/GmSSL" -B "$capture_root/GmSSL/build" \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
cmake --build "$capture_root/GmSSL/build" -j
./scripts/build_gmssl_pqkex_capture_demo.sh \
  "$capture_root/GmSSL/build"
```

The final command prints the path of `pqkex_capture_demo`.

## Capture inside the Ubuntu virtual machine

Capturing inside Ubuntu is independent of the VM's NAT or bridged networking
mode. In terminal 1:

```sh
sudo tcpdump -i lo -s 0 -w pqkex-clienthello.pcap 'tcp port 44330'
```

In terminal 2:

```sh
./build-pqkex-capture/pqkex_capture_demo 44330
```

After the demo prints `PASS`, return to terminal 1 and press `Ctrl-C`. Verify
that the file is non-empty:

```sh
ls -lh pqkex-clienthello.pcap
```

Copy the PCAP to a Windows shared folder or from Windows PowerShell with SCP:

```powershell
scp USER@VM_IP:/path/to/hybrid-pqc-cert/pqkex-clienthello.pcap .
```

## Inspect in Wireshark on Windows

Open `pqkex-clienthello.pcap`, select the TCP packet carrying the ClientHello,
and use **Analyze -> Decode As... -> TLS** if Wireshark does not decode it
automatically. The private extension may be displayed as `Unknown (65282)`.

Use this display filter when Wireshark recognizes the extension:

```text
tls.handshake.extension.type == 65282
```

Otherwise use **Edit -> Find Packet -> Hex Value** and search for:

```text
ff02000400020001
```

The bytes mean:

```text
FF 02 | 00 04 | 00 02 | 00 01
 type | extlen | listlen| ML-KEM-768 experimental KEM ID
```

There is no `0xFF02` ServerHello extension in the current implementation. A
successful capture proves only that capability advertisement reached the real
TLCP ClientHello wire path and that the server-side handler selected the common
KEM.

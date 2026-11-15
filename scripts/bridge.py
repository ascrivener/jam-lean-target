#!/usr/bin/env python3
"""Unix-socket listener for `jam-lean-target serve`: one fresh process per connection, bytes
pumped both ways (what `socat UNIX-LISTEN:SOCK,fork EXEC:...` does in the Docker image)."""
import os, socket, subprocess, sys, threading

def pump(src_read, dst_write, close):
    try:
        while True:
            b = src_read(65536)
            if not b: break
            dst_write(b)
    except OSError:
        pass
    finally:
        close()

def serve(sock_path, cmd):
    if os.path.exists(sock_path): os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); srv.bind(sock_path); srv.listen(4)
    while True:
        conn, _ = srv.accept()
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        def w(b, p=p): p.stdin.write(b); p.stdin.flush()
        t1 = threading.Thread(target=pump, args=(conn.recv, w, lambda p=p: p.stdin.close()), daemon=True)
        t2 = threading.Thread(target=pump, args=(p.stdout.read1, conn.sendall, lambda c=conn: c.close()), daemon=True)
        t1.start(); t2.start()

serve(sys.argv[1], sys.argv[2:])

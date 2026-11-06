#!/usr/bin/env python3
# relogin_attach — attach frida to an ALREADY-RUNNING, plain-launched VK Calls
# process and dump every libssl plaintext buffer to a file. The Go relogin driver
# (internal/vk/relogin.go) runs this and scans the dump for the one-year
# access_token the app fetches during VK ID login.
#
# Why attach and not spawn: spawn+instrument-at-startup destabilises the app
# under software GL (the pid churns every ~minute, which breaks the silent-token
# deep-link handoff and triggers repeat flash-calls). Attaching to a stable,
# plain-launched instance does not. QtNetwork dlopen's libssl.so.3, so an
# LD_PRELOAD interposer misses it; frida sees SSL_read/SSL_write regardless.
#
# Usage: relogin_attach.py <out.bin> <pid> <seconds>
import sys, time, frida

JS = r"""
function h(name, bufArg){
  var m = Process.getModuleByName('libssl.so.3');
  var a = m.findExportByName(name); if(!a) return;
  Interceptor.attach(a, {
    onEnter: function(x){ this.buf=x[bufArg]; this.num=x[bufArg+1].toInt32(); this.rd=(name.indexOf('read')>=0); },
    onLeave: function(r){ try{ var len=this.rd?r.toInt32():this.num;
      if(len<=0||len>1<<20) return; send({rd:this.rd}, this.buf.readByteArray(len)); }catch(e){} }
  });
}
['SSL_write','SSL_read'].forEach(function(n){h(n,1);});
"""

def main():
    out = open(sys.argv[1], 'ab')
    pid = int(sys.argv[2])
    secs = int(sys.argv[3])
    s = frida.get_local_device().attach(pid)
    sc = s.create_script(JS)
    sc.on('message', lambda m, d: (out.write(d), out.flush()) if m.get('type') == 'send' and d else None)
    sc.load()
    print('attached', pid, flush=True)
    time.sleep(secs)

if __name__ == '__main__':
    main()

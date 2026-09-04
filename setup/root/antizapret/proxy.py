#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

import subprocess,time,argparse,threading,os,signal
from collections import deque
from ipaddress import IPv4Network
from dnslib import DNSRecord,RCODE,QTYPE,A
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger,TCPServer

class ProxyResolver(BaseResolver):
    def __init__(self,dns,dns_port,dns_timeout,ip_range,ttl,expire,quarantine,evict):
        self._env=os.environ.copy()
        # Free fake IPs: set for membership, deque for FIFO reuse order
        self.ip_free=set()
        self.ip_queue=deque()
        for host in IPv4Network(ip_range).hosts():
            fake_ip=str(host)
            self.ip_free.add(fake_ip)
            self.ip_queue.append(fake_ip)
        # Fake IP -> time it becomes reusable, only for quarantined ones
        self.ip_until={}
        self.ip_map={}
        # Loading existing fake IP mapping
        mapping=subprocess.run(["/usr/sbin/iptables","-w","-t","nat","-S","ANTIZAPRET-MAPPING"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,env=self._env)
        if mapping.returncode:
            subprocess.run(["/usr/sbin/iptables","-w","-t","nat","-N","ANTIZAPRET-MAPPING"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,env=self._env)
        warp_ips=set()
        warp=subprocess.run(["/usr/sbin/iptables","-w","-t","mangle","-S","ANTIZAPRET-WARP"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,env=self._env)
        if warp.returncode:
            subprocess.run(["/usr/sbin/iptables","-w","-t","mangle","-N","ANTIZAPRET-WARP"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,env=self._env)
        for line in warp.stdout.splitlines():
            parts=line.split()
            if len(parts) < 8:
                continue
            warp_ips.add(parts[3].split("/")[0])
        now=time.time()
        for line in mapping.stdout.splitlines():
            parts=line.split()
            if len(parts) < 8:
                continue
            fake_ip=parts[3].split("/")[0]
            real_ip=parts[7]
            if not self.mapping_ip(real_ip,fake_ip,now,fake_ip in warp_ips):
                print("Restarting: Invalid loaded fake IP mapping")
                self.fatal(1)
        print(f"Loaded: {len(self.ip_map)} fake IPs")
        self.dns=dns
        self.dns_port=dns_port
        self.dns_timeout=dns_timeout
        self.ttl=ttl
        # Seconds of inactivity before fake IP is removed
        self.expire=expire
        # Seconds a released fake IP is withheld before it is handed out again
        self.quarantine=quarantine
        # How many mappings are dropped at once when the IP pool runs dry
        self.evict=evict
        # Check for expired mapping more often than the threshold itself
        self.interval=max(1,self.expire // 4)
        self.lock=threading.Condition()
        # Start thread for expire fake IP mapping
        threading.Thread(target=self.expire_mapping_worker,daemon=True).start()

    def fatal(self,code):
        try:
            subprocess.run(["/usr/sbin/iptables","-w","-t","nat","-F","ANTIZAPRET-MAPPING"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,env=self._env)
            subprocess.run(["/usr/sbin/iptables","-w","-t","mangle","-F","ANTIZAPRET-WARP"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,env=self._env)
        finally:
            os._exit(code)

    def apply_rules(self,rules):
        mangle=["*mangle"]
        nat=["*nat"]
        for table,rule in rules:
            if table=="mangle":
                mangle.append(rule)
            else:
                nat.append(rule)
        lines=[]
        if len(mangle) > 1:
            lines.extend(mangle)
            lines.append("COMMIT")
        if len(nat) > 1:
            lines.extend(nat)
            lines.append("COMMIT")
        if not lines:
            return
        subprocess.run(["/usr/sbin/iptables-restore","-w","-n"],input="\n".join(lines).encode(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,env=self._env)

    def mapping_rules(self,real_ip,fake_ip,warp,add):
        rules=[]
        op="-A" if add else "-D"
        if warp:
            rules.append(("mangle",f"{op} ANTIZAPRET-WARP -d {fake_ip} -j MARK --set-mark 0x2"))
        rules.append(("nat",f"{op} ANTIZAPRET-MAPPING -d {fake_ip} -j DNAT --to-destination {real_ip}"))
        return rules

    def alloc_fake_ip(self,now):
        # Caller must hold the lock
        while self.ip_queue:
            fake_ip=self.ip_queue[0]
            # Taken while sitting in the queue, drop it lazily
            if fake_ip not in self.ip_free:
                self.ip_queue.popleft()
                continue
            until=self.ip_until.get(fake_ip)
            if until is not None:
                # Queue is ordered by release time, nothing behind it is ready either
                if until > now:
                    return None
                del self.ip_until[fake_ip]
            self.ip_queue.popleft()
            self.ip_free.discard(fake_ip)
            return fake_ip
        return None

    def release_fake_ip(self,fake_ip,now,quarantine):
        # Caller must hold the lock
        self.ip_free.add(fake_ip)
        if quarantine:
            self.ip_until[fake_ip]=now + self.quarantine
            self.ip_queue.append(fake_ip)
        else:
            self.ip_until.pop(fake_ip,None)
            self.ip_queue.appendleft(fake_ip)

    def reserve_fake_ip(self,real_ip,now,warp):
        # Returns (fake_ip,rules), rules is None when the mapping already exists
        key=(real_ip,warp)
        deadline=now + self.dns_timeout
        with self.lock:
            while True:
                entry=self.ip_map.get(key)
                if entry is None:
                    break
                if entry["ready"]:
                    entry["used"]=now
                    return entry["fake_ip"],None
                # Another request reserved this real IP but its rule is not in place yet
                if not self.lock.wait(max(0,deadline - time.time())):
                    print(f"Error: Timeout waiting for pending fake IP (real_ip={real_ip} warp={warp})")
                    return None,None
            fake_ip=self.alloc_fake_ip(now)
            if fake_ip is None:
                return None,None
            self.ip_map[key]={"fake_ip": fake_ip,"used": now,"ready": False}
        #print(f"Mapping: {fake_ip} to {real_ip} warp={warp}")
        return fake_ip,self.mapping_rules(real_ip,fake_ip,warp,True)

    def commit_mapping(self,keys):
        if not keys:
            return
        with self.lock:
            for key in keys:
                entry=self.ip_map.get(key)
                if entry:
                    entry["ready"]=True
            self.lock.notify_all()

    def rollback_mapping(self,keys):
        if not keys:
            return
        with self.lock:
            for key in keys:
                entry=self.ip_map.pop(key,None)
                if entry:
                    # Never handed out, so it goes back without quarantine
                    self.release_fake_ip(entry["fake_ip"],0,False)
            self.lock.notify_all()

    def evict_mapping(self,now):
        with self.lock:
            ready=[(entry["used"],key) for key,entry in self.ip_map.items() if entry["ready"]]
            if not ready:
                return False
            ready.sort()
            evicted=[]
            for _,key in ready[:self.evict]:
                entry=self.ip_map.pop(key)
                evicted.append((key,entry["fake_ip"]))
        rules=[]
        for (real_ip,warp),fake_ip in evicted:
            rules.extend(self.mapping_rules(real_ip,fake_ip,warp,False))
        try:
            self.apply_rules(rules)
        except Exception as e:
            print(f"Error: {e}")
            print("Restarting: Evict fake IP mapping failed")
            self.fatal(4)
        with self.lock:
            for _,fake_ip in evicted:
                # Pool is empty, these are needed right now
                self.release_fake_ip(fake_ip,now,False)
            self.lock.notify_all()
        print(f"Evicted: {len(evicted)} fake IPs")
        return True

    def mapping_ip(self,real_ip,fake_ip,now,warp):
        if self.ip_map.get((real_ip,warp)):
            print(f"Error: Real IP {real_ip} already mapped")
            return False
        if fake_ip not in self.ip_free:
            print(f"Error: Fake IP {fake_ip} not in IP pool")
            return False
        self.ip_free.discard(fake_ip)
        self.ip_map[(real_ip,warp)]={"fake_ip": fake_ip,"used": now,"ready": True}
        #print(f"Mapping: {fake_ip} to {real_ip} warp={warp}")
        return True

    def expire_mapping_worker(self):
        while True:
            time.sleep(self.interval)
            try:
                self.expire_mapping()
            except Exception as e:
                print(f"Error: {e}")
                print("Restarting: Expire fake IP mapping failed")
                self.fatal(2)

    def expire_mapping(self):
        with self.lock:
            now=time.time()
            expired=[]
            for key,entry in self.ip_map.items():
                if entry["ready"] and now - entry["used"] > self.expire:
                    expired.append((key,entry["fake_ip"]))
            for key,_ in expired:
                del self.ip_map[key]
        if not expired:
            return
        rules=[]
        for (real_ip,warp),fake_ip in expired:
            rules.extend(self.mapping_rules(real_ip,fake_ip,warp,False))
            #print(f"Unmapping: {fake_ip} to {real_ip} warp={warp}")
        self.apply_rules(rules)
        now=time.time()
        with self.lock:
            for _,fake_ip in expired:
                self.release_fake_ip(fake_ip,now,True)
            self.lock.notify_all()
        print(f"Expired: {len(expired)} fake IPs")

    def dump_status(self,signum=None,frame=None):
        now=time.time()
        with self.lock:
            mapped=len(self.ip_map)
            pending=sum(1 for entry in self.ip_map.values() if not entry["ready"])
            free=len(self.ip_free)
            held=sum(1 for fake_ip,until in self.ip_until.items() if until > now and fake_ip in self.ip_free)
            oldest=int(now - min((entry["used"] for entry in self.ip_map.values()),default=now))
        print(f"Status: mapped={mapped} pending={pending} free={free - held} quarantined={held} oldest={oldest}s ttl={self.ttl} expire={self.expire} quarantine={self.quarantine}")

    def resolve(self,request,handler):
        warp=handler.server.warp
        try:
            # Blocked domains are only reachable over fake IPv4, never answer AAAA
            if request.q.qtype==QTYPE.AAAA:
                return request.reply()
            if handler.protocol=="udp":
                data=request.send(self.dns,self.dns_port,timeout=self.dns_timeout)
            else:
                data=request.send(self.dns,self.dns_port,tcp=True,timeout=self.dns_timeout)
            reply=DNSRecord.parse(data)
            if request.q.qtype==QTYPE.A:
                now=time.time()
                records=[]
                rules=[]
                keys=[]
                total=0
                mapped=0
                for record in reply.rr:
                    record.ttl=self.ttl
                    if record.rtype!=QTYPE.A:
                        records.append(record)
                        continue
                    total+=1
                    real_ip=str(record.rdata)
                    fake_ip,new=self.reserve_fake_ip(real_ip,now,warp)
                    if fake_ip is None and self.evict_mapping(now):
                        fake_ip,new=self.reserve_fake_ip(real_ip,now,warp)
                    if fake_ip is None:
                        print(f"Error: No fake IP left in IP pool (real_ip={real_ip} qname={request.q.qname} warp={warp})")
                        continue
                    if new:
                        rules.extend(new)
                        keys.append((real_ip,warp))
                    record.rdata=A(fake_ip)
                    records.append(record)
                    mapped+=1
                if rules:
                    try:
                        self.apply_rules(rules)
                    except Exception as e:
                        print(f"Error: {e} (rules={len(rules)} qname={request.q.qname} warp={warp})")
                        self.rollback_mapping(keys)
                        reply=request.reply()
                        reply.header.rcode=RCODE.SERVFAIL
                        return reply
                    self.commit_mapping(keys)
                # Unmapped records are dropped, fail only when nothing survived
                if total and not mapped:
                    reply=request.reply()
                    reply.header.rcode=RCODE.SERVFAIL
                    return reply
                reply.rr=records
        except Exception as e:
            print(f"Error: {e} (qname={request.q.qname} qtype={QTYPE[request.q.qtype]} protocol={handler.protocol})")
            reply=request.reply()
            reply.header.rcode=RCODE.SERVFAIL
        return reply

if __name__=="__main__":
    p=argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument("--dns",default="127.2.2.2:53",help="Upstream DNS server:port (default:127.2.2.2:53)")
    p.add_argument("--dns-timeout",type=float,default=5,help="Upstream DNS timeout (default: 5s)")
    p.add_argument("--ip-range",default="198.18.0.0/15",help="Fake IP range (default:198.18.0.0/15)")
    p.add_argument("--ttl",type=int,default=1800,help="TTL in seconds for A records (default: 1800)")
    p.add_argument("--expire",type=int,default=0,help="Seconds of inactivity before fake IP is removed (default: ttl * 2)")
    p.add_argument("--quarantine",type=int,default=-1,help="Seconds a released fake IP is withheld before reuse (default: ttl)")
    p.add_argument("--evict",type=int,default=64,help="Mappings dropped at once when the IP pool runs dry (default: 64)")
    p.add_argument("--proxy",default="127.3.3.3:53",help="Local Fake IP proxy listen address:port (default:127.3.3.3:53)")
    p.add_argument("--warp",default="127.4.4.4:53",help="Local WARP proxy listen address:port (default:127.4.4.4:53)")
    p.add_argument("--log",default="truncated,error",help="Log hooks to enable (default: +truncated,+error,-request,-reply,-recv,-send,-data)")
    p.add_argument("--log-prefix",action="store_true",default=False,help="Log prefix (timestamp/handler/resolver) (default: False)")
    args=p.parse_args()
    args.dns,_,args.dns_port=args.dns.partition(":")
    args.dns_port=int(args.dns_port or 53)
    args.proxy,_,args.proxy_port=args.proxy.partition(":")
    args.proxy_port=int(args.proxy_port or 53)
    args.warp,_,args.warp_port=args.warp.partition(":")
    args.warp_port=int(args.warp_port or 53)
    if args.expire <= 0:
        args.expire=args.ttl * 2
    if args.quarantine < 0:
        args.quarantine=args.ttl
    TCPServer.request_queue_size=128
    print("Starting...")
    resolver=ProxyResolver(args.dns,args.dns_port,args.dns_timeout,args.ip_range,args.ttl,args.expire,args.quarantine,args.evict)
    signal.signal(signal.SIGUSR1,resolver.dump_status)
    logger=DNSLogger(args.log,prefix=args.log_prefix)
    def start_server(address,port,tcp=False):
        server=DNSServer(resolver,port=port,address=address,tcp=tcp,logger=logger,handler=DNSHandler)
        server.server.warp=address==args.warp
        server.start_thread()
        return server
    udp_server=start_server(args.proxy,args.proxy_port)
    tcp_server=start_server(args.proxy,args.proxy_port,tcp=True)
    print(f"Started proxy resolver {args.proxy}:{args.proxy_port} -> {args.dns}:{args.dns_port}")
    udp_warp=start_server(args.warp,args.warp_port)
    tcp_warp=start_server(args.warp,args.warp_port,tcp=True)
    print(f"Started WARP resolver {args.warp}:{args.warp_port} -> {args.dns}:{args.dns_port}")
    while all(s.thread.is_alive() for s in (udp_server,tcp_server,udp_warp,tcp_warp)):
        time.sleep(1)
    print("Restarting: A server thread died")
    os._exit(3)

"""Own maintenance for syslog/kern.log only; no restart, truncation or app logs."""
import errno,fcntl,json,os,pathlib,stat,subprocess,sys,time
CONFIG='/etc/logrotate.d/5path-ir-system-logs'
STATE=pathlib.Path('/var/lib/logrotate/status')
ARCHIVES=[pathlib.Path('/var/log/syslog.1'),pathlib.Path('/var/log/kern.log.1')]
def closed(identity):
 for p in pathlib.Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   for fd in(p/'fd').iterdir():
    try:
     s=fd.stat()
     if(s.st_dev,s.st_ino)==identity:return False
    except OSError as e:
     if e.errno not in [errno.ENOENT,errno.ESRCH]:raise
  except OSError as e:
   if e.errno not in [errno.ENOENT,errno.ESRCH]:raise
 return True
def main():
 own=pathlib.Path('/run/lock/5path-ir-log-maintenance.lock').open('a')
 try:fcntl.flock(own,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:return dict(status='SKIPPED_OWN_LOCK')
 force=sys.argv[1:]==['--initial'];assert not sys.argv[1:]or force,'EXACT_MAINTENANCE_MODE'
 args=['/usr/sbin/logrotate','--state',str(STATE)]
 if force:args.append('--force')
 args.append(CONFIG);z=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if z.returncode==3:return dict(status='SKIPPED_GLOBAL_LOGROTATE_BUSY')
 assert z.returncode==0,z.stderr[-1500:]
 # Reacquire the CURRENT state inode after native logrotate finishes. This
 # prevents its daily job from renaming an archive during manual compression.
 state=STATE.open('r+')
 try:fcntl.flock(state,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:return dict(status='ROTATED_COMPRESSION_DEFERRED_BUSY')
 assert(state.fileno()>=0 and os.fstat(state.fileno()).st_ino==STATE.stat().st_ino),'LOGROTATE_STATE_INODE_CHANGED'
 result=dict(status='OK',rotated=True,compressed=[],skipped=[])
 for p in ARCHIVES:
  if not p.exists():continue
  assert p.parent==pathlib.Path('/var/log')and p.resolve()==p and stat.S_ISREG(p.lstat().st_mode)and p.stat().st_nlink==1
  before=p.stat();identity=(before.st_dev,before.st_ino);until=time.monotonic()+7
  while not closed(identity)and time.monotonic()<until:time.sleep(.2)
  if not closed(identity):result['skipped'].append(dict(path=str(p),reason='STILL_OPEN'));continue
  current=p.stat();assert(current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns)==(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns),'ARCHIVE_CHANGED'
  target=p.with_name(p.name+'.gz');assert not target.exists(),'ARCHIVE_TARGET_EXISTS'
  temporary=p.with_name(p.name+'.5path-gzip-'+str(os.getpid())+'.tmp');created_inode=None
  try:
   with temporary.open('xb')as output:
    temporary.chmod(0o600);created_inode=temporary.stat().st_ino
    z=subprocess.run(['/bin/gzip','-1','--stdout','--',str(p)],stdout=output,stderr=subprocess.PIPE,text=True,timeout=110);output.flush();os.fsync(output.fileno())
   assert z.returncode==0,z.stderr[-500:]
   z=subprocess.run(['/bin/gzip','--test','--',str(temporary)],capture_output=True,text=True,timeout=40);assert z.returncode==0,z.stderr[-500:]
   current=p.stat();assert(current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns)==(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)and closed(identity),'ARCHIVE_CHANGED_DURING_COMPRESSION'
   os.chown(temporary,before.st_uid,before.st_gid);temporary.chmod(stat.S_IMODE(before.st_mode));os.utime(temporary,ns=(before.st_atime_ns,before.st_mtime_ns))
   os.link(temporary,target);p.unlink();after=target.stat()
  finally:
   if created_inode is not None and temporary.exists():assert temporary.stat().st_ino==created_inode;temporary.unlink()
  result['compressed'].append(dict(path=str(target),before_allocated=before.st_blocks*512,after_allocated=after.st_blocks*512))
 return result
if __name__=='__main__':print(json.dumps(main()))

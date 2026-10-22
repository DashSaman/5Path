"""Real logrotate behavior when a closed delayed archive is compressed early."""
import pathlib,tempfile,subprocess,shutil,json
d=pathlib.Path(tempfile.mkdtemp(prefix='ir-rotate-fixture-'));p=d/'sample.log';cfg=d/'policy';state=d/'state';result={}
def run(a):
 z=subprocess.run(a,capture_output=True,text=True,timeout=6);assert z.returncode==0,z.stderr;return z
try:
 cfg.write_text(str(p)+' {\n size 1k\n rotate 3\n missingok\n notifempty\n create 0640 root root\n compress\n delaycompress\n}\n')
 for i in range(3):
  p.write_bytes(bytes([65+i])*131072);run(['/usr/sbin/logrotate','-f','-s',str(state),str(cfg)])
  archive=p.with_name(p.name+'.1');assert archive.is_file();run(['/bin/gzip','-1',str(archive)])
  assert p.exists()and p.stat().st_size==0 and archive.with_suffix('.1.gz').exists()
 result=dict(passed=True,three_real_rotations_with_manually_compressed_closed_archives=True,only_temp_files=True)
finally:shutil.rmtree(d);result['clean']=not d.exists();print(json.dumps(result))

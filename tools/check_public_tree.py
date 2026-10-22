"""Public-artifact checks. Reports paths/categories only, never matching values."""
import ast,json,pathlib,re,sys
root=pathlib.Path(__file__).resolve().parents[1]
roots=('core','experimental','tests','integration','tools','docs','evidence','.github')
files=[p for folder in roots for p in (root/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
files += [root/n for n in ('README.md','AGENTS.md','CHANGELOG.md','requirements-dev.txt','pyproject.toml','.gitignore','.gitattributes') if (root/n).exists()]
patterns={
 'github_token':re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{40,})'),
 'private_key_material':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{70,}'),
 'owner_password_shape':re.compile(r'(?<![A-Za-z0-9])\d{6}@[A-Za-z]{3,20}(?![A-Za-z0-9])'),
 'warp_license_shape':re.compile(r'(?<![A-Za-z0-9])[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}(?![A-Za-z0-9])'),
 'personal_windows_path':re.compile(r'[A-Za-z]:[\\/]Users[\\/]',re.I),
 'operational_private_LAN':re.compile(r'192\.168\.50\.(?:10|30)\b'),
}
issues=[]
for p in files:
 rel=p.relative_to(root).as_posix()
 if p.suffix.lower() in ('.pem','.key','.zip','.pdf','.exe') or '.private.' in p.name:issues.append((rel,'private_or_binary_file'));continue
 text=p.read_text(encoding='utf-8')
 for category,pattern in patterns.items():
  if pattern.search(text):issues.append((rel,category))
 if p.suffix=='.py':ast.parse(text,filename=rel)
 if p.suffix=='.json':json.loads(text)
 if p.suffix=='.md':
  for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)',text):
   if target.startswith(('https://','http://','#')):continue
   if not (p.parent/target.split('#',1)[0]).exists():issues.append((rel,'missing_relative_link:'+target))
print(json.dumps({'files_checked':len(files),'issues':issues,'passed':not issues},ensure_ascii=False))
raise SystemExit(1 if issues else 0)

"""Portable tests only. No SSH, host configuration, WAN or production access."""
import pathlib,sys,unittest
root=pathlib.Path(__file__).resolve().parents[1]
for folder in ('core','experimental'):sys.path.insert(0,str(root/folder))
suite=unittest.defaultTestLoader.discover(str(root/'tests'),pattern='test_*.py')
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)

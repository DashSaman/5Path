"""Exact amendment of our release admission, retaining live firewall's old commit identity."""
import hashlib,json
OLD="if commit.get('run_id')!=cfg['run_id']or commit.get('config_sha256')!=sha:raise ValueError('RELEASE_COMMIT_IDENTITY')"
NEW="""if commit.get('run_id')!=cfg['run_id']:raise ValueError('RELEASE_COMMIT_IDENTITY')
 revision=commit.get('capacity_revision')or{}
 valid_revision=(revision.get('run_id')==cfg['run_id']and revision.get('previous_config_sha256')==commit.get('config_sha256')and revision.get('current_config_sha256')==sha)
 if commit.get('config_sha256')!=sha and not valid_revision:raise ValueError('RELEASE_COMMIT_IDENTITY')"""
def revised_source(data):
 text=data.decode();assert text.count(OLD)==1,'EXACT_ADMISSION_VERSION_REQUIRED';text=text.replace(OLD,NEW);compile(text,'country_release_runtime.py','exec');return text.encode()

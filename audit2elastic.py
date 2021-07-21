#!/usr/bin/env python3

from argparse import ArgumentParser, REMAINDER
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk, parallel_bulk
from dateutil.tz import gettz

import sys, os, csv, json, re, dateutil.parser, pprint

parser = ArgumentParser(prog='audit2elastic', description='Push Office 365 audit logs to ElasticSearch')

parser.add_argument('--server', '-s', dest='elastic_server', action='store', default=os.environ.get('ES_HOSTS', 'http://10.80.121.231:9200'), help='ElasticSearch server(s)')
parser.add_argument('--index',  '-i', dest='elastic_index',  action='store', default='o365-%s' % hex(abs(hash(json.dumps(sys.argv[1:]))))[2:10], help='ElasticSearch index name')
parser.add_argument("paths", nargs=REMAINDER, help='Target audit log file(s)', metavar='paths')

args, extra = parser.parse_known_args(sys.argv[1:])

es = Elasticsearch(args.elastic_server, index=args.elastic_index)
tzinfos = {"AEST" : gettz("Australia/Brisbane")}

print(f"Using server: {args.elastic_server}")
print(f"Using index: {args.elastic_index}")

def convert_key(string):
	s1 = re.sub('([^\.])([A-Z][a-z]+)', r'\1_\2', string.replace(' ', '_'))
	s2 = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
	s3 = re.sub('_+', r'_', s2.replace('.', '_'))
	return s3.replace('extended_properties', '').replace('target_updated_properties', 'target_updated') \
		.replace('parameters', '').replace('additional_details', '')

def normalise_user(string):
	return re.sub(r'(.*\\)?([^@ ]+)([@ ].*)?', r'\2', string.lower())

def parse_date(string, fuzzy=True):
	return dateutil.parser.parse(string)

def parse_audit_data(string, prefix=None):
	if not type(string) in (bytes, str): return string
	if not str(string).startswith(('"', "'", "{", "[")): return string
	try:
		audit_data = json.loads(string, object_pairs_hook=object_pairs_hook(prefix))
		if type(audit_data) is dict: flattened = flatten_audit_data(audit_data)
		else: flattened = audit_data
		return flattened
	except json.JSONDecodeError as ex:
		return string

def object_pairs_hook(prefix=None):
	def wrapper(pairs):
		obj = {convert_key((prefix + '_' + key) if prefix else key): value for key, value in pairs}
		if set(obj.keys()) == {'name', 'value'}:
			value = parse_audit_data(obj['value'], )
			return {convert_key(obj['name']): value}
		elif set(obj.keys()) == {'name', 'new_value', 'old_value'}:
			value = parse_audit_data(obj['new_value'], prefix)
			return {convert_key(obj['name']): value}
		if set(obj.keys()) == {'id', 'type'}:
			return obj
		return obj
	return wrapper

def flatten(item, key=None):
	flattened = {}
	if isinstance(item, dict): flattened.update(flatten_dict(item, prefix=key))
	elif isinstance(item, list): flattened.update(flatten_list(item, prefix=key))
	else: flattened[key] = item
	return flattened

def flatten_dict(data, prefix=None):
	flattened = {}
	for key, value in data.items():
		flattened.update(flatten(value, (prefix + '_' + key) if prefix else key))
	return flattened

def flatten_list(items, prefix=None):
	flattened = {}
	flattened_items = {}
	for item in items:
		flattened_item = flatten(item, prefix)
		for key, value in flattened_item.items():
			flattened_items.update({key: [value]}) if key not in flattened_items.keys() else flattened_items[key].append(value)
	flattened.update(flattened_items)
	return flattened

def flatten_audit_data(audit_data, prefix=''):
	if type(audit_data) is dict:
		return flatten(audit_data)
	return audit_data

def process_records(path):
	with open(path) as audit_file:
		lines = len(audit_file.readlines()) - 1
		audit_file.seek(0)
		audit_csv = csv.reader(audit_file)
		header = next(audit_csv)
		keys = [convert_key(key) for key in header]
		for i, values in enumerate(audit_csv, 1):
			record = {key: parse_audit_data(value) for key, value in zip(keys, values)}
			if 'audit_data' in record.keys():
				record.update(record['audit_data'])
				del record['audit_data']
			record['username'] = None
			for key, value in record.copy().items():
				if value in (None, 'null', '<null>', [], ['<null>'], [''], '', [['']], {}) and key != 'username':
					del record[key]
				elif value and key in ('sender_ip', 'client_ip_address', 'client_ip', 'actor_ip_address', 'from_ip') and 'ip_address' not in record.keys():
					record['ip_address'] = re.sub(r'\[?((([1-9]+[0-9]*\.){3,}[1-9]+[0-9]*)|((([1-9a-f]+[0-9a-f]*)?:){1,8}[0-9a-f]*[1-9a-f]+))\]?.*', r'\1', value)
				elif key in ('creation_time', 'end_date') and 'timestamp' not in record.keys():
					record['timestamp'] = parse_date(value)
					# del record[key]
				elif key in ('creation_date', 'run_date', 'last_accessed') and 'timestamp' not in record.keys():
					timeentry=value+" AEST"
					record['timestamp'] = dateutil.parser.parse(timeentry, dayfirst=True, fuzzy=True, tzinfos=tzinfos)
				elif key in ('username', 'mailbox_owner_upn') and value is not None:
					record['username'] = normalise_user(value)
				elif key in ('item_is_record', 'user_type', 'internal_logon_type', 'azure_active_directory_event_type', 'cross_mailbox_operation', 'logon_type', 'external_access'):
					record[key] = str(value)
				elif key in ('', None, 'null'):
					record['extended_properties'] = value
					del record[key]
			if i % 1000 == 0 or i == lines: print(f"Processed {i}/{lines} records")
			# pprint.pprint(record)
			yield record



for path in args.paths:
	if not os.path.exists(path):
		raise FileNotFoundError(f"Audit log file {path} not found")
	print(f"Processing {path}...")
	for ok, info in parallel_bulk(es, ({"_index": args.elastic_index, "_id": hex(abs(hash(json.dumps(record, sort_keys=True, default=str)))), "_type": "_doc", "_source": record} for record in process_records(path))):
		if not ok: print(f"Error {info}")


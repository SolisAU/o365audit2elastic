# o365audit2elastic
Python script to push the Office 365 Unified Audit Log, Admin Audit Log and Mailbox Audit Logs into ElasticSearch. Works with the o365auditlogretriever scripts.

Run under WSL or with Python3 in Windows
`./audit2elastic.py --index nameofcompany-ual /path/to/source/auditlog.csv`

The log will be ingested with pre-pending o365-<nameofcompany>-ual into the Elastic search

`o365-` is there so that it goes into the correct enrichment pipeline.

`-ual` at the end is there so we can filter based on index and source (ual, mt)

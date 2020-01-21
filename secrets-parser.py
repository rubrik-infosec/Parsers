#!/usr/bin/python 
import json
import sys
import requests

secrets = {} # This will contain all the parsed data

def parse_git_secrets(filename):
	# Parse Git-Secrets
	f = open(filename,"r")
	parsed = ''
	for i in f.readlines():
		if "ERROR" in i:
			break
		else:
			parsed += str(i)

	secretList = parsed.split("\n")
	for secret in secretList:
		data =  secret.split(":") #['test.py', '4', 'aws_access = "AKIAZ2NIUIV5UD5OVOCO"']
		if len(data) >2:
			if secrets.has_key(data[0]) :
				secrets[data[0]].append({data[1]: data[2]})
			else:
				secrets[data[0]] = [] 
				secrets[data[0]].append({data[1]: data[2]})

def parse_detect_secrets(filename):
	# Parse Detect-Secrets
	f = open(filename,"r")
	data = json.loads(f.read()) # Now data contains results and all keys represent files
	files = data.keys() 
	for file in files:
		secretList =  data[file]
		for secret in secretList:
			lineNumber = secret['line_number']
			secretType = secret['type']
			if secrets.has_key(file):
				secrets[file].append({lineNumber: secretType})
			else:
				secrets[file] = []
				secrets[file].append({lineNumber: secretType})

def parse_dict(secrets):
	parsedSecret = '' # This will contain the parsed Dict data
	keys = secrets.keys()
	for file in keys:
		parsedSecret += 'File: ' + file  +  "\n"
		for vulns in secrets[file]:
			parsedSecret += 'LineNumber: ' + str(vulns.keys()[0]) + ' : ' + vulns[vulns.keys()[0]] + '\n'
		parsedSecret += '\n' 
	return parsedSecret

def send_to_slack(result): # Send to slack
	webhook_url = sys.argv[3]
	data = {'text':'Secrets Detected in Code', 'blocks': [ { 'type':'section', 'text': { 'type':'mrkdwn', 'text': result}}, {'type':'section', 'text': {'type':'mrkdwn','text':'#TODO: Commit URL' }}] , 'username': 'ci-infosec-alerts', 'icon_emoji':'key'}
	requests.post(webhook_url, json=data)				
		

	


if len(sys.argv) != 4:
	print '[-] Usage: python ' + sys.argv[0] + ' <Git-secrets-file> <Detect-secrets-file> <Slack_web_token>'
	sys.exit(1)
parse_git_secrets("git-secrets")
parse_detect_secrets("detect-secrets")
parsedSecret =  parse_dict(secrets)
send_to_slack(parsedSecret)

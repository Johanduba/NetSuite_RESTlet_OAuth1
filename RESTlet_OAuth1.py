import json
import time #To generate the OAuth timestamp
import urllib.parse #To URLencode the parameter string
import hmac #To implement HMAC algorithm
import hashlib #To generate SHA256 digest
from base64 import b64encode #To encode binary data into Base64
import binascii #To convert data into ASCII
import requests #To make HTTP requests
import random
from contextlib import redirect_stdout

linesread = 0
offset_string = ''
offset = 0  
deploy = 1
#Script Number from NetSuite RESTlet
script = 1234
NSOrderNum = []

oauth_signature_method = "HMAC-SHA256"
oauth_version = "1.0"

#Update with NetSuite Account and OAuth1.0 tokens
account = "123456"
oauth_consumer_key = "123"
consumer_secret = "456"
access_token = "789"
token_secret = "123"

def create_parameter_string(oauth_consumer_key,oauth_nonce,oauth_signature_method,oauth_timestamp,oauth_version,access_token,deploy,script):
    deploy_string = str(deploy)
    script_string = str(script)
    print('create parameter deploy'+ deploy_string + ' script ' + script_string)
    parameter_string = ''
    parameter_string = parameter_string + 'deploy=' + deploy_string
    parameter_string = parameter_string + '&oauth_consumer_key=' + oauth_consumer_key
    parameter_string = parameter_string + '&oauth_nonce=' + oauth_nonce
    parameter_string = parameter_string + '&oauth_signature_method=' + oauth_signature_method
    parameter_string = parameter_string + '&oauth_timestamp=' + oauth_timestamp
    parameter_string = parameter_string + '&oauth_token=' + access_token
    parameter_string = parameter_string + '&oauth_version=' + oauth_version
    parameter_string = parameter_string + '&script=' + script_string
    return parameter_string

def create_signature(secret_key, signature_base_string):
    encoded_string = signature_base_string.encode()
    encoded_key = secret_key.encode()
    temp = hmac.new(encoded_key, encoded_string, hashlib.sha256).hexdigest()
    byte_array = b64encode(binascii.unhexlify(temp))
    return byte_array.decode()

def call_Restlet(body):
    print(body)
    body3 = str(body)
    body2 = body3.replace("'", '"')
    deploy_string = '1'
    method = 'POST'
    #Hard Coded this orginally for simplicity
    url1 = 'https://' + account + '.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=' + script + '&deploy=1'
    url = 'https://' + account + '.restlets.api.netsuite.com/app/site/hosting/restlet.nl'
    
    oauth_timestamp = str(int(time.time()))
    oauth_nonce = ''.join(random.choices("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k=11))
    parameter_string = create_parameter_string(oauth_consumer_key,oauth_nonce,oauth_signature_method,oauth_timestamp,oauth_version,access_token,deploy,script)
    encoded_parameter_string = urllib.parse.quote(parameter_string, safe='')
    print(' parameter_string ' + parameter_string)

    encoded_base_string = method + '&' + urllib.parse.quote(url, safe='') 
    encoded_base_string = encoded_base_string + '&' + encoded_parameter_string
    signing_key = consumer_secret + '&' + token_secret
    print('signing key ' + signing_key)

    oauth_signature = create_signature(signing_key, encoded_base_string)
    encoded_oauth_signature = urllib.parse.quote(oauth_signature, safe='')
    print(' Encoded Signature ' + encoded_oauth_signature)
    
    headers = {
        'Content-Type': 'application/json',
        'prefer':'transient',
        'Authorization': 'OAuth realm="{0}",oauth_consumer_key="{1}",oauth_token="{2}",oauth_signature_method="{3}",oauth_timestamp="{4}",oauth_nonce="{5}",oauth_version="{6}",oauth_signature="{7}" '.format(
                account,oauth_consumer_key,access_token,oauth_signature_method, oauth_timestamp ,oauth_nonce,oauth_version ,encoded_oauth_signature)
    }
    print(headers)

    response = requests.post(url1, data=body2, headers=headers)
    jsonCreate_text = response.text
    print('jsonCreate')
    print(jsonCreate_text) 

def openData():
    #Update yourname and filename with correct values orginally run on a mac, ['Data'] was parent of JSON array
    with open('/Users/yourname/Developer/Python/filename.txt', newline='') as f:
        data = json.load(f)
        for i in data['Data']:
            print(i)
            NSrecord_count = call_Restlet(i)

openFile1 = openData()
response = ' '
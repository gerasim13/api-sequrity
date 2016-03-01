from flask import Flask
from flask import current_app, request, abort

import hashlib
import json

class ApiSequrity(object):
    def __init__(self, secret):
        super(ApiSequrity, self).__init__()
        self.secret = secret

    def gen_key(self, uid: str):
        combined = self.secret + uid[:8]
        hash_str = hashlib.md5(combined.encode('utf-8')).hexdigest()
        return hash_str

    def check_key(self, uid: str, key: str):
        return self.gen_key(uid) == key

    def parse_header(self,request):
        uid,key = request.headers.get('Credentials', '').split('/')
        return uid,key

    def check_request_args(self, request):
        debug   = 'debug' in request.args
        canpass = current_app.config.get('DEBUG', False)
        key     = request.args.get('key')
        uid     = request.args.get('uid')
        with current_app.app_context():
            if uid is None and key is None:
                uid, key = self.parse_header(request)
            if not canpass or 'pass' not in request.args:
                if uid is None and key is None:
                    abort(400)
                if not self.check_key(uid, key):
                    abort(401, json.dumps({'message': uid + ' ' + key})) if debug else abort(401)
        return key, uid, debug

from flask import Flask
from flask import current_app, request

import hashlib

class ApiSequrity(secret):
    def __init__(self, secret):
        super(ApiSequrity, self).__init__()
        self.secret = secret

    def gen_key(uid: str):
        combined = self.secret + uid[:8]
        hash_str = hashlib.md5(combined.encode('utf-8')).hexdigest()
        return hash_str

    def check_key(uid: str, key: str):
        return gen_key(uid) == key

    def check_request_args(request):
        with current_app.app_context():
            if 'key' not in request.args or 'uid' not in request.args:
                abort(400)
            pass_check = 'pass' in request.args
            debug      = 'debug' in request.args
            key        = request.args.get('key')
            uid        = request.args.get('uid')
            if not pass_check and not check_key(uid, key):
                abort(401, "{'message': genkey + " "  + key}") if debug else abort(401)
            return key, debug, uid

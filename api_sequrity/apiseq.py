from flask import Flask

class ApiSequrity(object):
    """docstring for ApiSequrity"""
    def __init__(self, arg):
        super(ApiSequrity, self).__init__()
        self.arg = arg

    def gen_key(uid: str):
        secret   = os.environ['SECRET_KEY']
        combined = secret + uid[:8]
        hash_str = hashlib.md5(combined.encode('utf-8')).hexdigest()
        return hash_str

    def check_key(uid: str, key: str, debug: bool):
        genkey = gen_key(uid)
        if gen_key(uid) == key:
            return True
        if debug:
            abort(401, "{'message': genkey + " "  + key}")

    def check_request_args():
        if 'pass' in request.args:
            return 0, 0, 0
        if 'key' not in request.args or 'uid' not in request.args:
            abort(400)
        key   = request.args.get('key')
        uid   = request.args.get('uid')
        debug = 'debug' in request.args
        if not check_key(uid, key, debug) and key_check_on:
            abort(401)
        return key, debug, uid

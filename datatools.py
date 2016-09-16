import hashlib
import hmac
import random
import string
import re

# Encryption Key Word
SECRET = "HELLOWORLD"

# Encryption Related Functions
class Encryption():
    def hash_str(self, s):
        return hmac.new(SECRET,s).hexdigest()

    def make_secure_val(self, s):
        return "%s|%s" % (s, self.hash_str(s))

    def check_secure_val(self, h):
        val = h.split('|')[0]
        if h == self.make_secure_val(val):
            return val

    def make_salt(self):
        return ''.join(random.choice(string.letters) for i in range(5))

    def make_pw_hash(self, name, pw, salt = None):
        if not salt:
            salt = self.make_salt()
        return "%s,%s" % (hashlib.sha256(name+pw+salt).hexdigest(), salt)

    def valid_pw(self, name, pw, h):
        value = h.split(',')
        return h == self.make_pw_hash(name, pw, value[1])

# User Input Parsing and Verification
class InputVerification():
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    def valid_username(self, username):
        return self.USER_RE.match(username)

    def valid_password(self, password):
        return self.PASS_RE.match(password)

    def valid_email(self, email):
        return self.EMAIL_RE.match(email)
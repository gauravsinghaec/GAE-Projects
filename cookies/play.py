# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2
#jinja is Template programming language
import jinja2
# os allows us to get the path of our working directory
import os
# Used for hashing in coockes
# import hashlib
import hmac


template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)

SECRET="imsosecret"

def hash_str(s):
    #Old cookie hashing technique
    # return hashlib.sha256(s).hexdigest()

    #new Cookie hasing with secret key and HMAC
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

# -----------------
# User Instructions
# 
# Implement the function check_secure_val, which takes a string of the format 
# s,HASH
# and returns s if hash_str(s) == HASH, otherwise None 

def check_secure_val(h):
    s = h.split('|')[0]
    if h == make_secure_val(s):
        return s
    else:
        return None

class BaseHandler(webapp2.RequestHandler):
    def write(self,*argv,**kwargs):
        self.response.write(*argv,**kwargs)

    def render_str(self,template,**kw):
        t = jinja_env.get_template(template)
    	return t.render(kw)

    def render(self,template,**kwargs):
        self.write(self.render_str(template,**kwargs))

class MainHandler(BaseHandler):
    def get(self):
        self.response.headers['Content-Type']= 'text/plain'
        visits = 0
        visits_cookie_str = self.request.cookies.get('visits')
        if visits_cookie_str:
            check_val = check_secure_val(visits_cookie_str)
            if check_val:
                visits = int(check_val)

        visits += 1
        new_cookie_val = make_secure_val(str(visits))    

        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)

        if visits > 10000:
            self.write('You are the best ever!')    
        else:    
            self.write("You've been here %s times" % visits)

app = webapp2.WSGIApplication([('/', MainHandler)], debug=True)

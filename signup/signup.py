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

import jinja2
# os allows us to get the path of our working directory
import os

from google.appengine.ext import db

import re

import hmac

import random
import string
import hashlib


template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)


STRING_RE = re.compile(r"^[a-zA-Z ]{3,150}$")
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

SECRET="imsosecret"
ALPHABETS = "abcdefghijklmnopqrstuvwxyz"

# *****************************************************************
# Implementing Cookie using HMAC 
# *****************************************************************
def hash_str(s):
    #Old cookie hashing technique
    # return hashlib.sha256(s).hexdigest()

    #new Cookie hasing with secret key and HMAC
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))
# Implement the function check_secure_val, which takes a string of the format 
# s,HASH
# and returns s if hash_str(s) == HASH, otherwise None 

def check_secure_val(h):
    s = h.split('|')[0]
    if h == make_secure_val(s):
        return s
    else:
        return None

# *****************************************************************
# Implementing Cookie using salt to mitigate rainbow table issue 
# in other hmac,md5 or sha256 hashing
# *****************************************************************
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

# Implement the function valid_pw() that returns True if a user's password 
# matches its hash. You will need to modify make_pw_hash.

def make_pw_hash(name, pw,salt=None):
    if not salt:
        salt = make_salt()        
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    ###Your code here
    salt = h.split('|')[1]
    H = make_pw_hash(name, pw,salt)
    return (h == H)

#***********************************************************
# Below code fetches parent key object from Cloud Datastore
#***********************************************************
def get_parent_key(name = 'root'):
	return db.Key.from_path('users',name)


#***********************************************************
# Below code fetches entity key object from Cloud Datastore
#***********************************************************
def get_user_key(group = 'root'):
	return db.Key.from_path('blogs',name)


#***********************************************************
# Below is encoding function for ROT13
#***********************************************************
def encodeText(s):
	inputText =""
	for c in s:
		if c.lower() in ALPHABETS:
			pos=ALPHABETS.find(c.lower())
			if pos<13: 
				indx=pos+13
			else:
				indx=pos+13-26
			if c==ALPHABETS[pos].upper():
				inputText+=ALPHABETS[indx].upper()
			else:	
				inputText+=ALPHABETS[indx]	
		else:
			inputText+=c	
	return inputText

def valid_string(name):
    return STRING_RE.match(name)

def valid_username(username):
    return username and USER_RE.match(username)

def valid_password(password):
    return password and PASSWORD_RE.match(password)

def verify_password(password,verify_password):
    return password == verify_password 

def valid_email(email):
    return not email or EMAIL_RE.match(email) 

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def write(self,*argv,**kwargs):
        self.response.write(*argv,**kwargs)

    def render_str(self,template,**kw):
        return render_str(template, **kw)

    def render(self,template,**kwargs):
        self.write(self.render_str(template,**kwargs))

#***********************************************************
# Below is code for setting Cookie in browser
#***********************************************************
    def set_secure_cookie(self,name,val):
		new_cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %(name,new_cookie_val))

#***********************************************************
# Below is code for getting Cookie in browser
#***********************************************************
    def get_secure_cookie(self,name):
		cookie_recieved = self.request.cookies.get(name)
		return cookie_recieved

    def login(self,user_id):
    	self.set_secure_cookie('user_id',user_id)

    def logout(self):    	    
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class UserData(db.Model):
	user_name 	= db.StringProperty(required=True) 
	pw_hash   	= db.StringProperty(required=True) 
	email 		= db.StringProperty() 

	@classmethod
	def by_id(cls,user_id):
		user = UserData.get_by_id(user_id,parent=get_parent_key())
		return user

	@classmethod	
	def by_name(cls,name):
		q = UserData.all()
		user =q.filter('user_name =', name)
		return user.get()

	@classmethod	
	def register(cls,name,pw,email=None):
		hash_pw = make_pw_hash(name,pw)            
		user = UserData(parent=get_parent_key(),user_name=name,pw_hash=hash_pw,email=email)
		return user
			
class SignupHandler(BaseHandler):
    def render_signup(self,**params):
        self.render('signup.html',**params)
	
	def done(self,*a,**kw):
		raise NotImplementedError

    def get(self):
        self.render('signup.html')

    def post(self):
        self.input_username = self.request.get('username')
        self.input_email = self.request.get('email')
        self.input_pw    = self.request.get('password')
        self.input_vpw   = self.request.get('verify')

        params = dict(uname=self.input_username,email=self.input_email)
        have_error = False

        username    = valid_username(self.input_username) 
        password    = valid_password(self.input_pw) 
        verify      = verify_password(self.input_pw,self.input_vpw) 
        email 		= valid_email(self.input_email)

        unameerror  = ""
        pwerror     = ""
        vpwerror    = ""
        emailerror  = ""

        if not username:
            params['unameerror']  = "That's not a valid username."
            have_error = True
        if not password:        
            params['pwerror']     = "That's not a valid password."
            have_error = True
        elif not verify:        
            params['vpwerror']    = "Your passwords didn't match."
            have_error = True
        if not email:
            params['emailerror']  = "That's not a valid email."
            have_error = True  

        if have_error:
        	self.render_signup(**params)
        else:
        	self.done()	                    	
            
class Unit2Signup(SignupHandler):
    def done(self):    	
        self.redirect('/unit2/welcome?username='+self.input_username)

class Unit2Welcome(SignupHandler):
    def get(self):    	
    	username = self.request.get('username')
        self.render('welcome.html',name=username)

class RegisterHandler(SignupHandler):
    def done(self):    	
        user = UserData.by_name(self.input_username)
        if user:
        	usernameerror  = "That user already exists"
        	self.render('signup.html',unameerror = usernameerror)
        else:	
        	userData = UserData.register(self.input_username,self.input_pw,self.input_email)
        	userData.put()
        	user_id = userData.key().id()
        	self.set_secure_cookie('user_id',str(user_id))
        	self.redirect('/unit3/welcome')        

class Unit3Welcome(BaseHandler):
    def get(self):    	
        cookie_val = self.get_secure_cookie('user_id')
        load_weclcome = True
    	if cookie_val:
    	    check_val = check_secure_val(cookie_val)
            if not check_val:
            	load_weclcome = False                    
        else:
        	load_weclcome = False    	
    	if load_weclcome:			
	    	user_id = int(cookie_val.split('|')[0])
	    	user = UserData.by_id(user_id) 
	        self.render('welcome.html',name=user.user_name)
    	else:
	        self.redirect('/signup')

class LoginHandler(BaseHandler):
    def get(self):
        self.render('login.html')           
    def post(self):
    	user_name = self.request.get('username')
    	password = self.request.get('password')
    	valid_user = False
    	user = UserData.by_name(user_name)
        if user:
        	if valid_pw(user_name,password,user.pw_hash):
        		valid_user = True

        if valid_user:		
        	user_id = user.key().id()
        	self.set_secure_cookie('user_id',str(user_id))
        	self.redirect('/unit3/welcome')
        else:	
        	error  = "Invalid login"
        	self.render('login.html',error = error,uname=user_name)    	        	

class LogoutHandler(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')
   
class MainHandler(BaseHandler):
    def get(self):
        self.render('front.html')

class ROT13Handler(BaseHandler):
    def render_form(self,error="",encodedtext=""):
    	self.render('rot13.html',error=error,textdata=encodedtext)

    def get(self):
        self.render('rot13.html')

    def post(self):
    	user_text 	=self.request.get('text')
    	encodedtext = encodeText(user_text)
        if not user_text:        
        	self.render_form('Error: you have not entered any data it seems')
        else:	
        	self.render_form('Text Encoded, Please Verify:',encodedtext)

app = webapp2.WSGIApplication([ ('/', MainHandler),
								('/unit2/rot13', ROT13Handler),
								('/unit2/signup',Unit2Signup),
								('/unit2/welcome',Unit2Welcome),
								('/signup', RegisterHandler),
								('/login', LoginHandler),
								('/logout', LogoutHandler),
								('/unit3/welcome',Unit3Welcome)], debug=True)

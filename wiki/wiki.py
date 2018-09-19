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

import re

from google.appengine.ext import db
from google.appengine.api import memcache

import hmac

import random
import string
import hashlib

import json,urllib2
import logging
import time

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)

SECRET="imsosecret"


# *****************************************************************
# Implementing Cookie using HMAC 
# *****************************************************************
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# *****************************************************************
# Implementing Cookie using salt to mitigate rainbow table issue 
# in other hmac,md5 or sha256 hashing
# *****************************************************************
def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


#***********************************************************
# Below code fetches parent key object from Cloud Datastore
#***********************************************************
def get_parent_key(name = 'root'):
    return db.Key.from_path('users',name)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASSWORD_RE.match(password)

def verify_password(password,verify_password):
    return password == verify_password 

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
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
        return cookie_recieved and check_secure_val(cookie_recieved)

    def login(self,user_id):
        self.set_secure_cookie('user_id',user_id)

    def logout(self):           
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

#***********************************************************
# webapp2.RequestHandler.initialize gets called for every GET
# Request and self.user will have the user object handy
#***********************************************************
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.get_secure_cookie('user_id')
        self.user = uid and UserData.by_id(int(uid))

class UserData(db.Model):
    user_name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_updated = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls,user_id):
        user = UserData.get_by_id(user_id,parent=get_parent_key())
        return user

    @classmethod    
    def by_name(cls,name):
        q = UserData.all()
        user =q.filter('user_name =', name).get()
        return user

    @classmethod    
    def register(cls,name,pw,email=None):
        hash_pw = make_pw_hash(name,pw)            
        user = UserData(parent=get_parent_key(),user_name=name,pw_hash=hash_pw,email=email)
        return user

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class SignupHandler(BaseHandler):            
    def get(self):
        self.render('signup.html',user=self.user)

    def post(self):
        input_username = self.request.get('username')
        input_email = self.request.get('email')
        input_pw    = self.request.get('password')
        input_vpw   = self.request.get('verify')

        params = dict(uname=input_username,email=input_email)
        have_error = False

        username    = valid_username(input_username) 
        password    = valid_password(input_pw) 
        verify      = verify_password(input_pw,input_vpw) 
        email       = valid_email(input_email)

        unameerror  = None
        pwerror     = None
        vpwerror    = None
        emailerror  = None

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
            self.render('signup.html',**params)
        else:
            user = UserData.by_name(input_username)
            if user:
                usernameerror  = "That user already exists"
                self.render('signup.html',unameerror = usernameerror)
            else:   
                userData = UserData.register(input_username,input_pw,input_email)
                userData.put()
                
                user_id = userData.key().id()
                self.login(str(user_id))
                self.redirect('/welcome')                               
            
def wiki_key(name = 'RootWiki'):
    return db.Key.from_path('wikis', name)

loginTime = 0
PageTime = 0
PAGE_RE = re.compile(r"^[a-zA-Z]{3,20}$")
class Wiki(db.Model):
    page_name = db.StringProperty(required=True)
    content = db.TextProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)
    last_updated = db.DateTimeProperty(auto_now=True)

    @classmethod    
    def by_pagename(cls,name):
        q = Wiki.all().filter('page_name =', name)
        #page = q.order('-created').fetch(limit=1).get()
        page = q.order('-created').get()
        return page

    def render(self):
        return render_str('viewpage.html',blogposts=self)


class WikiPage(BaseHandler):
    def render_wiki(self,**kw):
        self.render('viewpage.html',**kw)

    def get(self,pagename=""):
        logging.error("View "+pagename)
        pagename = pagename
        CURRENT_TIME =time.time()
        global PageTime        
        PageTime = CURRENT_TIME

        page = Wiki.by_pagename(pagename)
        trackRefresh = CURRENT_TIME  - PageTime
        if self.user:            
            if page:            
                self.render_wiki(user = self.user,content=page.content,trackRefresh=round(trackRefresh,2),pagename=pagename)
            else:    
                self.redirect('/wiki/_edit/%s' % pagename)
        else:        
            self.redirect('/wiki/login')            


class EditPage(BaseHandler):
    def render_newpost(self,**kw):
        self.render('editpage.html',**kw)

    def get(self,pagename=''):
        pagename_param = pagename
        if pagename_param is None:
            logging.error("Edit Existing Page")        
            pagename_param =''
            pagename='wikifront'
        else:    
            logging.error("Edit Page "+pagename)        

        page = Wiki.by_pagename(pagename)
        if page:
            content = page.content
        else:
            content = ''
        self.render_newpost(user = self.user,content=content,editModeOn=True,pagename=pagename_param)           

    def post(self,pagename=''):
        content = self.request.get('content')  
        if pagename:
            logging.error("Posting Edited Page") 
            page = Wiki.by_pagename(pagename)
            if not page:       
                page = Wiki(parent = wiki_key(),page_name = pagename,content=content)
            else:
                page.content = content    

            page.put()
            self.redirect('/wiki/%s' % pagename)
        else:    
            pagename='wikifront'
            page = Wiki.by_pagename(pagename)
            if not page:       
                page = Wiki(parent = wiki_key(),page_name = pagename,content=content)
            else:
                page.content = content    

            page.put()
            self.redirect('/wiki')    

class WikiFront(BaseHandler):
    def render_front(self,**kw):
        self.render('viewpage.html',**kw)
    
    def get(self):
        pagename = 'wikifront'
        page = Wiki.by_pagename(pagename)
        if page:
            content = page.content
        else:
            content = ''
        self.render_front(user = self.user,content=content)


class LoginHandler(BaseHandler):
    def render_login(self,**kw):
        self.render('login.html',**kw)

    def get(self):
        if self.user:
            self.redirect('/wiki')    
        else:
            self.render_login(user=self.user)           
                   
    def post(self):
        user_name = self.request.get('username')
        password = self.request.get('password')
        valid_user = False
        user = UserData.by_name(user_name)
        if user and valid_pw(user_name,password,user.pw_hash):
                valid_user = True
        if valid_user:      
            user_id = user.key().id()
            self.login(str(user_id))
            self.redirect('/wiki')
        else:   
            error  = "Invalid login"
            self.render_login(error = error,uname=user_name)                 

class LogoutHandler(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/wiki/signup')                 

class FlushCache(BaseHandler):
    def get(self):
        CACHE.clear()
        self.redirect('/wiki')           

class WelcomeHandler(BaseHandler):
    def get(self):
        if self.user:
            self.render('welcome.html',name=self.user.user_name,user=self.user)            
        else:
            self.redirect('/wiki/signup')

class LandingPage(BaseHandler):
    def get(self):
        self.render('welcome.html',user=self.user)                            
                        
app = webapp2.WSGIApplication([
            ('/', LandingPage),
            ('/wiki/?', WikiFront),
            ('/wiki/_edit/?(\w+)?', EditPage), 
            ('/wiki/signup/?', SignupHandler),
            ('/wiki/login/?', LoginHandler),
            ('/wiki/logout/?', LogoutHandler),
            ('/wiki/flush/?', FlushCache),            
            ('/wiki/(\w+)?', WikiPage),                        
            ('/welcome/?', WelcomeHandler),
            ], debug=True)

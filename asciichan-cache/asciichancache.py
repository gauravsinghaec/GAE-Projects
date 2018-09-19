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
#to use the Google App Engine Datastore
from google.appengine.ext import db

import logging

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)


class BaseHandler(webapp2.RequestHandler):
    def write(self,*argv,**kwargs):
        self.response.write(*argv,**kwargs)

    def render_str(self,template,**kw):
        t = jinja_env.get_template(template)
    	return t.render(kw)

    def render(self,template,**kwargs):
        self.write(self.render_str(template,**kwargs))

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)        

CACHE = {}
def top_arts(update = False):
    key = 'top'
    if not update and key in CACHE:
        arts = CACHE.get(key)
    else:
        logging.error("DB QUERY")
        arts = db.GqlQuery("select * "
                            " from Art" 
                            " order by created desc"
                            " limit 10"
                            )
        arts = list(arts)
        CACHE[key] = arts

    return arts

class MainHandler(BaseHandler):
    def render_front(self,error="",title="",art=""):
        arts = top_arts()
        self.render("front.html",arts=arts,error=error,title=title,art=art)

    def get(self):
        return self.render_front()

    def post(self):
        title = self.request.get('title')
        art = self.request.get('art')
        if title and art:
            a = Art(title=title,art=art)
            a.put()
            #clear the cache
            #CACHE.clear()

            #rerun the query and update the cache
            top_arts(True) 

            self.redirect("/")
        else:
            error = "We need both title and art!"
            self.render_front(error=error,title=title,art=art)        

class SubmitHandler(BaseHandler):
    def get(self):        
        self.render("thanks.html")

app = webapp2.WSGIApplication([('/', MainHandler),('/thanks', SubmitHandler)], debug=True)

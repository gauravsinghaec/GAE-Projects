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
import os

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

class MainHandler(BaseHandler):
    def get(self):
        items = self.request.get_all("food")
        self.render("shopping_list.html",items=items)

class FizzbuzzHandler(BaseHandler):
    def get(self):
        x = self.request.get("n")
        if x:
            x=int(x)
        self.render("fizzbuzz.html",n=x)

app = webapp2.WSGIApplication([('/', MainHandler),('/fizzbuzz', FizzbuzzHandler)], debug=True)

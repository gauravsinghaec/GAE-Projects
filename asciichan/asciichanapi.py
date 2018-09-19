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

import urllib2
from xml.dom import minidom

#to use the Google App Engine Datastore
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)

IP_URL= "http://freegeoip.net/xml/"

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"

API_KEY='&key=AIzaSyCjQaAX0RZDQN-iSePldDoWhmmE6HJobbY'

def gmaps_img(points):
    coord_param = '&'.join("markers=%s,%s" %(p.lat,p.lon) for p in points)
    key = API_KEY
    return GMAPS_URL + coord_param + API_KEY

def get_coord(ip):
    
    fullURL = IP_URL + ip
    try:
        content = urllib2.urlopen(fullURL).read()
    except URLError:
        return    

    if content:
        x = minidom.parseString(content)
        longiNode = x.getElementsByTagName("Longitude")            
        latiNode = x.getElementsByTagName("Latitude")
        if latiNode and longiNode and longiNode[0].childNodes[0].nodeValue and latiNode[0].childNodes[0].nodeValue:
            longi=str(longiNode[0].childNodes[0].nodeValue)
            lati=str(latiNode[0].childNodes[0].nodeValue)
            return db.GeoPt(lati,longi)                    
            #return lati,longi

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()
        
class BaseHandler(webapp2.RequestHandler):
    def write(self,*argv,**kwargs):
        self.response.write(*argv,**kwargs)

    def render_str(self,template,**kw):
        t = jinja_env.get_template(template)
    	return t.render(kw)

    def render(self,template,**kwargs):
        self.write(self.render_str(template,**kwargs))

class MainHandler(BaseHandler):
    def render_front(self,**kw):
        arts = db.GqlQuery("select * from Art order by created desc")
        kw['arts'] = arts
        #prevent running of multiple queries
        #store the quesry result in list
        arts = list(arts)

        #Gett all cordinates points
        point = []
        points = filter(None,(a.coords for a in arts))
        
        img_url = None
        #Creates Google Map URL
        if points:
            img_url = gmaps_img(points)

        kw['img_url'] = img_url    

        self.render("front.html",**kw)        

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get('title')
        art = self.request.get('art')
        error=""
        if title and art:
            a = Art(title=title,art=art)
            coords = get_coord(self.request.remote_addr)
            if coords:
                a.coords = coords
            a.put()

            art=""
            title=""
        else:
            error = "We need both title and art!"
        self.render_front(error=error,title=title,art=art)        

class SubmitHandler(BaseHandler):
    def get(self):        
        self.render("thanks.html")

app = webapp2.WSGIApplication([('/', MainHandler),('/thanks', SubmitHandler)], debug=True)

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

# <!DOCTYPE html>
# <html>
# <head>
# 	<title></title>
# </head>
# <body>
# <form action="https://www.google.com/search">
# 	<input type="text" name="q">
# 	<input type="submit" name="submit">
# </form>
# </body>
# </html>
form="""
<form method="post">
	<input type="text" name="q"><br>
	<input type="password" name="p"><br>	
	What is your DOB?
	<br>
	<label>	Month	
		<input type="text" name="month" value="%(m)s">
	</label>
	<label> Day
		<input type="text" name="day" value="%(d)s">
	</label>
	<label> Year
		<input type="text" name="year" value="%(y)s">
	</label>	
	<div style="color:red">%(error)s</div>
	<br>
	<br>	
	<input type="submit" name="submit">
</form>
"""
months = ['January','February','March','April','May','June','July','August','September','October','November','December']

def valid_month(month):
	mDict=dict([(m[:3].lower(),m) for m in months])
	if month:
		if mDict.has_key(month[:3].lower()) or month.capitalize() in mDict.values():
			return month.capitalize()
		return None
	return None	

def valid_day(day):
	if day and day.isdigit():
		day = int(day)
		if day in range(1,32):
			return day
		return None
	return None		

def valid_year(year):
	if year and year.isdigit():
		year = int(year)
		if year in range(1990,2021):
			return year
		return None
	return None	


class MainPage(webapp2.RequestHandler):
    def write_form(self,error="",month="",day="",year=""):
    	self.response.write(form % {'error':error,'m':month,'d':day,'y':year})

    def get(self):
        self.write_form()
    def post(self):
    	user_month 	=self.request.get('month')
    	user_day 	=self.request.get('day')
    	user_year 	=self.request.get('year')
        month	=	valid_month(user_month)
        day		= 	valid_day(user_day)
        year	=	valid_year(user_year)
        if not (month and day and year):        
        	self.write_form('Error: the date is not valid',user_month,user_day,user_year)
        else:	
	        #self.response.write('Thanks! Its a valid date')	Limitations so we will use Redirect in next line
	        self.redirect("/thanks")
class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write('Thanks! All datas are valid and you are registered with us now')
    def post(self):
        #reqQuery=self.request.get('q')
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write(self.request)

app = webapp2.WSGIApplication([('/', MainPage),('/thanks',ThanksHandler)], debug=True)

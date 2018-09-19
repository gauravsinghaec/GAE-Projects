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

form="""
<!DOCTYPE html>
<html>
<head>
	<title></title>
</head>
<body>
<h1> Enter some text to ROT13:</h1>
<form method="post">	
	<textarea name="text" rows="10" cols="48">%(textdata)s</textarea>
	<br>
	<div style="color:red">%(error)s</div>
	<input type="submit" name="submit">
</form>
</body>
</html>
"""
alphabets = "abcdefghijklmnopqrstuvwxyz"

import cgi
def escapeHTML(s):
	return cgi.escape(s,quote=True)

def encodeText(s):
	#s=escapeHTML(s)
	inputText =""
	for c in s:
		if c.lower() in alphabets:
			pos=alphabets.find(c.lower())
			if pos<13: 
				indx=pos+13
			else:
				indx=pos+13-26
			if c==alphabets[pos].upper():
				inputText+=alphabets[indx].upper()
			else:	
				inputText+=alphabets[indx]	
		else:
			inputText+=c	
	return inputText

class MainPage(webapp2.RequestHandler):
    def write_form(self,error="",encodedtext=""):
    	self.response.write(form % {'error':error,'textdata':encodedtext})

    def get(self):
        self.write_form()
    def post(self):
    	user_text 	=self.request.get('text')
    	encodedtext = encodeText(user_text)
        if user_text == '':        
        	self.write_form('Error: you have not entered any data it seems')
        else:	
        	self.write_form('Text Encoded, Please Verify:',encodedtext)

app = webapp2.WSGIApplication([('/', MainPage)], debug=True)

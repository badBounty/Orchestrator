import requests
import re
import math

regex_str = r"""
  		(?:"|')                               # Start newline delimiter
  		(
    		((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
    		[^"'/]{1,}\.                        # Match a domainname (any character + dot)
    		[a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    		|
    		((?:/|\.\./|\./)                    # Start with /,../,./
    		[^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
    		[^"'><,;|()]{1,})                   # Rest of the characters can't be
    		|
    		([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    		[a-zA-Z0-9_\-/]{1,}                 # Resource name
    		\.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
    		(?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
    		|
    		([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
    		[a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
    		(?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
    		|
    		([a-zA-Z0-9_\-]{1,}                 # filename
    		\.(?:php|asp|aspx|jsp|json|
    		     action|html|js|txt|xml)        # . + extension
    		(?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
  		)
  		(?:"|')                               # End newline delimiter
		"""

invalid_substrings = ['.png', '.jpg', '.mp4', '.mp3']


def get_js_in_url(url):
    regex = re.compile(regex_str, re.VERBOSE)
    try:
        response = requests.get(url, verify=False, timeout=3)
    except Exception:
        return []

    all_matches = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, response.text)]
    js_endpoints = list()
    # print(all_matches)
    for match in all_matches:
        if '.js' in list(match)[0] and 'http' in list(match)[0]:
            js_endpoints.append(list(match)[0])
        elif '.js' in list(match)[0]:
            split_url = url.split('/')
            final_url = split_url[0] + '//' + split_url[2]
            if list(match)[0][0] == '.':
                url_with_js_endpoint = final_url + list(match)[0][1:]
            elif list(match)[0][0] == '/' and not list(match)[0][:2] == '//':
                url_with_js_endpoint = final_url + list(match)[0]
            else:
                url_with_js_endpoint = final_url + '/' + list(match)[0]
            js_endpoints.append(url_with_js_endpoint)
    return js_endpoints

import base64
import requests
import time
from flask import Flask, render_template, request

app = Flask(__name__)

API_KEY = "00c144e46af49e046a2e0026bdbb89593a255bbd55e86a77e6c802624afab0f6"

def check_url_virustotal(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    headers = {"x-apikey": API_KEY}
    
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
            
        elif response.status_code == 404:
            scan_url = "https://www.virustotal.com/api/v3/urls"
            post_response = requests.post(scan_url, headers=headers, data={"url": url})
            
            if post_response.status_code == 200:
                time.sleep(4)
                retry_response = requests.get(api_url, headers=headers)
                if retry_response.status_code == 200:
                    return retry_response.json()
            
            return None
            
        else:
            return None
            
    except Exception as e:
        print(f"Exception API: {e}")
        return None

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    url = ""
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            result = check_url_virustotal(url)
    
    return render_template('index.html', result=result, url=url)

if __name__ == "__main__":
    app.run(debug=True)

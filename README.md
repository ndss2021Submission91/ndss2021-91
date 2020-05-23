#General
In this repository, you can find the toolchain that we want to make available alongside our paper "Reining in the Web's Inconsistencies with Site Policy".  
It hosts the code for SPEnforcer, SPCollector, SPAggregator and SPAnalyzer as described throughout section 6.
# Setup
You can install all dependencies in via:  
```
pip3 install -r requirements.txt
```

# SPEnforcer
In order to test SPEnforcer, you can load the Chrome Extension into your Chrome and interact with the popup.  
SPEnforcer has a default policy loaded for the site sptest.com which can be used alongside the Django TestApp.  
To setup this TestApp you need to add an entry to your ```/etc/hosts``` file such that sptest.com points to ```127.0.0.1```.  
After setting up this local DNS entry you can start the Django in ```TestApp/``` via:  
```python3 manage.py runserver```  
Then you can visit ```http://sptest.com:8000/foo``` and ```http://sptest.com:8000/bar``` respectively.  
You should be able to see that there is already a policy loaded for testing purposes when interacting with the popup.  
In ```TestApp/SPTest/views.py``` you can see which cookie properties are set and comments indicate to which
 security level they should be upgraded according to the policy that is already loaded into the extension, 
 which you can find at ```SPEnforcer/background.js```.  
 You can verify that SPEnforcer upgraded these attributes by investigating the Network tab in the Devtools bar and
  checking the individual headers in the HTTP response.

# SPCollector
SPCollector is bundled together with SPEnforcer and can be enabled via a boolean switch in ```SPEnforcer/background.js```.  
Once enabled it will send all collected headers to SPAggregator. 
 
# SPAggregator
SPAggregator is implemented as a minimal Flask server which can be started in ```SPAggregator/``` using:
```
python3 SPAggregator.py
``` 

Once running, it will collect all observed URLs and relevant headers in a temporary sqlite database. Retrieving the compiled manifest is possible through a POST request to `/get_manifest`, sending the site in a JSON object like `{"site": "site.com"}`. This returns both the generated manifest as well as the URL mapping.

# SPAnalyzer
SPAnalyzer can be used as a command-line utility in ```SPAnalyzer/``` via:
```
python3 SPAnalyzer.py --input <path_to_site_policy_file>
```
We provide some example manifest files in ```example_manifest/```.  
The final output of the tool will provide an overview about the issues outlined in Section 6.C.
Furthermore, it provides conditions under which inconsistencies will arise, by pairwise comparison of the policies. 


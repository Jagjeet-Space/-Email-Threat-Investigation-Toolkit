Phishscan is an Email_Threat_Investigation CLI tool purpose is to make email analyzing fast and efficent with Key IOC's right in our output. It is build to make email analyzing easy, with every key information will be presented through this tool that is needed to know if the email is suspicious or not. 

What Phishscan do is take .eml file and analyze in three different first and print out in json output. These three scripiits names as:

`analyze_headers.` as its name says it analyze headers to identify spoofing, sender authenticity and unusal routing and.

`ioc_extractor` analyze IOC in whole email to identify maliciious extract links, domains, from headers,body and attachmemts  

`attachment_analyzer` to detect malicious files, compute hashes, and check suspicious traits  

We will discuss these scripts in details later. Now when we have these three scripts we will pipe those modules into one script that will run our Phishscan. These three files scripts will use by phishscan.py script that will use three modules of these scripts with that script phishcan can use those scripts however we want it if we want to output just attachment related IOC then we can use attachment option with Phischan CLI to filter out only attachment analysis vice versa with others script. We can also make Phishscan to put our all output in formatted json file.

For installing Phishscan we just have ```pip``` 

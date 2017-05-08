import logging
from datamodel.search.datamodel import ProducedLink, OneUnProcessedGroup, robot_manager, Link
from spacetime.client.IApplication import IApplication
from spacetime.client.declarations import Producer, GetterSetter, Getter
from lxml import html,etree
from lxml.html import fromstring
import re, os
from time import time
import urllib2
#import requests
#from requests.exceptions import HTTPError



try:
    # For python 2
    from urlparse import urlparse, parse_qs
except ImportError:
    # For python 3
    from urllib.parse import urlparse, parse_qs


logger = logging.getLogger(__name__)
LOG_HEADER = "[CRAWLER]"
url_count = (set() 
    if not os.path.exists("successful_urls.txt") else 
    set([line.strip() for line in open("successful_urls.txt").readlines() if line.strip() != ""]))
MAX_LINKS_TO_DOWNLOAD = 3000

#####################
# ANALYTICS GLOBALS #
#####################
SUBDOMAINS = {} # Key: Subdomain (String) | Value: URLs Processed (int)
INVALID_LINKS = 0
MOST_OUT = ""

@Producer(ProducedLink, Link)
@GetterSetter(OneUnProcessedGroup)
class CrawlerFrame(IApplication):

    def __init__(self, frame):
        self.starttime = time()
        # Set app_id <student_id1>_<student_id2>...
        self.app_id = "56103533_27358552_49463175"
        # Set user agent string to IR W17 UnderGrad <student_id1>, <student_id2> ...
        # If Graduate studetn, change the UnderGrad part to Grad.
        self.UserAgentString = "IR S17 UnderGrad 56103533, 27358552, 49463175"
		
        self.frame = frame
        assert(self.UserAgentString != None)
        assert(self.app_id != "")
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def initialize(self):
        self.count = 0
        l = ProducedLink("http://www.ics.uci.edu", self.UserAgentString)
        print l.full_url
        self.frame.add(l)

    def update(self):
        for g in self.frame.get_new(OneUnProcessedGroup):
            print "Got a Group"
            outputLinks, urlResps = process_url_group(g, self.UserAgentString)
            for urlResp in urlResps:
                if urlResp.bad_url and self.UserAgentString not in set(urlResp.dataframe_obj.bad_url):
                    urlResp.dataframe_obj.bad_url += [self.UserAgentString]
            for l in outputLinks:
                if is_valid(l) and robot_manager.Allowed(l, self.UserAgentString):
                    lObj = ProducedLink(l, self.UserAgentString)
                    self.frame.add(lObj)
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def shutdown(self):
        print "downloaded ", len(url_count), " in ", time() - self.starttime, " seconds."
        pass

def save_count(urls):
    global url_count
    urls = set(urls).difference(url_count)
    url_count.update(urls)
    if len(urls):
        with open("successful_urls.txt", "a") as surls:
            surls.write(("\n".join(urls) + "\n").encode("utf-8"))

def process_url_group(group, useragentstr):
    rawDatas, successfull_urls = group.download(useragentstr, is_valid)
    save_count(successfull_urls)
    return extract_next_links(rawDatas), rawDatas
    
#######################################################################################
'''
STUB FUNCTIONS TO BE FILLED OUT BY THE STUDENT.
'''
def extract_next_links(rawDatas):
    global SUBDOMAINS
    #print("Checking enl1####################################################")
    outputLinks = list()
    for item in rawDatas:
        print("CONTENT ####################################################")
        print(item.content)
        print("#############################################################")
        try:
            content = urllib2.urlopen(item.url).read()
        except urllib2.URLError:
            print("ERRORHTTP################################################")
        else:
            print("SUCCESS###############################################")
            print("CHK HTML###############################################")
            h = html.fromstring(content)
            h.make_links_absolute(item.url)
            print (html.tostring(h))
            print("########################################################")
            for link in h.iterlinks():
                parsed = urlparse(link[2])
                print(parsed)
                print(link)
                if parsed.scheme=='http' and 'ics.uci.edu' in parsed.netloc:
                    if parsed.netloc not in SUBDOMAINS:
                        SUBDOMAINS[parsed.netloc] = 1
                    else:
                        SUBDOMAINS[parsed.netloc] = SUBDOMAINS[parsed.netloc] + 1
                    outputLinks.append(link[2])
                    print("\n")
                    print(SUBDOMAINS)
                    print("\n")
            print("##########################################################")
        
        #print("Checking enl2####################################################")
        
    '''
    rawDatas is a list of objs -> [raw_content_obj1, raw_conteLaidnt_obj2, ....]
    Each obj is of type UrlResponse  declared at L28-42 datamodel/search/datamodel.py
    the return of this function should be a list of urls in their absolute form
    Validation of link via is_valid function is done later (see line 42).
    It is not required to remove duplicates that have already been downloaded. 
    The frontier takes care of that.

    Suggested library: lxml
    '''
    return outputLinks

def is_valid(url):
    #print("Checking is_Valid###################################################")
    '''
    Function returns True or False based on whether the url has to be downloaded or not.
    Robot rules and duplication rules are checked separately.

    This is a great place to filter out crawler traps.
    '''
    parsed = urlparse(url)
    #print("URL CHECK:",url)
    ##############################################################################
    ##############################################################################
    
    
    '''
    if re.match('^.*/[^/]{300,}$',url)!=None:
        print("BAD WIX######################################################")
        url.bad_url=True
        return False
    
    
    if re.compile('^.*calendar.*$').match(url)!=None:
        print("BAD CAL######################################################")
        url.bad_url=True
        return False
    
    if re.compile('^.*?(/.+?/).*?\1.*$|^.*?/(.+?/)\2.*$').match(url)!=None:
        print("REP DIR######################################################")
        url.bad_url=True
        return False
    
    if re.compile('^.*(/misc|/sites|/all|/themes|/modules|/profiles|/css|/field|/node|/theme){3}.*$').match(url)!=None:
        print("EXT DIR######################################################")
        url.bad_url=True
        return False
    '''

    global INVALID_LINKS
    
    split_path=parsed.path.split('/')
    for item in split_path:
        if item!='':
            if split_path.count(item)>1:
                #print(split_path,"#################################")
                print("BAD PATH######################################################")
                #url.bad_url=True
                INVALID_LINKS = INVALID_LINKS + 1
                return False
        if "calendar" in item.lower():
            print("BAD CAL######################################################")
            #url.bad_url=True
            INVALID_LINKS = INVALID_LINKS + 1
            return False
        if len(item)>300:
            print("BAD WIX######################################################")
            #url.bad_url=True
            INVALID_LINKS = INVALID_LINKS + 1
            return False
    
    ##############################################################################
    ##############################################################################
    if parsed.scheme not in set(["http", "https"]):
        return False
    try:
        return ".ics.uci.edu" in parsed.hostname \
            and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4"\
            + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
            + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
            + "|thmx|mso|arff|rtf|jar|csv"\
            + "|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        
    
    return True   

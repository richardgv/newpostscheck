#! /usr/bin/env python3.2
# -*- coding: utf-8 -*-
# vim:fileencoding=utf-8

# Forum New Post Notifier
# Richard Grenville (RichardGv)
# https://github.com/richardgv/newpostscheck
# License: GPLv3 or later
# This script sucks, I know.

# Modules
import urllib.request, urllib.parse, os, re, http.cookies, time, hashlib, socket, random, argparse, sys, io, gzip
from collections import deque
if 'posix' == os.name:
	import pipes

# HTTP debug flag
from http.client import HTTPConnection
HTTPConnection.debuglevel = 0

# Constants
config = dict(
		# cookiefilepath: Path to the cookie file
		cookiefilepath = 'newpostscheck_cookies.txt',
		# interval: The interval between checks, in seconds
		interval = 540,
		# maxretry: Maximum retries
		maxretry = 3,
		# debug: A flag to print additional debug messages and
		# save HTTP responses for debugging purposes
      		debug = False,
		# debugpathbase: The prefix of the path to save HTTP responses
		# in debug mode
      		debugpathbase = '/tmp/newpostscheck_',
		# timeout: Connection timeout, in seconds
		timeout = 10,
		# headers: Custom HTTP headers
		headers = {'Accept-Encoding': 'gzip', 'Accept-Charset': 'UTF-8,*'},
		# headers_host: URL-specific HTTP headers
		headers_host = { '^http://(www\.)?niftyhost.us': { 'User-Agent': r'Mozilla/5.0 (X11; Linux x86_64; rv:2.0) Gecko/20110325 Firefox/4.0'} },
		# dnscache: Enable DNS caching
		dnscache = True,
		# dnscache: Enable command queuing
		cmdqueuing = True,
		# envprefix: Prefix of environment variables changing the script
		# configurations dynamically, "" to disable the feature
	      	envprefix = 'NPC_',
		# conffile: A list of paths to search for configuration files
      		conffile = [ 'newpostscheck.xml' ],
		# regex_default
		regex_default = dict(post_title = 1, post_author = 1, post_url = 1, friendlyredir = 1, login_session = 1)
		)
config['target'] = dict(
		niftyhost = dict(
		enable = True, 
		username = '', 
		password = '', 
		url = 'http://www.niftyhost.us/support/search.php?action=getnew', 
		encoding = 'utf-8', 
		loginurl = 'http://www.niftyhost.us/support/member.php', 
		base = 'http://www.niftyhost.us/support/', 
		regex_newpost = r'<!-- start: forumdisplay_thread_gotounread -->(.|\n)+?<!-- end: search_results_threads_thread -->', 
		regex_post_title = r'<a href=".+?\.html" class="[\w\s]+subject_new" id="tid_.*?">(.+?)</a>', 
		regex_post_author = r'<a href=".+?\.html">Last Post</a>: <a href=".+?\.html">(.*?)</a>', 
		regex_post_url = r'<a href="(.+?)"><img src="', 
		query = 'action=do_login&url=http%3A%2F%2Fwww.niftyhost.us%2Fsupport%2Findex.php&quick_login=1&quick_username={username}&quick_password={password}&submit=Login&quick_remember=yes', 
		regex_logout = r'<span id="quick_login">Hello There, Guest!', 
		regex_empty = r'<td class="trow1">Sorry, but no results were returned using the query information you provided. Please redefine your search terms and try again.</td>'), 
		
		serial_experience = dict(
		enable = True, 
		username = '', 
		password = '', 
		url = 'http://www.serialexperience.co.cc/search.php?action=unreads', 
		encoding = 'utf-8', 
		loginurl = 'http://www.serialexperience.co.cc/member.php?action=login', 
		base = 'http://www.serialexperience.co.cc/', 
		regex_newpost = r'<!-- start: forumdisplay_thread_gotounread -->(.|\n)+?<!-- end: search_results_threads_thread -->', 
		regex_post_title = r'<a href=".+?\.html" class="[\w\s]+subject_new" id="tid_.*?">(.+?)</a>', 
		regex_post_author = r'<a href=".+?\.html">Last Post</a>: <a href=".+?\.html">(.*?)</a>', 
		regex_post_url = r'<a href="(.+?)"><img src="', 
		query = 'action=do_login&url=http%3A%2F%2Fwww.serialexperience.co.cc%2Findex.php&quick_login=1&quick_username={username}&quick_password={password}&submit=Login&quick_remember=yes', 
		regex_logout = r'<!-- end: headerinclude -->(?!(.|\n)+ajaxpmnotice\(\))', 
		regex_empty = r'<td class="trow1">Sorry, but no results were returned using the query information you provided. Please redefine your search terms and try again.</td>', 
		regex_friendlyredir = '<a href="([^"]+)">(<span class="smalltext">)?Click here if you don\'t want to wait any longer.'), 
		
		xdwebhosting = dict(
		enable = True, 
		username = '', 
		password = '', 
		base = 'http://www.xdwebhosting.com/forums/', 
		url = 'http://www.xdwebhosting.com/forums/search.php?action=getnew', 
		encoding = 'utf-8', 
		loginurl = 'http://www.xdwebhosting.com/forums/member.php', 
		regex_newpost = r'<!-- start: forumdisplay_thread_gotounread -->(.|\n)+?<!-- end: search_results_threads_thread -->', 
		regex_post_title = r'<a href=".+?\.html" class="[\w\s]+subject_new" id="tid_.*?">(.+?)</a>', 
		regex_post_author = r'<a href=".+?\.html">Last Post</a>: <a href=".+?\.html">(.*?)</a>', 
		regex_post_url = r'<a href="(.+?)"><img src="', 
		query = 'action=do_login&url=http%3A%2F%2Fwww.xdwebhosting.com%2Fforums%2Findex.php&quick_login=1&quick_username={username}&quick_password={password}&submit=Login&quick_remember=yes', 
		regex_logout = r'<span id="quick_login">Hello There, Guest!', 
		regex_empty = r'<td class="trow1">Sorry, but no results were returned using the query information you provided. Please redefine your search terms and try again.</td>'), 
		
		zemhost = dict(
		enable = True,
		username = '', 
		password = '', 
		url = 'http://www.zemhost.com/forums/search.php?do=getnew&contenttype=vBForum_Post', 
		encoding = 'iso-8859-1', 
		loginurl = 'http://www.zemhost.com/forums/login.php?do=login', 
		base = 'http://www.zemhost.com/forums/', 
		regex_newpost = r'<h3 class="searchtitle">(.|\n)+?<div class="threadpostedin td alt">(.|\n)+?</div>', 
		regex_post_title = r'<a class="title threadtitle_unread" href=".+?" id=".+?" title="(.|\n)+?">(.+?)</a>', 
		regex_post_title_group = 2,
		regex_post_author = r'<dd>\s+by <a href=".+?">(.+?)</a>', 
		regex_post_url = r'<a href="(.+?)" id=".+?"><img class="gotonewpost"', 
		query = 'vb_login_username={username}&vb_login_password_hint=Password&vb_login_password=&cookieuser=1&s=&securitytoken=guest&do=login&vb_login_md5password={pwdmd5}&vb_login_md5password_utf={pwdmd5_utf}', 
		regex_logout = r'<ul class="nouser">', 
		regex_empty = r'<div class="blockrow restore">Sorry, there are no new posts to view.<br />'), 
		
		kottnet = dict(
		enable = False, 
		username = '', 
		password = '', 
		url = 'http://kottnet.net/forum/index.php?action=unread;all;start=0', 
		encoding = 'utf-8', 
		loginurl = 'http://kottnet.net/forum/index.php?action=login2', 
		base = 'http://kottnet.net/forum/', 
		regex_newpost = r'<tr>(.|\n)+?</tr>', 
		regex_post_title = r'<span id="msg_\d+"><a href=".+?">(.+?)</a></span>', 
		regex_post_author = r'(?<!Started )by <a href=".+?">(.+?)</a>', 
		regex_post_url = r'<a href="http://kottnet.net/forum/(.+?)" id="newicon\d+"><img src=".+?" alt="New" /></a>', 
		query = 'user={username}&passwrd=&cookielength=-1&hash_passwrd={smfhash}', 
		regex_logout = r'<form id="guest_form"', 
		regex_empty = r'<h3 class="catbg centertext">\s+No messages...', 
		regex_login_session = 'onsubmit="hashLoginPassword\\(this, \'(\\w+)\'\\);"'), 
		
		fvwmforums = dict(
		enable = True, 
		username = '', 
		password = '', 
		url = 'http://www.fvwmforums.org/phpBB3/search.php?search_id=unreadposts', 
		encoding = 'utf-8', 
		loginurl = 'http://www.fvwmforums.org/phpBB3/ucp.php?mode=login', 
		base = 'http://www.fvwmforums.org/phpBB3/', 
		query = 'username={username}&password={password}&autologin=on&login=Login&redirect=.%2Findex.php%3F', 
		regex_logout = r'title="Login" accesskey="x">Login</a></li>', 
		regex_newpost = r'<dl class="icon" style="background-image: url\(./styles/prosilver/imageset/topic_unread.gif\); background-repeat: no-repeat;">(.|\n)+?</dl>', 
		regex_post_title = r'class="topictitle">(.+?)</a>', 
		regex_post_author = r'by <a href=".+?">(.+?)</a>\n', 
		regex_post_url = r'<a href="./(.+?)"><img src="./styles/prosilver/imageset/icon_topic_newest.gif"', 
		regex_empty = r'<p>No suitable matches were found.</p>'), 
		
		ucweb = dict(
		enable = False, 
		username = '', 
		password = '', 
		url = 'http://forum.ucweb.com/', 
		encoding = 'utf-8', 
		loginurl = 'http://forum.ucweb.com/logging.php?action=login&', 
		base = 'http://forum.ucweb.com/', 
		query = 'formhash={formhash}&referer=index.php&loginfield=username&username={username}&password={password}&questionid=0&answer=&cookietime=315360000&loginmode=&styleid=&loginsubmit=true', 
		regex_logout = r'<li><a href="register.php" class="notabs">Register</a></li>', 
		regex_login_session = r'<input type="hidden" name="formhash" value="(\w+)" />'), 
		)
config['strlst'] = dict(
		fdbg = dict(posix = '\033[32mDEBUG: {}\033[0m\n', default = 'DEBUG: {}\n'), 
		ferr = dict(posix = '\033[41m{}\033[0m\n', default = '{}\n'),
		msg_newpost = dict(posix = '\033[1;32mA new post in {site}: {title} by {author}\033[0m:\n{url}\n', default = 'A new post in {site}: {title} by {author}:\n{url}\n'), 
		msg_check = dict(default = 'Checking {}...\n', ),
		msg_next = dict(default = 'Next check: {} seconds later\n', ),
		msg_interval = dict(posix = '\r\033[1G\033[K{} seconds left', default = '\r{} seconds left'),
		msg_intervalend = dict(posix = '\033[1G\033[K', default = '\r'),
		msg_login = dict(default = 'Hmm, I forgot to login to {}?\n'),
		msg_loggedin = dict(default = 'Logged in to {}.\n'),
		msg_retry = dict(default = 'Retrying...\n'),
		msg_friendlyredir = dict(default = '\"Friendly\" redirection... I hate this.\n'),
		err_req = dict(default = '{type}: {errmsg} when visiting {url}'),
		err_opendns = dict(default = 'Meh, we met a DNS problem -- and you are a lovely OpenDNS user.'),
		err_fail = dict(default = 'I met an error when trying to access {}. Retrying...'),
		err_noaccount = dict(default = 'And I cannot find your username or password, either.'),
		err_tmretries = dict(default = 'Oh, too many retries. Skipping it.'),
		err_no_friendlyredir_target = dict(default = 'No friendly redirection target found.'),
		err_friendlyredir_fail = dict(default = 'I met an error when trying to handling friendly redirection of {}. Retrying...'),
		err_friendlyredir_tmretries = dict(default = 'Oh, too many retries when handling friendly redirection. Skipping it.'),
		err_login_fail = dict(default = 'I met an error when trying to login to {}. Retrying...'),
		err_login_sessionstr = dict(default = 'Login session string not found.'),
		err_io = dict(default = 'I met an IOError {}.'),
		cmd_newpost = dict(posix = [r'notify-send A\ new\ post\ in\ {site_esc} {title_esc}\ by\ {author_esc}', 'mplayer -really-quiet /usr/share/sounds/purple/receive.wav'], default = ()), 
		cmd_err = dict(posix = ['notify-send I\ failed\ when\ checking\ new\ posts\ in\ {site_esc}', ], default = ()), 
		)

def getosstr(tb):
	if os.name in tb:
		return tb[os.name]
	else:
		return tb['default']

fdbg = getosstr(config['strlst']['fdbg'])

# Variables
timer = 0
dnscacheentries = dict()
edit = dict()
editdata = ''
cmdqueue = deque()

# XML config parser
def configparse(path, ignore_missing = True):
	success = False
	debug_prt('configparse: Start parsing: {}', path)
	if isinstance(path, list):
		for i in path[:-2]:
			if configparse(path, ignore_missing):
				success = True
		if not success:
			success = configparse(path[-1], True)
		return success
	if os.path.isdir(path):
		debug_prt('configparse: Directory recursion: {}', path)
		for root, dirs, files in os.walk(path):
			for name in files:
				if name.endswith('.xml'):
					configparse(join(root, name))
		return True
	import xml.parsers.expat
	global config
	p = xml.parsers.expat.ParserCreate()
	def configparse_startele(name, attrs):
		global edit, editdata
		debug_prt('XML startele: {} / {}', name, repr(attrs))
		if edit:
			debug_prt('XML: Two edit elements are stacking: {} and {}', name, repr(edit))
			raise Exception('Configuration parsing error')
		elif 'config' == name and 'name' in attrs \
				and attrs['name'] in config:
			edit = dict( type = 'config', 
					name = attrs['name'],
					mode = attrs.get('mode', 'assign') )
		elif 'target' == name and 'key' in attrs \
				and 'name' in attrs:
			edit = dict( type = 'target', 
					key = attrs['key'],
					name = attrs['name'],
					mode = attrs.get('mode', 'assign') )
		elif 'strlst' == name and 'key' in attrs:
			edit = dict( type = 'strlst', 
					key = attrs['key'],
					name = attrs.get('name', os.name),
					mode = attrs.get('mode', 'assign') )
		elif 'include' == name:
			edit = dict( type = 'include', 
					ignore_missing = bool(attrs.get('ignore_missing', False)) )
		editdata = ''
	def configparse_endele(name):
		global edit, editdata
		editdata = editdata.strip()
		if not edit:
			debug_prt('XML: chardata belongs to no edit element: {}', repr(editdata))
			return
		debug_prt('XML: chardata belongs to {}: {}', repr(edit), repr(editdata))
		if 'include' == edit['type']:
			configparse(editdata, edit['ignore_missing'])
		elif 'config' == edit['type']:
			editconf(config, edit['name'], editdata, edit['mode'])
		elif 'strlst' == edit['type']:
			create_strlst(edit['key'], edit['name'])
			editconf(config['strlst'][edit['key']], edit['name'], editdata, edit['mode'])
		elif 'target' == edit['type']:
			create_target(edit['key'], edit['name'])
			editconf(config['target'][edit['key']], edit['name'], editdata, edit['mode'])
		edit = list()
		editdata = ''
	def configparse_chardata(data):
		global editdata
		editdata = editdata + data
	p.StartElementHandler = configparse_startele
	p.EndElementHandler = configparse_endele
	p.CharacterDataHandler = configparse_chardata
	try:
		if '-' == path:
			path = sys.stdin
		else:
			path = open(path, 'rb')
		p.ParseFile(path)
	except IOError as err:
		if not ignore_missing:
			raise err
		success = False
		debug_prt('I met an IOError: {}', err)
	return success

def editconf(parent, key, new, mode):
	new = eval(new)
	if 'append' == mode:
		if isinstance(parent[key], list) and isinstance(new, list):
			parent[key].extend(new)
			return
		elif isinstance(orig, dict) and isinstance(new, dict):
			parent[key].update(new)
			return
	parent[key] = new

def create_target(key, name):
	if key not in config['target']:
		config['target'][key] = dict(enable = True)
	if name not in config['target'][key]:
		config['target'][key][name] = None

def create_strlst(key, name):
	if key not in config['strlst']:
		config['strlst'][key] = dict()
	if name not in config['strlst'][key]:
		config['strlst'][key][name] = config['strlst'][key].get('default', [ list() if name.startswith('cmd_') else '' ])

# XML config generator
def genconf(output, full = False):
	import xml.etree.ElementTree as etree
	from xml.dom import minidom
	root = etree.Element('root')
	if not full:
		for i in { 'debug', 'debugpathbase' }:
			ele = etree.SubElement(root, 'config', dict(name = i))
			ele.text = repr(config[i])
		for i in config['target']:
			for j in { 'username', 'password' }:
				ele = etree.SubElement(root, 'target', dict(key = i, name = j))
				ele.text = repr(config['target'][i][j])
	else:
		for i in config:
			if i in { 'target', 'strlst', 'conffile', 'envprefix' }:
				continue
			ele = etree.SubElement(root, 'config', dict(name = i))
			ele.text = repr(config[i])
		for i in config['target']:
			for j in config['target'][i]:
				ele = etree.SubElement(root, 'target', dict(key = i, name = j))
				ele.text = repr(config['target'][i][j])
		for i in config['strlst']:
			ele = etree.SubElement(root, 'strlst', dict(key = i))
			ele.text = repr(getosstr(config['strlst'][i]))
	xmldom = minidom.parseString(etree.tostring(root, 'utf-8'))
	if '-' == output:
		f = sys.stdout
		f.write(xmldom.toprettyxml())
	else:
		f = open(output, 'w', encoding = 'utf-8')
		f.write(xmldom.toprettyxml())
		f.close()

# Functions
def unescape(s):
    s = s.replace("&lt;", "<")
    s = s.replace("&gt;", ">")
    s = s.replace("&quot;", "\"")
    # this has to be last:
    s = s.replace("&amp;", "&")
    return s

def request(url, encoding, data = None):
	if isinstance(data, str):
		data = data.encode('utf-8')
	req = urllib.request.Request(url, data, config['headers'])
	if data:
		debug_prt('urlopen(\'{}\', \'{}\')', url, data)
	else:
		debug_prt('urlopen(\'{}\')', url)
	try:
		resp = urllib.request.urlopen(req, None, config['timeout'])
		if -1 != resp.geturl().find('guide.opendns.com'):
			prtmsg('err_opendns', url);
			if req.host in dnscacheentries:
				del config['dnscache'][req.host]
			return None;
		if 'gzip' == resp.info().get('Content-Encoding'):
			debug_prt('gzip compression detected')
			resp = gzip.GzipFile(fileobj = io.BytesIO(resp.read()), mode = 'rb')
		resp = resp.read()
		resp = resp.decode(encoding)
	except Exception as err:
		prtmsg('err_req', type = err.__class__, errmsg = err, url = url)
		return None
	return resp;

def newpostscheck(key):
	prtmsg('msg_check', key)
	retry = config['maxretry']
	while retry:
		resp = request(config['target'][key]['url'], config['target'][key]['encoding'])
		if not resp:
			prtmsg('err_fail', key)
			retry -= 1
			continue
		debug_file('{}{}.html'.format(config['debugpathbase'], key), resp)
		if config['target'][key].get('regex_logout'):
			match = re.search(config['target'][key]['regex_logout'], resp)
			if match:
				prtmsg('msg_login', key)
				if config['target'][key].get('username') and config['target'][key].get('password'):
					prtmsg('msg_retry', key)
					login(key, resp)
				else:
					prtmsg('err_noaccount', key)
					retry = 0
					break
				retry -= 1
				continue
		break
	if not retry:
		prtmsg('err_tmretries', key)
		cmdqueue_add('cmd_err', site = key)
		return None
	resp = friendlyredir(key, resp)
	if not resp:
		return
	if config['target'][key].get('regex_empty'):
		match = re.search(config['target'][key]['regex_empty'], resp)
		if match:
			debug_prt('regex_empty matched.')
			return dict()
	if 'regex_newpost' in config['target'][key] and config['target'][key]['regex_newpost']:
		for match in re.finditer(config['target'][key]['regex_newpost'], resp):
			match = match.group(config['target'][key].get('regex_newpost_group', 0))
			info = dict()
			for i in config['target'][key]:
				if not i.startswith('regex_post_') or i.endswith('_group'):
					continue
				name = i[len('regex_post_'):]
				info[name] = unescape(getregexdef(re.search(config['target'][key][i], match), key, 'post_' + name))
				if 'url' == name:
					info[name] = config['target'][key]['base'] + info[name]
			prtmsg('msg_newpost', site = key, **info)
			cmdqueue_add('cmd_newpost', site = key, **info)
			if not config['cmdqueuing']:
				cmdquee_proc()

def friendlyredir(key, oriresp):
	if config['target'][key].get('regex_friendlyredir'):
		prtmsg('msg_friendlyredir', key)
		match = re.search(config['target'][key]['regex_friendlyredir'], oriresp)
		if not match:
			prtmsg('err_no_friendlyredir_target')
			return
		match = config['target'][key]['base'] + unescape(getregexdef(match, key, 'friendlyredir'))
		retry = config['maxretry']
		while retry:
			resp = request(match, config['target'][key]['encoding'])
			if not resp:
				prtmsg('err_friendlyreedir_fail', key)
				retry -= 1
				continue
			debug_file('{}{}_friendlyredir.html'.format(config['debugpathbase'], key), resp)
			break
		if not retry:
			prtmsg('err_friendlyredir_tmretries')
			return
		return resp
	else:
		return oriresp

def login(key, resp):
	resp = request(config['target'][key]['loginurl'], config['target'][key]['encoding'], config['target'][key]['query'].format(username = urllib.parse.quote_plus(config['target'][key]['username']), password = urllib.parse.quote_plus(config['target'][key]['password']), pwdmd5 = hashlib.md5(config['target'][key]['password'].encode(config['target'][key]['encoding'])).hexdigest(), pwdmd5_utf = hashlib.md5(config['target'][key]['password'].encode('utf-8')).hexdigest(), formhash = formhash(key, resp), smfhash = smfhash(key, resp)))
	if not resp:
		prtmsg('msg_login_fail')
		return
	prtmsg('msg_loggedin', key)
	debug_file('{}{}_login.html'.format(config['debugpathbase'], key), resp)
	if config['cookiefilepath']:
		cookies.save(config['cookiefilepath'])

def formhash(key, resp):
	if not config['target'][key].get('regex_login_session'):
		return ''
	match = re.search(config['target'][key]['regex_login_session'], resp)
	if not match:
		prtmsg('msg_login_sessionstr', key)
		return ''
	match = getregexdef(match, key, 'login_session')
	debug_prt('formhash = {}', match)
	return match

def smfhash(key, resp):
	match = formhash(key, resp)
	if not match:
		return ''
	return hashlib.sha1((hashlib.sha1((config['target'][key]['username'].lower() + config['target'][key]['password']).encode('utf-8')).hexdigest() + match).encode('utf-8')).hexdigest()

def cmdqueue_add(cmdindex, *arg, **kwargs):
	global cmdqueue
	if 'pipes' in sys.modules:
		for key in set(kwargs.keys()):
			kwargs[key + "_esc"] = pipes.quote(kwargs[key])
	for cmd in config['strlst'][cmdindex]:
		cmdqueue.append(cmd.format(*arg, **kwargs))

def cmdqueue_proc():
	global cmdqueue
	for cmd in cmdqueue:
		os.system(cmd)
	cmdqueue.clear()

def getregexdef(match, key, name):
	return match.group(config['target'][key].get('regex_' + name + '_group', config['regex_default'][name]))

def genstrlst():
	"""Generate platform-specific string list"""
	global fdbg, config
	flags = set()
	for strindex in config['strlst']:
		if strindex.startswith('f'):
			flags.add(strindex[1:])
			config['strlst'][strindex] = getosstr(config['strlst'][strindex])
	for strindex in config['strlst']:
		flag = set()
		if strindex.startswith('f'):
			continue
		string = getosstr(config['strlst'][strindex])
		for i in flags:
			if strindex.startswith(i + '_'):
				flag.add(i)
			if 'flag_' + i in config['strlst'][strindex]:
				if config['strlst'][strindex]['flag_' + i]:
					flag.add(i)
				else:
					flag.discard(i)
		for i in flag:
			string = config['strlst']['f' + i].format(string)
		config['strlst'][strindex] = string
	fdbg = config['strlst']['fdbg']

def lstargets():
	prefix = ' '
	prefix_url = '    '
	print('Available target sites: ')
	for i in config['target']:
		print(prefix + i + '\n' + prefix_url + config['target'][i]['url'] + '\n')

def debug_file(path, content):
	if config['debug']:
		f = open(path, 'wb')
		f.write(content.encode('utf-8'))
		f.close()

def prtmsg(strindex, *arg, **kwargs):
	print(config['strlst'][strindex].format(*arg, **kwargs), end = '')

def debug_prt(msg, *arg, **kwargs):
	if config['debug']:
		print(fdbg.format(msg.format(*arg, **kwargs)), end = '', file = sys.stderr)

# HTTPHandler
class httphandler(urllib.request.HTTPHandler):
	def http_open(self, req):
		for i in config['headers_host']:
			if re.search(i, req.full_url):
				debug_prt('URL-specific header: {} => {}',
						repr(config['headers_host'][i]), req.full_url)
				for j in config['headers_host'][i].items():
					req.add_unredirected_header(*j)
		if config['dnscache']:
			if req.host not in dnscacheentries:
				ip = socket.gethostbyname_ex(req.host)[-1]
				if not isinstance(ip, str):
					ip = random.choice(ip)
				dnscacheentries[req.host] = ip
				debug_prt('DNS cache (new): {} == {}', req.host, ip)
			debug_prt('DNS cache: {} == {}', req.host, dnscacheentries[req.host])
			req.host = dnscacheentries[req.host]
		return urllib.request.HTTPHandler().http_open(req)

# Argument parser
args = list(sys.argv)
del args[0]
if config['envprefix'] + 'OPTIONS' in os.environ:
	debug_prt('Env _OPTIONS: {}', repr(os.environ[config['envprefix'] + 'OPTIONS'].split()))
	args = args + os.environ[config['envprefix'] + 'OPTIONS'].split()
parser = argparse.ArgumentParser(description='Checks for new posts in various forums')
parser.add_argument('conf', help = "path to the configuration file (\"-\" for stdin)", nargs = '?', metavar = 'CONFIGURATION_FILE')
parser.add_argument('-d', '--debug', help = "enable debug mode", action = 'store_true')
parser.add_argument('-D', '--no-debug', help = "disable debug mode", action = 'store_true')
parser.add_argument('-e', '--enable', help = "enable a target", metavar = 'TARGET', nargs = '+')
parser.add_argument('-E', '--disable', help = "disable a target", metavar = 'TARGET', nargs = '+')
parser.add_argument('-o', '--only', help = "keep only a target enabled", metavar = 'TARGET')
group = parser.add_mutually_exclusive_group()
group.add_argument('-g', '--genconf', help = "generate a basic configuration file (\"-\" for stdout) and quit", metavar = 'FILE')
group.add_argument('-G', '--genfullconf', help = "generate a configuration file containing all the configuration settings (\"-\" for stdout) and quit", metavar = 'FILE')
group.add_argument('-s', '--list-targets', help = "list supported target sites", action = 'store_true')
parsed_args = parser.parse_args(args)
if parsed_args.debug:
	config['debug'] = True
elif parsed_args.no_debug:
	config['debug'] = False
debug_prt('parsed_args = {}', repr(parsed_args))
if parsed_args.conf:
	configparse(parsed_args.conf, False)
	config['conffile'] = parsed_args.conf
else:
	configparse(config['conffile'])
if parsed_args.debug:
	config['debug'] = True
elif parsed_args.no_debug:
	config['debug'] = False
if parsed_args.only:
	if parsed_args.only not in config['target']:
		raise Exception('Target specified with --only not found.')
	for i in config['target']:
		config['target'][i]['enable'] = False
	del i
	config['target'][parsed_args.only]['enable'] = True
if parsed_args.enable:
	for i in parsed_args.enable:
		if i not in config['target']:
			raise Exception('Target specified with --enable not found.')
		config['target'][i]['enable'] = True
if parsed_args.disable:
	for i in parsed_args.disable:
		if i not in config['target']:
			raise Exception('Target specified with --disable not found.')
		config['target'][i]['enable'] = False
if parsed_args.genconf:
	genconf(parsed_args.genconf, False)
	exit()
elif parsed_args.genfullconf:
	genconf(parsed_args.genfullconf, True)
	exit()
elif parsed_args.list_targets:
	lstargets()
	exit()
del parser, args, parsed_args, group

# Build urllib.request opener
cookieprocessor = urllib.request.HTTPCookieProcessor()
cookies = http.cookiejar.MozillaCookieJar()
if config.get('cookiefilepath') and os.path.isfile(config['cookiefilepath']):
	cookies.load(config['cookiefilepath'])
cookieprocessor.cookiejar = cookies
defopener = urllib.request.build_opener(cookieprocessor, httphandler)
urllib.request.install_opener(defopener)

genstrlst()

# Main section
while True:
	for i in config['target'].keys():
		if config['target'][i]['enable']:
			newpostscheck(i)
	cmdqueue_proc()
	timer = config['interval']
	prtmsg('msg_next', timer)
	while timer:
		time.sleep(1)
		timer -= 1
		prtmsg('msg_interval', timer)
	prtmsg('msg_intervalend', timer)

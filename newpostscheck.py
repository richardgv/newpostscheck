#! /usr/bin/env python3.2
# -*- coding: utf-8 -*-
# vim:fileencoding=utf-8

# Forum New Post Notifier
# Richard Grenville (RichardGv)
# https://github.com/richardgv/newpostscheck
# License: GPLv3 or later
# This script sucks, I know.

# Modules
import urllib.request, urllib.parse, os, re, http.cookies, time, hashlib, socket, random, argparse, sys, io, gzip, shlex, html
from collections import deque
try:
	import pipes
except ImportError:
	pass

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
      		debugpathbase = [ '/tmp/newpostscheck_', 'newpostscheck_' ],
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
		# cycles: Cycles to run
	      	cycles = -1,
		# envprefix: Prefix of environment variables changing the script
		# configurations dynamically, "" to disable the feature
	      	envprefix = 'NPC_',
		# conffile: A list of paths to search for configuration files
      		conffile = [ '/etc/newpostscheck.xml', '~/.newpostscheck.xml','newpostscheck.xml' ],
		# regex_default
		regex_default = dict(post_title = 1, post_author = 1, post_url = 1, friendlyredir = 1, login_session = 1)
		)
config['target'] = dict(
		niftyhost = dict(
		enable = True, 
		username = '', 
		password = '', 
		url = 'http://www.niftyhost.us/support/search.php?action=unreads', 
		encoding = 'utf-8', 
		loginurl = 'http://www.niftyhost.us/support/member.php', 
		base = 'http://www.niftyhost.us/support/', 
		regex_newpost = r'<a href="[^>]+><img[^>]+?alt="Go to first unread post"(.|\n)+?</tr>', 
		regex_post_title = r'<a href=".+?\.html" class="[\w\s]+subject_new" id="tid_.*?">(.+?)</a>', 
		regex_post_author = r'<a href=".+?\.html">Last Post</a>: <a href=".+?\.html">(.*?)</a>', 
		regex_post_url = r'<a href="(.+?)"><img src="', 
		query = 'action=do_login&url=http%3A%2F%2Fwww.niftyhost.us%2Fsupport%2Findex.php&quick_login=1&quick_username={username}&quick_password={password}&submit=Login&quick_remember=yes', 
		regex_logout = r'<span id="quick_login">Hello There, Guest!', 
		regex_empty = r'<td class="trow1">Sorry, but no results were returned using the query information you provided. Please redefine your search terms and try again.</td>'), 
		
		serial_experience = dict(
		enable = False, 
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
		enable = False,
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
		regex_empty = r'<strong>No suitable matches were found.</strong>'), 
		
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
		ferr = dict(posix = '\033[41m{}\033[0m', default = '{}', file = { sys.stderr }),
		msg_newpost = dict(posix = '\033[1;32mA new post in {site}: {title} by {author}\033[0m:\n{url}\n', default = 'A new post in {site}: {title} by {author}:\n{url}\n'), 
		msg_nonewpost = dict(default = 'No new posts found in {site}.\n'), 
		msg_start = dict(default = 'Starting checking cycle {cycle}...\n', ),
		msg_fin = dict(default = 'Finished checking cycle {cycle}...\n', ),
		msg_check = dict(default = 'Checking {}...\n', ),
		msg_next = dict(default = 'Next check: {} seconds later\n', ),
		msg_interval = dict(posix = '\r\033[1G\033[K{} seconds left', default = '\r{} seconds left'),
		msg_intervalend = dict(posix = '\033[1G\033[K', default = '\r'),
		msg_login = dict(default = 'Hmm, I forgot to login to {}?\n'),
		msg_loggedin = dict(default = 'Logged in to {}.\n'),
		msg_retry = dict(default = 'Retrying...\n'),
		msg_interrupt = dict(default = '\n'),
		msg_friendlyredir = dict(default = '\"Friendly\" redirection... I hate this.\n'),
		err_req = dict(default = '{type}: {errmsg} when visiting {url}\n', flag_err = True),
		err_opendns = dict(default = 'Meh, we met a DNS problem -- and you are a lovely OpenDNS user.\n', flag_err = True),
		err_fail = dict(default = 'I met an error when trying to access {}. Retrying...\n', flag_err = True),
		err_noaccount = dict(default = 'And I cannot find your username or password, either.\n', flag_err = True),
		err_tmretries = dict(default = 'Oh, too many retries. Skipping it.\n', flag_err = True),
		err_no_friendlyredir_target = dict(default = 'No friendly redirection target found.\n', flag_err = True),
		err_friendlyredir_fail = dict(default = 'I met an error when trying to handling friendly redirection of {}. Retrying...\n', flag_err = True),
		err_login_fail = dict(default = 'I met an error when trying to login to {}. Retrying...\n', flag_err = True),
		err_login_sessionstr = dict(default = 'Login session string not found.\n', flag_err = True),
		err_io = dict(default = 'I met an IOError {}\n.', flag_err = True),
		err_unused_arg = dict(default = '{number} of {name} argument(s) is/are not used.\n', flag_err = True),
		cmd_newpost = dict(posix = [r'notify-send A\ new\ post\ in\ {site_esc_html} {title_esc_html}\ by\ {author_esc_html}', 'mplayer2 -really-quiet /usr/share/sounds/purple/receive.wav'], default = []), 
		cmd_err = dict(posix = [r'notify-send I\ failed\ when\ checking\ new\ posts\ in\ {site_esc}', ], default = []), 
		cmd_fin = dict(default = []), 
		)

def getosstr(tb):
	if os.name in tb:
		return tb[os.name]
	elif 'default' in tb:
		return tb['default']
	else:
		return None

fdbg = getosstr(config['strlst']['fdbg'])

# Variables
timer = 0
dnscacheentries = dict()
cmdqueue = deque()
cur_cycle = 0

# XML config parser
def configparse(path, ignore_missing, debug_enforce):
	edit = dict()
	editdata = ''
	success = False
	debug_prt('configparse(): Start parsing: {} ({}, {})', path, ignore_missing, debug_enforce)
	if not path:
		return False
	if isinstance(path, list):
		for i in path[:-1]:
			if configparse(i, True, debug_enforce):
				success = True
		if not success:
			success = configparse(path[-1], ignore_missing, debug_enforce)
		return success
	path = os.path.expanduser(path)
	if os.path.isdir(path):
		debug_prt('configparse: Directory recursion: {}', path)
		for root, dirs, files in os.walk(path):
			files.sort()
			dirs.sort()
			debug_prt('os.walk(): {}, {}', dirs, files)
			for name in files:
				if name.endswith('.xml'):
					configparse(os.path.join(root, name), True, debug_enforce)
		return True
	import xml.parsers.expat
	global config
	p = xml.parsers.expat.ParserCreate()
	def configparse_startele(name, attrs):
		nonlocal edit, editdata
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
					ignore_missing = (False if attrs.get('ignore_missing', 'True') in { 'False', 'false', '0' } else True) )
		editdata = ''
	def configparse_endele(name):
		nonlocal edit, editdata
		editdata = editdata.strip()
		if not edit:
			debug_prt('XML: chardata belongs to no edit element: {}', repr(editdata))
			return
		debug_prt('XML: chardata belongs to {}: {}', repr(edit), repr(editdata))
		if 'include' == edit['type']:
			configparse(editdata, edit['ignore_missing'], debug_enforce)
		elif 'config' == edit['type']:
			if not ('debug' == edit['name'] and debug_enforce):
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
		nonlocal editdata
		editdata = editdata + data
	p.StartElementHandler = configparse_startele
	p.EndElementHandler = configparse_endele
	p.CharacterDataHandler = configparse_chardata
	try:
		if '-' == path:
			xmldata = sys.stdin.read()
		else:
			f = open(path, 'rb')
			xmldata = f.read()
			f.close()
	except IOError as err:
		if not ignore_missing:
			raise err
		debug_prt('configparse(): I met an IOError: {}', err)
	else:
		p.Parse(xmldata)
		success = True
	return success

def editconf(parent, key, new, mode = 'assign'):
	new = eval(new)
	if isinstance(parent[key], list) and isinstance(new, list):
		if 'append' == mode:
			parent[key].extend(new)
			return
		if 'prepend' == mode:
			parent[key] = new + parent[key]
			return
	elif isinstance(parent[key], dict) and isinstance(new, dict) \
			and mode in { 'append', 'prepend' }:
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

def srepr(item):
	if sys.stdin is item:
		return 'sys.stdin'
	elif sys.stdout is item:
		return 'sys.stdout'
	elif sys.stderr is item:
		return 'sys.stderr'
	elif isinstance(item, set):
		if item:
			string = '{ '
			for i in item:
				string += srepr(i) + ', '
			string = string[:-2] + ' }'
			return string
		else:
			return 'set()'
	elif isinstance(item, list):
		if item:
			string = '[ '
			for i in item[:-1]:
				string += srepr(i) + ', '
			string += srepr(item[-1]) + ' ]'
			return string
		else:
			return '[]'
	else:
		return repr(item)

# XML config generator
def genconf(output, full = False, separate = False):
	try:
		from lxml import etree
	except ImportError:
		debug_prt('Cannot import lxml. Falling back to cElementTree.')
		import xml.etree.cElementTree as etree

	def genele(parent, name, attrs, item):
		ele = etree.SubElement(parent, name, attrs)
		if 'lxml' in sys.modules:
			ele.text = (etree.CDATA(srepr(item)) if not (isinstance(item, bool) or isinstance(item, int)) else repr(item))
		else:
			ele.text = srepr(item)
	
	def writetree(root, output, sub = ''):
		if 'lxml' in sys.modules:
			xmlstr = etree.tostring(root, encoding = 'utf-8', xml_declaration = True, pretty_print = True).decode('utf-8')
		else:
			from xml.dom import minidom
			xmlstr = minidom.parseString(etree.tostring(root, 'utf-8')).toprettyxml()
		if '-' == output:
			sys.stdout.write(('\n' + sub + ':\n' if sub else '') + xmlstr)
		else:
			f = open(output + sub, 'w', encoding = 'utf-8')
			f.write(xmlstr)
			f.close()
		root.clear()

	root = etree.Element('root')
	if full:
		config_items = set(config.keys()).difference({ 'target', 'strlst', 'conffile', 'envprefix' })
		strlst_items = config['strlst'].keys()
	else:
		config_items = { 'debug', 'cmdqueuing', 'interval' }
		strlst_items = { 'msg_newpost', 'msg_nonewpost', 'cmd_newpost', 'cmd_err' }
	for i in config_items:
		genele(root, 'config', dict(name = i), config[i])
	if separate:
		writetree(root, output, '10-config.xml')
	for i in strlst_items:
		genele(root, 'strlst', dict(key = i), getosstr(config['strlst'][i]))
		for j in { k for k in config['strlst'][i] if k.startswith('flag_') }:
			genele(root, 'strlst', dict(key = i, name = j), config['strlst'][i][j])
		if 'file_orig' in config['strlst'][i]:
			genele(root, 'strlst', dict(key = i, name = 'file'), config['strlst'][i]['file_orig'])
	if separate:
		writetree(root, output, '20-strlst.xml')
	for i in config['target']:
		for j in (config['target'][i] if full else { 'enable', 'username', 'password' }):
			genele(root, 'target', dict(key = i, name = j), config['target'][i][j])
		if separate:
			writetree(root, output, '30-' + i + '.xml')
	if not separate:
		writetree(root, output)

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
	debug_file(re.sub('[^a-zA-Z0-9_]', '_', re.sub('^http://', '', url, 1)), resp)
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
		if config['target'][key].get('regex_logout'):
			match = re.search(config['target'][key]['regex_logout'], resp)
			if match:
				prtmsg('msg_login', key)
				if config['target'][key].get('username') and config['target'][key].get('password'):
					login(key, resp)
				else:
					prtmsg('err_noaccount', key)
					retry = 0
					break
				retry -= 1
				continue
		resp = friendlyredir(key, resp)
		if resp:
			break
		retry -= 1
	if not retry:
		prtmsg('err_tmretries', key)
		cmdqueue_add('cmd_err', site = key)
		if not config['cmdqueuing']:
			cmdquee_proc()
		return None
	found = False
	if config['target'][key].get('regex_empty') and re.search(config['target'][key]['regex_empty'], resp):
		debug_prt('regex_empty matched.')
	elif 'regex_newpost' in config['target'][key] and config['target'][key]['regex_newpost']:
		for match in re.finditer(config['target'][key]['regex_newpost'], resp):
			found = True
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
	if not found:
		prtmsg('msg_nonewpost', site = key)

def friendlyredir(key, oriresp):
	if config['target'][key].get('regex_friendlyredir'):
		prtmsg('msg_friendlyredir', key)
		match = re.search(config['target'][key]['regex_friendlyredir'], oriresp)
		if not match:
			prtmsg('err_no_friendlyredir_target')
			return
		match = config['target'][key]['base'] + unescape(getregexdef(match, key, 'friendlyredir'))
		retry = config['maxretry']
		resp = request(match, config['target'][key]['encoding'])
		if not resp:
			prtmsg('err_friendlyredir_fail', key)
		return resp
	else:
		return oriresp

def login(key, resp):
	resp = request(config['target'][key]['loginurl'], config['target'][key]['encoding'], config['target'][key]['query'].format(username = urllib.parse.quote_plus(config['target'][key]['username']), password = urllib.parse.quote_plus(config['target'][key]['password']), pwdmd5 = hashlib.md5(config['target'][key]['password'].encode(config['target'][key]['encoding'])).hexdigest(), pwdmd5_utf = hashlib.md5(config['target'][key]['password'].encode('utf-8')).hexdigest(), formhash = formhash(key, resp), smfhash = smfhash(key, resp)))
	if not resp:
		prtmsg('msg_login_fail')
		return
	prtmsg('msg_loggedin', key)
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
			kwargs[key + "_esc_html"] = pipes.quote(html.escape(str(kwargs[key])))
			kwargs[key + "_esc"] = pipes.quote(str(kwargs[key]))
	for cmd in config['strlst'][cmdindex]['cur']:
		cmdqueue.append(cmd.format(*arg, **kwargs))

def cmdqueue_proc():
	global cmdqueue
	for cmd in cmdqueue:
		os.system(cmd)
	cmdqueue.clear()

def getregexdef(match, key, name):
	return match.group(config['target'][key].get('regex_' + name + '_group', config['regex_default'][name]))

def strlst_gen():
	'''Generate strings for the current platform'''
	global fdbg, config
	flags = set()
	for strindex in { i for i in config['strlst'].keys() if i.startswith('f') }:
		flags.add(strindex[1:])
		config['strlst'][strindex]['cur'] = getosstr(config['strlst'][strindex])
	for strindex in config['strlst']:
		if strindex.startswith('f'):
			continue
		if strindex.startswith('cmd_'):
			config['strlst'][strindex]['cur'] = getosstr(config['strlst'][strindex])
		else:
			string = getosstr(config['strlst'][strindex])
			filelst = set()
			for i in flags & { j[5:] for j in config['strlst'][strindex].keys() if j.startswith('flag_') }:
				if None != config['strlst']['f' + i]['cur']:
					string = config['strlst']['f' + i]['cur'].format(string)
				filelst |= config['strlst']['f' + i]['file']
			if 'file' in config['strlst'][strindex]:
				config['strlst'][strindex]['file_orig'] = config['strlst'][strindex]['file']
			elif filelst:
				config['strlst'][strindex]['file'] = filelst
			config['strlst'][strindex]['cur'] = string
	fdbg = config['strlst']['fdbg']['cur']

def strlst_cleanup():
	'''Remove unnecessary objects in config['strlst']'''
	for strindex in config['strlst']:
		for i in frozenset(config['strlst'][strindex]).difference({ 'file', 'cur' }):
			del config['strlst'][strindex][i]

def lstargets():
	prefix = ' '
	prefix_url = '    '
	print('Available target sites: ')
	for i in config['target']:
		print(prefix + i + '\n' + prefix_url + config['target'][i]['url'] + '\n')

def debug_file(path, content):
	if config['debug']:
		f = None
		for i in config['debugpathbase']:
			try:
				f = open(i + path + '.html', 'wb')
				f.write(content.encode('utf-8'))
				break
			except IOError as err:
				debug_prt('debug_file(): IOError: {}', str(err))
			finally:
				try:
					f.close()
				except AttributeError:
					pass


def prtmsg(strindex, *arg, **kwargs):
	outputlst = config['strlst'][strindex].get('file', { sys.stdout })
	for output in outputlst:
		# debug_prt(repr(config['strlst'][strindex]))
		if isinstance(output, str):
			output = open(os.path.expanduser(output), 'a', encoding = 'utf-8')
			print(config['strlst'][strindex]['cur'].format(*arg, **kwargs), end = '', file = output)
			output.close()
		else:
			print(config['strlst'][strindex]['cur'].format(*arg, **kwargs), end = '', file = output)

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
			if not re.match('^(\d{1,3}\.){3}\d{1,3}$', req.host):
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
if config['envprefix'] and config['envprefix'] + 'OPTIONS' in os.environ:
	debug_prt('Env _OPTIONS: {}', repr(os.environ[config['envprefix'] + 'OPTIONS'].split()))
	args = args + shlex.split(os.environ[config['envprefix'] + 'OPTIONS'], True, (True if 'posix' == os.name else False))
parser = argparse.ArgumentParser(description='A Python script that checks for new posts in various forums')
parser.add_argument('conf', help = "path to the configuration file(s) (\"-\" for stdin)", metavar = 'CONFIGURATION_FILE', nargs = '*')
parser.add_argument('-a', '--accountinfo', help = "indicate the account information of a target, the format is TARGET USERNAME PASSWORD TARGET USERNAME PASSWORD ...", nargs = '+')
parser.add_argument('-c', '--cycles', help = "indicate the cycles of new post checking the script performs, -1 for infinite", metavar = 'CYCLES')
parser.add_argument('-d', '--debug', help = "enable debug mode", action = 'store_true')
parser.add_argument('-D', '--no-debug', help = "disable debug mode", action = 'store_true')
parser.add_argument('-e', '--enable', help = "enable a target", metavar = 'TARGET', nargs = '+')
parser.add_argument('-E', '--disable', help = "disable a target", metavar = 'TARGET', nargs = '+')
parser.add_argument('-o', '--only', help = "keep only a target enabled", metavar = 'TARGET')
parser.add_argument('-s', '--separate', help = "split the generated configuration file", action = 'store_true')
parser.add_argument('-!', '--no-target', help = "dislabe all targets (for debugging)", action = 'store_true')
group = parser.add_mutually_exclusive_group()
group.add_argument('-g', '--genconf', help = "generate a basic configuration file (\"-\" for stdout, default) and quit", metavar = 'FILE', nargs = '?', default = argparse.SUPPRESS)
group.add_argument('-G', '--genfullconf', help = "generate a configuration file containing all the possible settings (\"-\" for stdout, default) and quit", metavar = 'FILE', nargs = '?', default = argparse.SUPPRESS)
group.add_argument('-l', '--list-targets', help = "list supported target sites", action = 'store_true')
parsed_args = parser.parse_args(args)
debug_enforce = False
if parsed_args.debug:
	config['debug'] = True
	debug_enforce = True
elif parsed_args.no_debug:
	config['debug'] = False
	debug_enforce = True
debug_prt('parsed_args = {}', repr(parsed_args))
if parsed_args.conf:
	configparse(parsed_args.conf, False, debug_enforce)
	config['conffile'] = parsed_args.conf
else:
	configparse(config['conffile'], True, debug_enforce)
strlst_gen()
if parsed_args.no_target:
	for i in config['target']:
		config['target'][i]['enable'] = False
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
if parsed_args.accountinfo:
	if len(parsed_args.accountinfo) % 3:
		prtmsg('err_unused_arg', name = 'accountinfo', number = len(parsed_args.accountinfo) % 3)
	for i in range(len(parsed_args.accountinfo) // 3):
		if parsed_args.accountinfo[i * 3] not in config['target']:
			raise Exception('Target specified with --accountinfo not found.')
		editconf(config['target'][parsed_args.accountinfo[i * 3]], 'username', repr(parsed_args.accountinfo[i * 3 + 1]))
		editconf(config['target'][parsed_args.accountinfo[i * 3]], 'password', repr(parsed_args.accountinfo[i * 3 + 2]))
	del i
if None != parsed_args.cycles:
	config['cycles'] = int(parsed_args.cycles)
if 'genconf' in parsed_args:
	genconf((parsed_args.genconf if None != parsed_args.genconf else '-'), False, parsed_args.separate)
	exit()
elif 'genfullconf' in parsed_args:
	genconf((parsed_args.genfullconf if None != parsed_args.genfullconf else '-'), True, parsed_args.separate)
	exit()
elif parsed_args.list_targets:
	lstargets()
	exit()
del parser, args, parsed_args, group
strlst_cleanup()

# Build urllib.request opener
cookieprocessor = urllib.request.HTTPCookieProcessor()
cookies = http.cookiejar.MozillaCookieJar()
if config.get('cookiefilepath') and os.path.isfile(config['cookiefilepath']):
	cookies.load(config['cookiefilepath'])
cookieprocessor.cookiejar = cookies
defopener = urllib.request.build_opener(cookieprocessor, httphandler)
urllib.request.install_opener(defopener)


# Main section
if not (config['cycles'] - cur_cycle):
	exit()
while True:
	remaining = (-1 if config['cycles'] < 0 else config['cycles'] - cur_cycle - 1)
	prtmsg('msg_start', cycle = cur_cycle, total = config['interval'], remaining = remaining, eta = remaining * config['interval'])
	for i in config['target'].keys():
		if config['target'][i]['enable']:
			newpostscheck(i)
	prtmsg('msg_fin', cycle = cur_cycle, total = config['interval'], remaining = remaining, eta = remaining * config['interval'])
	cmdqueue_add('cmd_fin', cycle = cur_cycle, total = config['interval'], remaining = remaining, eta = remaining * config['interval'])
	cmdqueue_proc()
	cur_cycle += 1
	if not (config['cycles'] - cur_cycle):
		break
	timer = config['interval']
	prtmsg('msg_next', timer)
	try:
		while timer:
			time.sleep(1)
			timer -= 1
			prtmsg('msg_interval', timer)
	except KeyboardInterrupt:
		prtmsg('msg_interrupt')
		exit()
	prtmsg('msg_intervalend', timer)

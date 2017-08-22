f = open("./urls")
read = f.read()
f.close()

ll = read.split("\n")

count = 10000
for l in ll :
	count += 1
	port = 80
	if l[:5] == "https" :
	    port = 443
	port = str(port)
	path = l.split("//")[1]
	t = path.split("/")
	path = "/".join(t[1:len(t)])

	print "alert tcp any any -> any " + port + " (msg:\"" + l + "\"; content:\"GET /" + path + "\"; content:\"Host: " + str(l.split("//")[1].split("/")[0]) + "\"; sid:" + str(count) + "; rev:1;)";

	if  l.split("://")[0] == "https" : 
		count += 1
		print 'alert tls any any -> any any (msg:"TLS : ' + l + ' "; tls_sni; content:"' + l.split("//")[1].split("/")[0] + '"; sid:' + str(count) + '; rev:1;)'

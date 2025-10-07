dist:
	cp -r server server-dist
	sed -i -E -e 's/flag-\w+/flag-redacted/g' server-dist/Dockerfile
	tar -czf server/public/server.tar.gz server-dist
	rm -rf server-dist
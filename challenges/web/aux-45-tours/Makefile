dist:
	cp -r server server-dist
	sed -i -E -e 's/flag-\w+/flag-REDACTED/g' server-dist/Dockerfile
	tar -czf server-dist.tar.gz server-dist
	rm -rf server-dist
all: part1-dist.tar.gz part2-dist.tar.gz

part1-dist.tar.gz:
	cp -r src part1-dist
	sed -i -E -e 's/flag-\w+/flag-REDACTED/g' part1-dist/part1.py
	tar -czf part1-dist.tar.gz part1-dist/{part1.py,random_files_generator.py,tree.py,pyproject.toml,uv.lock}
	rm -rf part1-dist

part2-dist.tar.gz:
	cp -r src part2-dist
	sed -i -E -e 's/flag-\w+/flag-REDACTED/g' part2-dist/part2.py
	tar -czf part2-dist.tar.gz part2-dist/{part2.py,random_files_generator.py,solve_common.py,tree.py,pyproject.toml,uv.lock}
	rm -rf part2-dist

.PHONY: all

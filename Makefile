yetus:
	@echo Running yetus
	rm -rf yetus-output/*
	mkdir -p yetus-output
	docker run --rm -v $(CURDIR):/src:delegated,z ghcr.io/apache/yetus:0.15.0 \
		--basedir=/src \
		--test-parallel=true \
		--dirty-workspace \
		--empty-patch \
		--plugins=all \
		--patch-dir=/src/yetus-output
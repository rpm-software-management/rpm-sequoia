# To download this Makefile, run:
#
# $ wget 'https://gitlab.com/sequoia-pgp/common-ci/-/raw/main/Makefile?ref_type=heads&inline=false'
#
# To update this Makefile, run:
#
# $ make Makefile

all:
	@echo "Try:"
	@echo "$ make deny"

update: Makefile

.PHONY: deny
deny: deny.toml
	cargo deny check

# The configuration files that we can update.
.PHONY: deny.toml
deny.toml:
	$(call update-file "$@")

# We can also update the Makefile.
Makefile:
	$(call update-file "$@")

# Download the latest version of the configuration file.  If it
# changed, save the old version to $@.bak, and show a diff.
define update-file =
	T=$$(mktemp); \
	wget 'https://gitlab.com/sequoia-pgp/common-ci/-/raw/main/$@?ref_type=heads&inline=false' -O "$$T" \
	&& echo "***************" \
	&& if test -e "$@"; then \
		if ! diff -u "$$T" "$@"; then \
			echo "*** $@ was out of date."; \
			cp "$@" "$@.bak"; \
			echo "(old version saved to $@.bak)"; \
			mv "$$T" "$@"; \
		else \
			echo "$@ was up to date."; \
			rm "$$T"; \
		fi; \
	else \
		echo "Downloaded $@"; \
		mv "$$T" "$@"; \
	fi
endef

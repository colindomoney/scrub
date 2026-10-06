RAYCAST := RaycastExtension

.PHONY: install install-cli install-raycast test

# Rebuild and install the CLI and the Raycast extension.
install: install-cli install-raycast

# Installs to ~/.cargo/bin/scrub, which the Raycast extension calls.
install-cli:
	cargo install --path . --force

# `ray build` also refreshes Raycast's copy in ~/.config/raycast/extensions.
install-raycast: $(RAYCAST)/node_modules
	cd $(RAYCAST) && npm run build

$(RAYCAST)/node_modules: $(RAYCAST)/package-lock.json
	cd $(RAYCAST) && npm install
	touch $@

test:
	cargo test

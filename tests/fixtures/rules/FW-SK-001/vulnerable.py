"""FW-SK-001 vulnerable: all plugins auto-imported without filtering."""

from semantic_kernel import Kernel

kernel = Kernel()

# Bulk import without any function-level filtering
kernel.import_plugin_from_module("my_plugins.search")
kernel.import_native_plugin_from_directory("/opt/plugins")

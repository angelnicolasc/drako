"""FW-SK-001 safe: plugins imported with explicit function filtering."""

from semantic_kernel import Kernel
from my_plugins.search import SearchPlugin

kernel = Kernel()

plugin = SearchPlugin()
kernel.add_plugin(plugin, plugin_name="my_plugin", functions=["safe_func"])

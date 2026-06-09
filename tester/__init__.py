# VF_TESTER Attack Modules
#
# v22: Plugin system auto-discovers modules via PluginRegistry.
# This __init__.py no longer manually imports modules — the registry
# scans the directory and loads any PluginInterface or AttackModule
# subclass it finds. See plugin_system.py for details.
#
# To add a new attack module:
#   1. Create a .py file in this directory (e.g. vf_my_attack.py)
#   2. Define a class inheriting from PluginInterface (or AttackModule for legacy)
#   3. Set the `meta` attribute with PluginMeta(name='my_attack', ...)
#   4. Done! No changes to this file or VF_TESTER.py needed.
#
# The PluginRegistry.discover() call in VF_TESTER.py handles the rest.


from plugin_system import PluginRegistry, PluginInterface, PluginMeta, AttackContext

__all__ = ['PluginRegistry', 'PluginInterface', 'PluginMeta', 'AttackContext']

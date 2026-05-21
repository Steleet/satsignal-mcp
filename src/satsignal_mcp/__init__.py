from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("satsignal-mcp")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

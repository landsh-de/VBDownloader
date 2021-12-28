# VBDownloader (with proxy-support behind firewall)

Simple tool to download files or web-pages with proxy-support and hardened crypto-algorithms.

* This tool is hardened in the usage of its crypto-suites against TLS connections fo web-sites with https-protocol.
* Only "Forward Secrecy" - crypto-suites are used.

* Proxy is supported by using the environment: HTTP_PROXY, HTTPS_PROXY and NO_PROXY (or the lowercase versions thereof).

* HTTPS_PROXY takes precedence over HTTP_PROXY for https requests.

+ For details, look into source-code ... :-)

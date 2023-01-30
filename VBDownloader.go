package main

	// VBDownloader V1.2 by Veit Berwig (20230111)
	//
	// Simple tool to download files or web-pages with proxy-support.
	//
	// This tool is hardened in the usage of its crypto-suites
	// against TLS connections fo web-sites with https-protocol.
	// Only "Forward Secrecy" - crypto-suites are used.
	//
	// Proxy is supported by using the environment: HTTP_PROXY,
	// HTTPS_PROXY and NO_PROXY (or the lowercase versions thereof).
	// HTTPS_PROXY takes precedence over HTTP_PROXY for https
	// requests.
	//
	// ToDo:
	//
	//     - Check for exclusive execution under admin-account
	//       by changing Manifest to "admin".
	//
	// =============================================================
	//
	// Changelog:
	//
	//
	//     20210924:
	//
	//     - Added proxy-support code for custom TLS-transport.
	//
	//     - Fixed an error, where ConnectionState will be read
	//       from "tls.conn" in PROXY-session, when "conn"
	//       may be 0x0 :-(.
	//
	//     - minor changes.
	//
	//
	//     20210927:
	//
	//     - Added certificate serial-number output in logging.
	//
	//     - Added "-proxy" option to force manual-proxy config
	//       for http(s).
	//
	//
	//     20230111:
	//
	//     - Did some code-cleanup and rebuild with Go 1.19.5.
	//
	//     - Tried to find out, why SSLLABS reports an SSLv2 usage,
	//       when doing a client-test under:
	//       https://www.ssllabs.com/ssltest/viewMyClient.html ...
	//       Maybe the test by SSLLABS is incomplete, because the
	//       Go-developers had already disabled SSLv2 and SSLv3 !
	//
	//     - No download will be performed, when no parameters
	//       are provided.
	//
	// =============================================================
	// A list of cipher suite IDs that are, or have been,
	// implemented by "crypto/tls/cipher_suites.go" package.
	// =============================================================
	// See
	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
	// =============================================================
	// TLS 1.2 cipher suites.
	// =============================================================
	// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0xc02f
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       uint16 = 0xc02b
	// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0xc030
	// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       uint16 = 0xc02c
	// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xcca8
	// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xcca9
	// =============================================================
	// TLS 1.3 cipher suites.
	// =============================================================
	// TLS_AES_128_GCM_SHA256                        uint16 = 0x1301
	// TLS_AES_256_GCM_SHA384                        uint16 = 0x1302
	// TLS_CHACHA20_POLY1305_SHA256                  uint16 = 0x1303
	// =============================================================
	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	// TLS_FALLBACK_SCSV uint16 = 0x5600
	//
	// TLS constants
	// =============================================================
	// VersionTLS10 = 0x0301
	// VersionTLS11 = 0x0302
	// VersionTLS12 = 0x0303
	// VersionTLS13 = 0x0304
	// =============================================================
	// Deprecated: SSLv3 is cryptographically broken, and is no longer
	// supported by this package. See golang.org/issue/32716.
	// VersionSSL30 = 0x0300
	// =============================================================

	// TLS-structure from tls.config derived from:
	// https://github.com/denji/golang-tls#perfect-ssl-labs-score-with-go
	// Portions of code derived from:
	// https://github.com/youngkin/gohttps/blob/master/client/client.go

	// (tls.Conn.ConnectionState)
	// https://stackoverflow.com/questions/52298564/transport-options-to-ensure-net-http-client-connect-via-tls-1-2#52299006
	// https://gist.github.com/xjdrew/97be3811966c8300b724deabc10e38e2

	// (Access HTTP response as string in Go)
	// https://stackoverflow.com/questions/38673673/access-http-response-as-string-in-go#38673673

	// Use Mozilla's "certdata.txt" in Go-Code
	// https://github.com/gwatts/rootcerts/blob/master/gencerts/gencerts.go
	// https://github.com/hashicorp/go-rootcerts


	// Help-Sites:
	// https://dlintw.github.io/gobyexample/public/index.html
	// https://golang.hotexamples.com/

	// Tiny filer from:
	// https://github.com/toolkits/file/blob/master/file.go
	// Tiny downloader from:
	// https://github.com/toolkits/file/blob/master/downloader.go
	// Tiny reader
	// https://github.com/toolkits/file/blob/master/reader.go
	// Tiny commands
	// https://github.com/toolkits/sys/blob/master/cmd.go
	// Tiny colorizer
	// https://github.com/toolkits/color/blob/master/color.go
	// example 1
	// https://github.com/youngkin/gohttps/blob/master/client/client.go
	// Url for client test:
	// https://www.ssllabs.com/ssltest/viewMyClient.html
	// https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

import (
    "crypto/tls"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
)

// ==================================================================
// Connection-State
// ==================================================================
func printConnState(conn *tls.Conn) {
	log.Print("------------------- TLS State Info ------------------")
	state := conn.ConnectionState()
	log.Printf("Version...................: %#x", state.Version)
	log.Printf("Check for details.........: \"https://golang.org/src/crypto/tls/common.go\"")
	log.Printf("HandshakeComplete.........: %t", state.HandshakeComplete)
	log.Printf("DidResume.................: %t", state.DidResume)
	log.Printf("CipherSuite...............: %#x", state.CipherSuite)
	log.Printf("Check for details.........: \"https://golang.org/src/crypto/tls/cipher_suites.go\"")
	log.Printf("NegotiatedProtocol........: %s", state.NegotiatedProtocol)
	log.Printf("NegotiatedProtocolIsMutual: %t", state.NegotiatedProtocolIsMutual)
	log.Print("Certificate chain:")
	for i, cert := range state.PeerCertificates {
    subject := cert.Subject
    issuer := cert.Issuer
    serial := cert.SerialNumber
		log.Printf(" %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", i, subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
		log.Printf("   i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)
		log.Printf("   SerialNumber: %#x", serial)
	}
	log.Print("----------------- TLS State Info End ----------------")
}

// ==================================================================
// Download
// ==================================================================
func Download(tofile, url string) error {
    var (
        conn *tls.Conn
        err  error
    )

    // ==============================================================
    // Configure TLS
    // https://pkg.go.dev/crypto/tls#Config
    // ==============================================================
    conf := &tls.Config{
					// https://cs.opensource.google/go/go/+/refs/tags/go1.19.5:src/crypto/tls/common.go
					InsecureSkipVerify: false,
					// RootCAs: ServerCertPool(),
					MinVersion: tls.VersionTLS12,
                    MaxVersion: tls.VersionTLS13,
					CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP521, tls.CurveP384, tls.CurveP256},
                    // PreferServerCipherSuites is a legacy field and has no effect.
                    // It used to control whether the server would follow the client's or the
                    // cipher suite based on logic that takes into account inferred client
                    // hardware, server hardware, and security.
                    // Deprecated: PreferServerCipherSuites is ignored.
					PreferServerCipherSuites: false,
                    //
                    // ### CipherSuites ###
                    // CipherSuites is a list of enabled TLS 1.0–1.2 cipher suites. The order of
                    // the list is ignored. Note that TLS 1.3 ciphersuites are not configurable.
                    // https://cs.opensource.google/go/go/+/refs/tags/go1.19.5:src/crypto/tls/cipher_suites.go
					// https://pkg.go.dev/crypto/tls#Config
					CipherSuites: []uint16{
					tls.TLS_CHACHA20_POLY1305_SHA256,                   // TLS 1.3 cipher suites.
					tls.TLS_AES_256_GCM_SHA384,                         // TLS 1.3 cipher suites.
					tls.TLS_AES_128_GCM_SHA256,                         // TLS 1.3 cipher suites.
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,  // TLS 1.2 cipher suites.
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,    // TLS 1.2 cipher suites.
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,  // TLS 1.2 cipher suites.
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,    // TLS 1.2 cipher suites.
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,        // TLS 1.2 cipher suites.
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,          // TLS 1.2 cipher suites.
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,        // TLS 1.2 cipher suites.
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,          // TLS 1.2 cipher suites.
					},
	}

    // ==============================================================
    // Create target-ile
    // ==============================================================
    out, err := os.Create(tofile)
    if err != nil {
      return err
    }
    defer out.Close()

    // ==============================================================
    // Construct transport
    // ==============================================================
    // Make use of "ProxyFromEnvironment" for custom transports
    // https://pkg.go.dev/net/http#ProxyFromEnvironment
    // https://stackoverflow.com/questions/51845690/how-to-program-go-to-use-a-proxy-when-using-a-custom-transport#53202838
    var PTransport = & http.Transport{
        Proxy: http.ProxyFromEnvironment,
        DialTLS: func(network, addr string) (net.Conn, error) {
            // https://pkg.go.dev/crypto/tls#example-Dial
            conn, err = tls.Dial(network, addr, conf)
            return conn, err
        },
    }
	if err != nil {
		log.Printf("Error processing Tls-Dialer !")
    log.Fatal(err)
		conn.Close()
		os.Exit(1)
  }

  // ==============================================================
  // Construct http-client
  // ==============================================================
  c := &http.Client{
  Transport: PTransport,
  }

  // ==============================================================
  // GET file (URL)
  // ==============================================================
  resp, err := c.Get(url)
  if err != nil {
          log.Printf("Error processing Url for download:")
          log.Printf(" ===> %s", url)
          log.Fatal(err)
  } else {
          log.Printf("Processing download, using url:")
          log.Printf(" ===> %s", resp.Request.URL)
  }
  defer resp.Body.Close()

  if conn != nil {
      printConnState(conn)
  }

  // ==============================================================
  // Copy to target-file
  // ==============================================================
  _, err = io.Copy(out, resp.Body)
  return err
}


// ==================================================================
// MAIN
// ==================================================================
func main() {

	Myhelp   := flag.Bool("help", false, "Optional, prints usage info.")
	Myver    := flag.Bool("version", false, "Optional, prints version info.")
	// Myurl    := flag.String("url", "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt", "The url for the download.")
	// Mytofile := flag.String("tofile", "certdata.txt", "The local name for the download.")
	Myurl    := flag.String("url", "", "The url for the download.")
	Mytofile := flag.String("tofile", "", "The local name for the download.")
	Myproxy  := flag.String("proxy", "", "The proxy-server to use for the download.")
	Mywd     := flag.String("wd", "", "Set current working-directory (for file-operations).")

	flag.Parse()

	usage    := `Usage:

vbdownloader -url <download-url> -tofile <local-file> -help -version -proxy

Options:
  -help     Optional, Prints this message.
  -version  Optional, Prints the version info.
  -url      Optional, The url for the download.
  -tofile   Optional, The local filename for the download.
  -proxy    Optional, The proxy-server to use for the download.
  -wd       Optional, Set current working-directory (for file-operations).
`
	version  := `Version:

VBDownLoader version 1.2 by veit berwig (2023 ZIT-SH)
VBDownLoader is using hardened Cypher-Suites for TLS.
Check it out: use url ...
1) https://clienttest.ssllabs.com/ssltest/viewMyClient.html
   and download to "MyClient.html" and open file in Browser, or
2) https://www.howsmyssl.com/a/check
   and download to "HowsMySSL.json" and open file in Browser.

Proxy is supported by using the environment or commandline:
HTTP_PROXY, HTTPS_PROXY and NO_PROXY (or lowercase versions).
HTTPS_PROXY takes precedence over HTTP_PROXY for https requests.

Options:
  -help     Optional, Prints this message.
  -version  Optional, Prints the version info.
  -url      Optional, The url for the download.
  -tofile   Optional, The local filename for the download.
  -proxy    Optional, The proxy-server to use for the download.
  -wd       Optional, Set current working-directory (for file-operations).
`
    Myversion := `VBDownLoader version 1.2 by veit berwig (2023 ZIT-SH)`

    fmt.Println("=====================================================================")
    fmt.Println(Myversion)
    fmt.Println("=====================================================================")

	if *Myhelp == true {
			fmt.Println(usage)
			return
	}

	if *Myver == true {
			fmt.Println(version)
			return
	}

	if *Myurl == "" {
		log.Fatalf("The \"url\" parameter is required but missing:\n%s", usage)
	}

	if *Mytofile == "" {
		log.Fatalf("The \"tofile\" parameter is required but missing:\n%s", usage)
	}

	if *Myproxy != "" {
        os.Setenv("HTTP_PROXY", *Myproxy)
        os.Setenv("HTTPS_PROXY", *Myproxy)
        log.Printf("Using proxy-server: \"%s\" ...", *Myproxy)
	}
    // Change working-directory, when provided
	if *Mywd != "" {
        err := os.Chdir(*Mywd)
        if err != nil {
            log.Fatalf("Error, using the prvided working-directory:\n%s", err)
        }
	}
  // Get and print current working-directory ...
  MyDir, err := os.Getwd()
  if err != nil {
      log.Fatalf("Error, getting the current directory:\n%s", err)
  }
  log.Printf("Current Working Direcotry:")
  log.Printf("%s", MyDir)

  // ==============================================================
  // Download file
  // ==============================================================
  Myerr := Download(*Mytofile, *Myurl)
  if Myerr != nil {
      log.Printf("Error processing Download to file:")
      log.Printf(" ===> \"%s\" ...", *Mytofile)
      log.Fatal(err)
      os.Exit(1)
  } else {
      log.Printf("It seems to be, that processing download to file:")
      log.Printf(" ===> \"%s\" went fine ...", *Mytofile)
      os.Exit(0)
	}
}
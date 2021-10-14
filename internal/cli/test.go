package cli

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

var flagTestPort = flag.Int("testPort", 8443, "port for test server")

func Test() {

	config, err := GetConfig()
	if err != nil {
		log.Fatal("Config error: ", err)
	}

	cert, err := config.ReadCertificate()
	if err != nil {
		log.Fatal("Error reading certificate: ", err)
	}
	domain := strings.TrimPrefix(cert.Subject.CommonName, "*.")
	url := fmt.Sprintf("https://localhost.%s:%d", domain, *flagTestPort)
	fmt.Print("Serving test page at:\n\n", url, "\n\n")

	http.HandleFunc("/", handleTest)
	addr := fmt.Sprintf(":%d", *flagTestPort)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Error listening to %s: %v", addr, err)
		}
		wg.Done()
		log.Fatal(http.ServeTLS(l, nil, config.CertificateFile, config.KeyFile))
	}()
	wg.Wait()

	fmt.Println("Sending self-test request...")
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal("Error reading response body: ", err)
	}
	fmt.Printf("Response: %q\n\n", body)

	fmt.Println("You can test in a browser now or Ctrl-C to exit.")
	<-(chan struct{})(nil)
}

func handleTest(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("It worked!"))
}

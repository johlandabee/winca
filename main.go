package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/Azure/go-ntlmssp"
	"github.com/teris-io/cli"
)

const (
	derFormat    = "bin"
	base64Format = "b64"
)

// Credentials is a simple combination of username + password
type Credentials struct {
	Username string
	Password string
}

// HTTPClient is a http.Client interface
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DownloadCertificate download a previously requested certificate
func DownloadCertificate(client HTTPClient, id int, baseURL string, cred *Credentials) ([]byte, error) {
	downloadURL := fmt.Sprintf("%s/certnew.cer?ReqID=%d&Enc%s", baseURL, id, base64Format)

	req, newRequestError := http.NewRequest("GET", downloadURL, nil)
	if newRequestError != nil {
		return nil, newRequestError
	}

	req.SetBasicAuth(cred.Username, cred.Password)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Could not download certificate: " + resp.Status)
	}

	defer resp.Body.Close()

	cert, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func findRequestID(str string) int {
	re := regexp.MustCompile(`ReqID=(\d+)`)
	match := re.FindStringSubmatch(str)
	if match == nil {
		return 0
	}

	idStr := match[1]
	id, _ := strconv.ParseInt(idStr, 10, 32)

	return int(id)
}

// RequestCertificate Request a new certificate from a windows CA using the 'certsrv' API
func RequestCertificate(client HTTPClient, baseURL string, tpl string, csr []byte, cred *Credentials) (int, error) {
	urlData := url.Values{}
	urlData.Add("Mode", "newreq")
	urlData.Add("CertRequest", string(csr))
	urlData.Add("CertAttrib", "CertificateTemplate:"+tpl)
	urlData.Add("TargetStoreFlags", "0")
	urlData.Add("SaveCert", "no")

	urlDataEnc := urlData.Encode()
	reader := strings.NewReader(urlDataEnc)

	req, newRequestError := http.NewRequest("POST", baseURL+"/certfnsh.asp", reader)
	if newRequestError != nil {
		return 0, newRequestError
	}

	req.SetBasicAuth(cred.Username, cred.Password)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	bodyStr := string(bodyBytes)

	if resp.StatusCode != http.StatusOK {
		return 0, errors.New("Could not request certificate. Status code " + resp.Status + "\n" + bodyStr)
	}

	id := findRequestID(bodyStr)
	if id == 0 {
		return 0, errors.New("Could not find request id in response body\n" + bodyStr)
	}

	return int(id), nil
}

func writeCertificate(path string, cert []byte) error {
	return ioutil.WriteFile(path, cert, 0644)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func getCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	check(err)

	password := string(bytePassword)

	fmt.Println()

	return strings.TrimSpace(username), strings.TrimSpace(password)
}

// LoadCsr load and validate a OpenSSL CSR from the filesystem
func LoadCsr(path string) ([]byte, error) {
	dat, ioErr := ioutil.ReadFile(path)
	if ioErr != nil {
		return nil, ioErr
	}

	block, rest := pem.Decode(dat)
	if len(rest) > 0 {
		return nil, fmt.Errorf("Could not PEM decode CSR. Rest found: %s", string(rest))
	}

	_, parseErr := x509.ParseCertificateRequest(block.Bytes)
	if parseErr != nil {
		return nil, parseErr
	}

	return dat, nil
}

func getCertificateAction(args []string, options map[string]string) int {
	csr, loadCsrErr := LoadCsr(args[0])
	check(loadCsrErr)

	out, url, tpl := args[1], args[2], args[3]
	username, password := options["username"], options["password"]

	if username == "" || password == "" {
		username, password = getCredentials()
	}

	cred := &Credentials{Username: username, Password: password}

	skipVerify, _ := strconv.ParseBool(options["skipVerify"])
	tr := ntlmssp.Negotiator{
		RoundTripper: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
		},
	}

	client := &http.Client{Transport: tr}

	fmt.Println("Requesting certificate...")

	id, requestErr := RequestCertificate(client, url, tpl, csr, cred)
	check(requestErr)

	fmt.Printf("Issued request with ID %d\n", id)
	fmt.Printf("Downloading certificate to %s\n", out)

	cert, downloadErr := DownloadCertificate(client, id, url, cred)
	check(downloadErr)

	err := writeCertificate(out, cert)
	check(err)

	return 0
}

func main() {
	get := cli.NewCommand("get", "Get a new certificate").WithShortcut("g").
		WithArg(cli.NewArg("csrPath", "A path to an existing CSR file on disk")).
		WithArg(cli.NewArg("outPath", "The certificate output path")).
		WithArg(cli.NewArg("apiUrl", "The api url")).
		WithArg(cli.NewArg("template", "The certificate template to use")).
		WithOption(cli.NewOption("username", "The user context to issue the certificate with").WithChar('u')).
		WithOption(cli.NewOption("password", "The password").WithChar('p')).
		WithOption(cli.NewOption("skipVerify", "Skip SSL verification").WithType(cli.TypeBool)).
		WithAction(getCertificateAction)

	app := cli.New("Request and download a new certificate from a Windows CA").
		WithCommand(get)

	os.Exit(app.Run(os.Args, os.Stdout))
}

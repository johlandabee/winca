package main

import (
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockHTTPClient struct {
	TestDocument string
	StatusCode   int
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.TestDocument == "" {
		return &http.Response{
			StatusCode: m.StatusCode,
		}, nil
	}

	reader, _ := os.Open(m.TestDocument)
	return &http.Response{
		Body:       ioutil.NopCloser(reader),
		StatusCode: m.StatusCode,
	}, nil
}

func TestRequestCertificate_404ErrorHandling(t *testing.T) {
	client := &MockHTTPClient{
		TestDocument: "test/response/error_404.html",
		StatusCode:   404,
	}

	var csr []byte
	id, err := RequestCertificate(client, "", "", csr, &Credentials{})

	assert.Equal(t, id, 0)
	assert.Error(t, err)
}

func TestRequestCertificate_ErrorInvalidTemplateHandling(t *testing.T) {
	client := &MockHTTPClient{
		TestDocument: "test/response/error_invalid_template.html",
		StatusCode:   200,
	}

	var csr []byte
	id, err := RequestCertificate(client, "", "", csr, &Credentials{})

	assert.Equal(t, id, 0)
	assert.Error(t, err)
}

func TestRequestCertificate_Success(t *testing.T) {
	client := &MockHTTPClient{
		TestDocument: "test/response/success.html",
		StatusCode:   200,
	}

	var csr []byte
	id, err := RequestCertificate(client, "", "", csr, &Credentials{})

	assert.Equal(t, id, 1437)
	assert.NoError(t, err)
}

func TestDownloadCertificate_NonOkStatus(t *testing.T) {
	client := &MockHTTPClient{
		StatusCode: 500,
	}

	cert, err := DownloadCertificate(client, 0, "", &Credentials{})

	assert.Nil(t, cert)
	assert.Error(t, err)
}

func TestDownloadCertificate_Success(t *testing.T) {
	client := &MockHTTPClient{
		TestDocument: "test/no_cert.txt",
		StatusCode:   200,
	}

	cert, err := DownloadCertificate(client, 0, "", &Credentials{})

	assert.Equal(t, string(cert), "--- I'M NOT A CERTIFICATE ---")
	assert.NoError(t, err)
}

func TestLoadCsr_ErrorOnNonExistentFile(t *testing.T) {
	csr, err := LoadCsr("test/nonexistent.txt")

	assert.Nil(t, csr)
	assert.Error(t, err)
}

func TestLoadCsr_ErrorOnInvalidCSR(t *testing.T) {
	csr, err := LoadCsr("test/csr/no_csr.txt")

	assert.Nil(t, csr)
	assert.Error(t, err)
}

func TestLoadCsr_ErrorOnTruncatedCSR(t *testing.T) {
	csr, err := LoadCsr("test/csr/bad_csr.txt")

	assert.Nil(t, csr)
	assert.Error(t, err)
}

func TestLoadCsr_Success(t *testing.T) {
	csr, err := LoadCsr("test/csr/good_csr.txt")

	assert.NotNil(t, csr)
	assert.NoError(t, err)
}

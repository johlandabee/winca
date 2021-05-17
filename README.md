# Windows Certificate Authority CLI

## About

A simple command line utility to request and download a new certificate using a OpenSSL CSR against a standard Windows Server CA.

Works great with Ansible.

## Usage

Print the help page with `winca get -h`:

````bash
winca get [--username=string] [--password=string] [--skipVerify] <csrPath> <outPath> <apiUrl> <template>

Description:
    Get a new certificate

Arguments:
    csrPath            A path to an existing CSR file on disk
    outPath            The certificate output path
    apiUrl             The api url
    template           The certificate template to use

Options:
    -u, --username     The user context to issue the certificate with
    -p, --password     The password
        --skipVerify   Skip SSL verification
````

### Example

````bash
# 1) Create a new CSR and private key using OpenSSL
openssl req -nodes -new -newkey rsa:2048 -sha256 -out csr.pem

# 2) Use winca to download a new certificate. It will ask for your <domain>\<username> and password.
winca get csr.pem mycert.crt https://mywindowsca/certsrv MyCertificateTemplate

# 3) You should now have a valid certificate singed by My CA. You can verify it using the command below
openssl x509 -in mycert.crt -text -noout
````

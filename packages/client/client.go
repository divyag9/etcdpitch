package client

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	etcdclient "github.com/coreos/etcd/client"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// Etcd has all the information required to connect to etcd and openpgp entity
type Etcd struct {
	endpoints     []string
	httpTransport *http.Transport
	entity        *openpgp.Entity
	keyapi        etcdclient.KeysAPI
}

//GetEndpoints returns list of end points retrieved from srv record
func (e *Etcd) GetEndpoints(service, proto, domain string) error {
	_, addrs, err := net.LookupSRV(service, proto, domain)
	if err != nil {
		return err
	}
	var urls []*url.URL
	for _, srv := range addrs {
		urls = append(urls, &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(srv.Target, fmt.Sprintf("%d", srv.Port)),
		})
	}
	e.endpoints = make([]string, len(urls))
	for i := range urls {
		e.endpoints[i] = urls[i].String()
	}
	fmt.Println("endpoints: ", e.endpoints)

	return nil
}

//GetHTTPTransport http transport for the cert and key
func (e *Etcd) GetHTTPTransport(certFilePath, keyFilePath string) error {
	if certFilePath == "" || keyFilePath == "" {
		return errors.New("Require both cert and key path")
	}

	// Check if the cert and key files exists
	if _, err := os.Stat(certFilePath); os.IsNotExist(err) {
		return fmt.Errorf("Cert file %s does not exist", certFilePath)
	}

	if _, err := os.Stat(keyFilePath); os.IsNotExist(err) {
		return fmt.Errorf("Key file %s does not exist", keyFilePath)
	}

	tlsCert, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		return err
	}
	certx509, _ := ioutil.ReadFile(certFilePath)

	block, _ := pem.Decode([]byte(certx509))
	certTest, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	privateKeyTest := tlsCert.PrivateKey

	// Create the Entity based on the cert and key provided
	config := &packet.Config{}
	config.DefaultCompressionAlgo = 1
	config.DefaultCipher = 9
	config.DefaultHash = 3
	e.entity, _ = openpgp.NewEntity("", "", "", config)
	e.entity.PrimaryKey.PubKeyAlgo = 1
	e.entity.PrimaryKey.PublicKey = (certTest.PublicKey).(*rsa.PublicKey)
	e.entity.PrivateKey.PrivateKey = privateKeyTest.(*rsa.PrivateKey)
	e.entity.PrivateKey.PublicKey.PubKeyAlgo = 1
	e.entity.PrivateKey.PublicKey.PublicKey = (certTest.PublicKey).(*rsa.PublicKey)

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
	}
	e.httpTransport = &http.Transport{
		TLSClientConfig: tlsConfig,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
	}

	return nil
}

// NewEtcd creates Etcd struct required for connecting to etcd and setting/getting key value
func NewEtcd(service, proto, domain, cert, key string) (*Etcd, error) {
	etcd := &Etcd{}
	err := etcd.GetEndpoints(service, proto, domain)
	if err != nil {
		return nil, err
	}
	err = etcd.GetHTTPTransport(cert, key)
	if err != nil {
		return nil, err
	}

	cfg := etcdclient.Config{
		Endpoints: etcd.endpoints,
		Transport: etcd.httpTransport,
		// set timeout per request to fail fast when the target endpoint is unavailable
		HeaderTimeoutPerRequest: time.Second,
	}
	cli, err := etcdclient.New(cfg)
	if err != nil {
		return nil, err
	}
	etcd.keyapi = etcdclient.NewKeysAPI(cli)

	return etcd, nil
}

// EncryptValue encrypts the value corresponding to the key
func EncryptValue(encryptionValue string, entity *openpgp.Entity) (*bytes.Buffer, error) {
	enlist := make(openpgp.EntityList, 1)
	enlist[0] = entity
	encryptionType := "PGP MESSAGE"

	encbuf := bytes.NewBuffer(nil)
	w, err := armor.Encode(encbuf, encryptionType, nil)
	if err != nil {
		return nil, err
	}

	plaintext, err := openpgp.Encrypt(w, enlist, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	message := []byte(encryptionValue)
	_, err = plaintext.Write(message)

	plaintext.Close()
	w.Close()
	fmt.Printf("Encrypted:\n%s\n", encbuf)
	return encbuf, nil
}

// DecryptValue decrypts the pgp message using the entitylist
func DecryptValue(encryptedMessage string, entity *openpgp.Entity) (string, error) {

	decbuf := bytes.NewBuffer([]byte(encryptedMessage))
	result, err := armor.Decode(decbuf)
	if err != nil {
		return "", err
	}

	enlist := make(openpgp.EntityList, 1)
	enlist[0] = entity

	md, err := openpgp.ReadMessage(result.Body, enlist, nil, nil)
	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	fmt.Printf("Decrypted:\n%s\n", string(bytes))

	return string(bytes), nil
}

// SetEtcdKey sets the value provided for the key
func SetEtcdKey(etcd *Etcd, key string, value string) error {
	encryptedValue, err := EncryptValue(value, etcd.entity)
	if err != nil {
		return err
	}
	resp, err := etcd.keyapi.Set(context.Background(), key, encryptedValue.String(), nil)
	if err != nil {
		return err
	}
	if resp != nil {
		// print common key info
		fmt.Printf("Set is done. Metadata is %q\n", resp)
		fmt.Println("pgp value: ", resp.Node.Value)
	}
	return nil
}

// GetEtcdValue retrieves value for a requested key
func GetEtcdValue(etcd *Etcd, key string) (string, error) {
	resp, err := etcd.keyapi.Get(context.Background(), key, nil)
	if err != nil {
		return "", err
	}
	if resp != nil {
		// print common key info
		fmt.Printf("Get is done. Metadata is %q\n", resp)
		fmt.Println("pgp value: ", resp.Node.Value)
		decryptedValue, err := DecryptValue(resp.Node.Value, etcd.entity)
		if err != nil {
			return "", err
		}
		return decryptedValue, nil
	}
	return "", nil
}

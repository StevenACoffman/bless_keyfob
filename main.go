package main

import (
	"os"
	"io/ioutil"
	"time"
	"golang.org/x/crypto/ssh"
	"net"
	"golang.org/x/crypto/ssh/agent"
	"crypto/rsa"
	"errors"
	"log"
	"encoding/pem"
	"crypto/x509"
)

func main() {

	myIP := getMyIP()

	log.Println("Got IP")
	pubKey, pubKeyErr := getPublicKey("bless_rsa")
	log.Println("Got PublicKey")
	if pubKeyErr != nil {
		log.Fatalf("PublicKey error %v", pubKeyErr	)
	}

	privKey, privKeyErr := getPrivateKey("bless_rsa")
	log.Println("Got PrivateKey")
	if privKeyErr != nil {
		log.Fatalf("PrivateKey error %v", privKeyErr	)
	}
	blessCert, blessCertErr := getValidBlessCert("bless_rsa", myIP)
	log.Println("Got BlessCert")
	if blessCertErr != nil {
		removeKey(pubKey)
		log.Println("Removed Blessed Public Key from SSH Agent")
	} else {
		addKey(privKey, blessCert)
		log.Println("Added Blessed Public Key to SSH Agent")
	}
}

func getPublicKey(rootKeyName string) ( ssh.PublicKey,  error){

	bytes, err := ioutil.ReadFile(os.Getenv("HOME") + "/.ssh/"+rootKeyName+".pub")
	if err != nil {
		log.Fatalf("Fatal error trying to read public key file: %s", err)
		return nil, errors.New("fatal error trying to read public key file")
	}
	newAuthorizedKey, _, _, _, err := ssh.ParseAuthorizedKey(bytes)
	return newAuthorizedKey, err
}

func getPrivateKey(rootKeyName string) ( *rsa.PrivateKey,  error){

	bytes, err := ioutil.ReadFile(os.Getenv("HOME") + "/.ssh/"+rootKeyName)
	if err != nil {
		log.Fatalf("Fatal error trying to read private key file: %s", err)
		return nil, errors.New("unable to get Private Key")
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(bytes)
	if block == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
		return nil, errors.New("unable to get Private Key")
	}
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		log.Fatalf("unknown key type %q, want %q", got, want)
		return nil, errors.New("unable to get Private Key")
	}

	// Decode the RSA private key
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func getValidBlessCert(rootKeyName string, currentIP string) (*ssh.Certificate, error) {
	// read in public key from file
	bytes, err := ioutil.ReadFile(os.Getenv("HOME") + "/.ssh/"+rootKeyName+"-cert.pub")
	if err != nil {
		log.Fatalf("Fatal error trying to read Bless Certificate file: %s", err)
		return nil, errors.New("unable to get Bless Certificate")
	}
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(bytes)
	if err != nil {
		log.Fatalf("Fatal error trying to parse Bless Cert: %s", err)
		return nil, errors.New("unable to parse Bless Cert:")
	}

	cert, ok := pubkey.(*ssh.Certificate)

	if !ok {
		log.Fatalf("got %v (%T), want *Certificate", pubkey, pubkey)
		return nil, errors.New("Unable to get Bless Cert")
	}

	now := time.Now()
	unixNow := now.Unix()

	const CertTimeInfinity = 1<<64 - 1

	sourceAddress := cert.CriticalOptions["source-address"]

	if currentIP != sourceAddress{
		log.Print("MyIP %v does not match Source Address %v", currentIP, sourceAddress)
		return nil, errors.New("Current IP "+currentIP+" does not match Bless Cert Source Address "+sourceAddress)
	}

	if after := int64(cert.ValidAfter); after < 0 || unixNow < int64(cert.ValidAfter) {
		log.Print("ssh: cert is not yet valid")
		return nil, errors.New("ssh: cert is not yet valid")
	}

	if before := int64(cert.ValidBefore); cert.ValidBefore != uint64(CertTimeInfinity) && (unixNow >= before || before < 0) {
		log.Print("ssh: cert has expired")
		return nil, errors.New("ssh: cert has expired")
	}

	return cert, nil
}


func getMyIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("Oops: " + err.Error() + "\n")
		os.Exit(1)
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func addKey( key *rsa.PrivateKey, cert *ssh.Certificate) {
	if key == nil {
		return
	}
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Fatalf("Unable to connect to SSH Agent %v", err)
	}
	defer conn.Close()
	agentClient := agent.NewClient(conn)

	err = agentClient.Add(agent.AddedKey{
		PrivateKey: key,
		Certificate: cert,
		LifetimeSecs: 14440,
	})
	if err != nil {
		log.Fatalf("failed to add key: %v", err)
	}
}

func removeKey(key ssh.PublicKey) {
	if key == nil {
		log.Fatalf("Unable to Remove Empty Key")
		return
	}
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Fatalf("Unable to remove Key")
	}
	defer conn.Close()
	agentClient := agent.NewClient(conn)

	err = agentClient.Remove(key)
	if err != nil {
		log.Print("failed to remove key %q: %v", key, err)
	}
}

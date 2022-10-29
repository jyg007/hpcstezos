package main

import (
	yaml "gopkg.in/yaml.v2"
	"crypto/x509"
	"io/ioutil"
	"google.golang.org/grpc/credentials"
	grpc "google.golang.org/grpc"
	"crypto/tls"
	"fmt"
	pb "hpcstezos/grpc"
)

var yamlConfig, _ = ioutil.ReadFile("credential.yaml")

var m = make(map[interface{}]interface{})
var err = yaml.Unmarshal([]byte(yamlConfig), &m)

var conn *grpc.ClientConn

var (
    crt = m["cert_path"].(string)
    key = m["key_path"].(string)
    ca  = m["cacert_path"].(string)
)

var certificate, _ = tls.LoadX509KeyPair(crt, key)
var certPool = x509.NewCertPool()
var cacert, _ = ioutil.ReadFile(ca)

func getAddress() string {
	return m["url"].(string)
}


func getCertPool() (*x509.CertPool) {
	certPool.AppendCertsFromPEM(cacert)
	return certPool
}

var creds = credentials.NewTLS(&tls.Config{
    ServerName:   getAddress(),
    Certificates: []tls.Certificate{certificate},
    RootCAs:      getCertPool(),
})

func getCallOpts() ([]grpc.DialOption) {
	return 	[]grpc.DialOption{
        //grpc.WithInsecure(),
        grpc.WithTransportCredentials(creds),
	}
}

func getGrep11Server() (pb.CryptoClient) {
	var err error
	conn, err = grpc.Dial(getAddress(), getCallOpts()...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	//defer conn.Close()
	return pb.NewCryptoClient(conn)
}

func disconnectGrep11Server() {
	conn.Close()
}

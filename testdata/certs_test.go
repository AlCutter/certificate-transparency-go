// Copyright 2016 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testdata_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func buildCA() ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	caKey := generateKey()
	caCert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Certificate Transparency CA"},
			Country:      []string{"GB"},
			Province:     []string{"Sussex"},
			Locality:     []string{"Fletching"},
		},
		SerialNumber:          big.NewInt(1234),
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 10),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caRaw, err := x509.CreateCertificate(rand.Reader, caCert, caCert, caKey.Public(), caKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caRaw}), caCert, caKey
}

func buildPrecert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey) {
	key := generateKey()
	ctPoison := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
		Critical: true,
	}
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Certificate Transparency Precert"},
			Country:      []string{"GB"},
			Province:     []string{"Sussex"},
			Locality:     []string{"Fletching"},
		},
		SerialNumber:          big.NewInt(5678),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		Extensions:            []pkix.Extension{ctPoison},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, cert, caCert, key.Public(), caKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), key
}

func buildPrecertSCT(precert *x509.Certificate, logSign *ecdsa.PrivateKey) []byte {

}

// TestRegenerateCerts can be used to rebuild all the certificate test data
// held in certs.go
func TestRegenerateCerts(t *testing.T) {
	caPEM, caCert, caKey := buildCA()
	t.Logf("\nCACertPEM = \"%s\"", string(caPEM))

	precertPEM, _ := buildPrecert(caCert, caKey)
	t.Logf("\nTestPreCertPEM = \"%s\"", string(precertPEM))

	logKey := generateKey()
	logPublicKeyDER, err := x509.MarshalPKIXPublicKey(logKey.Public())
	if err != nil {
		panic(err)
	}
	logPublicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: logPublicKeyDER})
	t.Logf("\nLogPublicKeyPEM = \"%s\"", string(logPublicKeyPEM))
}

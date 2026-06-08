package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// generateTestCerts creates a self-signed certificate and private key for testing.
// It returns the file paths to the cert and key.
func generateTestCerts(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"FlowLens Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file for cert: %v", err)
	}
	defer certOut.Close()
	if encodeErr := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); encodeErr != nil {
		t.Fatalf("Failed to write data to cert.pem: %v", encodeErr)
	}

	keyOut, err := os.CreateTemp("", "key-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file for key: %v", err)
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("Failed to write data to key.pem: %v", err)
	}

	return certOut.Name(), keyOut.Name()
}

func TestServer_StartStop(t *testing.T) {
	// Use a specific local port for testing.
	testListen := "127.0.0.1:28491"
	cfg := config.WebConfig{Listen: testListen, PageSize: 10}
	ringBuf := storage.NewRingBuffer(100)
	s := NewServer(cfg, ringBuf, nil, "", nil, nil, nil, nil)

	s.Mux().HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()

	// Wait for the server to start
	time.Sleep(200 * time.Millisecond)

	// Test the server is running
	resp, err := http.Get("http://" + testListen + "/ping")
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	if string(body) != "pong" {
		t.Errorf("Expected body 'pong', got %q", string(body))
	}

	// Stop the server
	if err := s.Stop(); err != nil {
		t.Fatalf("Failed to stop server: %v", err)
	}

	// Wait for Start to return
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Start returned unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestServer_StartStopTLS(t *testing.T) {
	certPath, keyPath := generateTestCerts(t)
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	testListen := "127.0.0.1:28492"
	cfg := config.WebConfig{
		Listen:   testListen,
		PageSize: 10,
		TLSCert:  certPath,
		TLSKey:   keyPath,
	}
	ringBuf := storage.NewRingBuffer(100)
	s := NewServer(cfg, ringBuf, nil, "", nil, nil, nil, nil)

	s.Mux().HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()

	// Wait for the server to start
	time.Sleep(200 * time.Millisecond)

	// Create a client that skips verification for the self-signed cert
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Test the server is running over HTTPS
	resp, err := client.Get("https://" + testListen + "/ping")
	if err != nil {
		t.Fatalf("Failed to connect to TLS server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.StatusCode)
	}

	// Test that HTTP fails
	resp, err = http.Get("http://" + testListen + "/ping")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("Expected HTTP request to TLS server to fail or return non-OK status, got OK")
		}
	}

	// Stop the server
	if err := s.Stop(); err != nil {
		t.Fatalf("Failed to stop server: %v", err)
	}

	// Wait for Start to return
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Start returned unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestStaticFileSystem(t *testing.T) {
	// 1. Test with an existing directory
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(testFile, []byte("hello"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	fs1 := staticFileSystem(tempDir)
	f1, err := fs1.Open("test.txt")
	if err != nil {
		t.Errorf("Failed to open file from staticFileSystem with dir: %v", err)
	} else {
		f1.Close()
	}

	// 2. Test with a non-existing directory (should fallback to embedded FS)
	fs2 := staticFileSystem("/does/not/exist/surely")
	// Embedded static filesystem might have things like "css", "js", let's try to open root or a known directory if possible, but actually we can just check it doesn't crash.
	// Since we know "css" is in static/, let's try to open "css" or just "."
	f2, err := fs2.Open(".")
	if err != nil {
		t.Errorf("Failed to open root from fallback staticFileSystem: %v", err)
	} else {
		f2.Close()
	}

	// 3. Test with an empty string
	fs3 := staticFileSystem("")
	f3, err := fs3.Open(".")
	if err != nil {
		t.Errorf("Failed to open root from fallback staticFileSystem (empty dir): %v", err)
	} else {
		f3.Close()
	}
}

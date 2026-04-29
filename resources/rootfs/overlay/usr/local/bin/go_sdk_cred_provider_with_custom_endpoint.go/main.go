package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
)

const mmdsBaseUrl = "http://169.254.169.254"

func main() {
	// Get MMDS token
	token, err := getMmdsToken()
	if err != nil {
		log.Fatalf("Failed to get MMDS token: %v", err)
	}

	// Construct a client
	client := &http.Client{
		Transport: &tokenInjector{
			token: token,
			next: &loggingRoundTripper{
				next: http.DefaultTransport,
			},
		},
	}

	// Construct a credential provider
	endpoint := fmt.Sprintf("%s/latest/meta-data/iam/security-credentials/role", mmdsBaseUrl)
	provider := endpointcreds.New(endpoint, func(o *endpointcreds.Options) {
		o.HTTPClient = client
	})

	// Load config with the custom provider
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithCredentialsProvider(provider),
	)
	if err != nil {
		log.Fatalf("Unable to load config: %v", err)
	}

	// Retrieve credentials
	cred, err := cfg.Credentials.Retrieve(context.TODO())
	if err != nil {
		log.Fatalf("Unable to retrieve credentials: %v", err)
	}

	fmt.Printf("%v,%v,%v\n", cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
}

func getMmdsToken() (string, error) {
	client := &http.Client{}

	// Construct a request
	req, err := http.NewRequest("PUT", mmdsBaseUrl + "/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("x-aws-ec2-metadata-token-ttl-seconds", "21600")

	// Log the request
	dumpReq, err := httputil.DumpRequest(req, true)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "REQUEST:\n%s\n", dumpReq)

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Log the response
	dumpResp, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "RESPONSE:\n%s\n", dumpResp)

	// Check the response status code.
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Status: %s", resp.Status)
	}

	// Read the body
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body), nil
}

// tokenInjector adds the token header on every metadata request
type tokenInjector struct {
	token string
	next http.RoundTripper
}

func (t *tokenInjector) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("x-aws-ec2-metadata-token", t.token)
	return t.next.RoundTrip(req)
}

// logginRoundTripper logs requests and responses
type loggingRoundTripper struct {
	next http.RoundTripper
}

func (l *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Log the request
	dumpReq, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "REQUEST:\n%s\n", dumpReq)

	// Perform the request
	resp, err := l.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Log the response
	dumpResp, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "RESPONSE:\n%s\n", dumpResp)

	return resp, nil
}

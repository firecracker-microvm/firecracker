package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

func main() {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithClientLogMode(
			aws.LogSigning|
				aws.LogRetries|
				aws.LogRequest|
				aws.LogRequestWithBody|
				aws.LogResponse|
				aws.LogResponseWithBody,
		),
	)
	if err != nil {
		log.Fatalf("Unable to load config: %v", err)
	}

	cred, err := cfg.Credentials.Retrieve(context.TODO())
	if err != nil {
		log.Fatalf("Unable to retrieve credentials: %v", err)
	}

	fmt.Printf("%v,%v,%v\n", cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
}

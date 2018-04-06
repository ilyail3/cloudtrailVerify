package main

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws"
	"log"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"os/user"
	"github.com/ilyail3/cloudtrailVerify"
	"os"
)

func main() {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	cred := credentials.NewSharedCredentials(usr.HomeDir+"/.aws/credentials", os.Args[1])

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-east-1"),
		Credentials: cred})

	if err != nil {
		log.Panicf("Failed to start session %v", err)
	}

	svc := s3.New(sess, &aws.Config{
		S3DisableContentMD5Validation: aws.Bool(true)})

	if err != nil {
		log.Panicf("failed to parse minDate:%v", err)
	}


	c := cloudtrailVerify.NewDigestCompare(svc, cred)

	err = c.ListDigestFiles(os.Args[2], os.Args[3])

	if err != nil {
		log.Panicf("failed to get tree:%v", err)
	}

	err = c.GetPublicKeys()

	if err != nil {
		log.Panicf("failed to get public keys:%v", err)
	}

	err = c.ValidateObjects()

	if err != nil {
		log.Panicf("validate object:%v", err)
	}


	/*err = validate(Validate{
		Bucket: BUCKET,
		Key:    FIRST_KEY,
	}, minDate, svc, keys)

	if err != nil {
		log.Panicf("Failed to validate:%v", err)
	}*/
}

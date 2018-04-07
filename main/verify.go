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
	"strings"
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

	if os.Args[3] == "AWSLogs" || strings.HasSuffix(os.Args[3], "/AWSLogs") {
		objects, err := svc.ListObjects(&s3.ListObjectsInput{
			Bucket:    aws.String(os.Args[2]),
			Prefix:    aws.String(os.Args[3] + "/"),
			Delimiter: aws.String("/"),
		})

		if err != nil {
			log.Panicf("failed to get list:%v", err)
		}

		for _, commonPrefix := range objects.CommonPrefixes {
			prefix := *commonPrefix.Prefix + "CloudTrail-Digest"
			err = c.ListDigestFiles(os.Args[2], prefix)

			if err != nil {
				log.Panicf("failed to get tree for:%s error:%v", prefix, err)
			}

			log.Printf("Read tree for:%s\n", prefix)
		}
	} else if strings.HasSuffix(os.Args[3], "/CloudTrail-Digest") {
		err = c.ListDigestFiles(os.Args[2], os.Args[3]+"/")

		if err != nil {
			log.Panicf("failed to get tree:%v", err)
		}
	} else {
		log.Panicf("bad location argument:%s", os.Args[3])
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

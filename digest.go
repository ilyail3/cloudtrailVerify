package cloudtrailVerify

import (
	"github.com/emirpasic/gods/sets/treeset"
	"github.com/aws/aws-sdk-go/service/s3"
	"regexp"
	"strings"
	"crypto/rsa"
	"time"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws"
	"fmt"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"crypto/x509"
	"log"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

const FilenameRegex = "\\/([0-9]{12})_CloudTrail-Digest_([a-z0-9-]+)_" +
	"([a-zA-Z0-9-]+)_([a-z0-9-]+)_([0-9]{8}T[0-9]{6}Z)\\.json\\.gz$"

const FilenameDateFormat = "20060102T150405Z"

type DigestCompare struct {
	Objects *treeset.Set
	minDates map[string]string
	maxDates map[string]string
	svc *s3.S3
	cred *credentials.Credentials
	publicKeys map[string]*rsa.PublicKey
}

func NewDigestCompare(svc *s3.S3, cred *credentials.Credentials) *DigestCompare {
	return &DigestCompare{
		Objects: treeset.NewWithStringComparator(),
		minDates: make(map[string]string),
		maxDates: make(map[string]string),
		publicKeys: make(map[string]*rsa.PublicKey),
		svc: svc,
		cred: cred,
	}
}

func (result *DigestCompare)ListDigestFiles(bucket string, prefix string) error {
	marker := ""

	filenameRegex,err := regexp.Compile(FilenameRegex)

	if err != nil {
		return err
	}

	for {
		resp, err := result.svc.ListObjects(&s3.ListObjectsInput{
			Bucket: &bucket,
			Prefix: &prefix,
			Marker: &marker})

		if err != nil {
			return err
		}

		for _, k := range resp.Contents {
			result.Objects.Add(bucket + "/" + *k.Key)

			parts := filenameRegex.FindStringSubmatch(*k.Key)

			region := parts[2]
			date := parts[5]

			current, exists := result.minDates[region]

			if !exists || strings.Compare(date, current) < 0 {
				result.minDates[region] = date
			}

			current, exists = result.maxDates[region]

			if !exists || strings.Compare(date, current) > 0 {
				result.maxDates[region] = date
			}
		}

		if !*resp.IsTruncated {
			break
		} else {
			marker = *resp.Contents[len(resp.Contents)-1].Key
		}
	}

	return err
}

func (result *DigestCompare)GetPublicKeys() error {
	for region, minDateStr := range result.minDates {
		maxDateStr := result.maxDates[region]

		minDate,err := time.Parse(FilenameDateFormat, minDateStr)

		if err != nil {
			return err
		}

		maxDate,err := time.Parse(FilenameDateFormat, maxDateStr)

		if err != nil {
			return err
		}

		awsSession, err := session.NewSession(&aws.Config{
			Region:      aws.String(region),
			Credentials: result.cred,
		})

		if err != nil {
			return fmt.Errorf("failed to start session %v", err)
		}

		cloudtrailSvc := cloudtrail.New(awsSession)

		publicKeys, err := cloudtrailSvc.ListPublicKeys(&cloudtrail.ListPublicKeysInput{
			StartTime: &minDate,
			EndTime: &maxDate,
		})

		if err != nil {
			return fmt.Errorf("failed to get keys %v", err)
		}

		for _, pk := range publicKeys.PublicKeyList {
			pub, err := x509.ParsePKCS1PublicKey(pk.Value)

			if err != nil {
				log.Fatal(err)
			}

			result.publicKeys[*pk.Fingerprint] = pub
		}
	}

	fmt.Println("Keys")
	fmt.Println(result.publicKeys)

	return nil
}

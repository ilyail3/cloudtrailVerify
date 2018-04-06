package main

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws"
	"log"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"os/user"
	"encoding/json"
	"strings"
	"io"
	"encoding/hex"
	"bytes"
	"fmt"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"crypto/rsa"
	"crypto/x509"
	"crypto"
	"crypto/sha256"
	"time"
	"github.com/ilyail3/cloudtrailVerify"
	"os"
)

type Validate struct {
	Bucket       string
	Key          string
	ExpectedSig  string
	ExpectedHash string
}

type LogFile struct {
	S3Bucket        string `json:"s3Bucket"`
	S3Object        string `json:"s3Object"`
	HashValue       string `json:"hashValue"`
	HashAlgorithm   string `json:"hashAlgorithm"`
	NewestEventTime string `json:"newestEventTime"`
	OldestEventTime string `json:"oldestEventTime"`
}

type DigestFile struct {
	PreviousDigestS3Bucket      string  `json:"previousDigestS3Bucket"`
	PreviousDigestS3Object      string  `json:"previousDigestS3Object"`
	DigestSignatureAlgorithm    string  `json:"digestSignatureAlgorithm"`
	PreviousDigestSignature     string  `json:"previousDigestSignature"`
	PreviousDigestHashAlgorithm string  `json:"previousDigestHashAlgorithm"`
	PreviousDigestHashValue     string  `json:"previousDigestHashValue"`
	DigestPublicKeyFingerprint  string  `json:"digestPublicKeyFingerprint"`
	DigestEndTime               string  `json:"digestEndTime"`
	DigestS3Bucket              string  `json:"digestS3Bucket"`
	DigestS3Object              string  `json:"digestS3Object"`
	LogFiles                    []LogFile `json:"logFiles"`
}

func streamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}

func verifySignature(keys map[string]*rsa.PublicKey, keyFingerPrint string, hashed [32]byte, signature string) error {
	signed, err := hex.DecodeString(signature)

	if err != nil {
		return fmt.Errorf("hex decode:%v", err)
	}

	pubicKey, exists := keys[keyFingerPrint]

	if !exists {
		return fmt.Errorf("no key for fingerprint:%s", keyFingerPrint)
	}

	return rsa.VerifyPKCS1v15(
		pubicKey,
		crypto.SHA256,
		hashed[:],
		signed)
}

func validate(v Validate, minDate string, client *s3.S3, keys map[string]*rsa.PublicKey) error {

	for {
		prevDate := v.Key[len(v.Key)-24 : len(v.Key)-8]

		if strings.Compare(prevDate, minDate) < 0 {
			return nil
		}

		f, err := client.GetObject(&s3.GetObjectInput{
			Bucket: &v.Bucket,
			Key:    &v.Key})

		if err != nil {
			return err
		}

		data := streamToByte(f.Body)
		f.Body.Close()

		decoder := json.NewDecoder(bytes.NewReader(data))

		file := &DigestFile{}
		decoder.Decode(file)

		hashed := sha256.Sum256(data)
		calculatedHash := hex.EncodeToString(hashed[:])

		if v.ExpectedHash != "" && calculatedHash != v.ExpectedHash {
			return fmt.Errorf(
				"bad hash encountered on key:%s, expected:%s, got:%s",
				v.Key,
				calculatedHash,
				v.ExpectedHash)
		}
		if *f.Metadata["Signature-Algorithm"] != "SHA256withRSA" {
			return fmt.Errorf("unkown signature algorithem encountered:%s", *f.Metadata["Signature-Algorithm"])
		}

		dataToSign := fmt.Sprintf("%s\n%s/%s\n%s\n%s",
			file.DigestEndTime,
			file.DigestS3Bucket,
			file.DigestS3Object,
			hex.EncodeToString(hashed[:]),
			file.PreviousDigestSignature)

		signatureHash := sha256.Sum256([]byte(dataToSign))

		err = verifySignature(keys, file.DigestPublicKeyFingerprint, signatureHash, *f.Metadata["Signature"])

		if err != nil {
			return fmt.Errorf("failed to validate signature:%v", err)
		}

		fmt.Printf("Verified object %s/%s\n", v.Bucket, v.Key)

		v.Bucket = file.PreviousDigestS3Bucket
		v.Key = file.PreviousDigestS3Object
		v.ExpectedSig = file.PreviousDigestSignature
		v.ExpectedHash = file.PreviousDigestHashValue
	}
}

func loadPublicKeys(cred *credentials.Credentials, region string, startTime time.Time, keys map[string]*rsa.PublicKey) error{
	awsSession, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: cred,
	})

	if err != nil {
		return fmt.Errorf("failed to start session %v", err)
	}

	cloudtrailSvc := cloudtrail.New(awsSession)

	publicKeys, err := cloudtrailSvc.ListPublicKeys(&cloudtrail.ListPublicKeysInput{
		StartTime: &startTime,
	})

	if err != nil {
		return fmt.Errorf("failed to get keys %v", err)
	}

	for _, pk := range publicKeys.PublicKeyList {
		pub, err := x509.ParsePKCS1PublicKey(pk.Value)

		if err != nil {
			log.Fatal(err)
		}

		keys[*pk.Fingerprint] = pub
	}

	return nil
}

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

	/*err = validate(Validate{
		Bucket: BUCKET,
		Key:    FIRST_KEY,
	}, minDate, svc, keys)

	if err != nil {
		log.Panicf("Failed to validate:%v", err)
	}*/
}

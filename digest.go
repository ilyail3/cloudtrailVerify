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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"bytes"
	"io"
	"crypto"
	"os"
	"encoding/csv"
	"sync"
)

const FilenameRegex = "\\/([0-9]{12})_CloudTrail-Digest_([a-z0-9-]+)_" +
	"([a-zA-Z0-9-]+)_([a-z0-9-]+)_([0-9]{8}T[0-9]{6}Z)\\.json\\.gz$"

const FilenameDateFormat = "20060102T150405Z"

const FileOpenMode = os.O_RDWR | os.O_TRUNC | os.O_CREATE

const FilePermission = 0600

type DigestCompare struct {
	Objects    map[ScanPartition]*treeset.Set
	minDates   map[string]string
	maxDates   map[string]string
	svc        *s3.S3
	cred       *credentials.Credentials
	publicKeys map[string]*rsa.PublicKey
}

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
	PreviousDigestS3Bucket      string    `json:"previousDigestS3Bucket"`
	PreviousDigestS3Object      string    `json:"previousDigestS3Object"`
	DigestSignatureAlgorithm    string    `json:"digestSignatureAlgorithm"`
	PreviousDigestSignature     string    `json:"previousDigestSignature"`
	PreviousDigestHashAlgorithm string    `json:"previousDigestHashAlgorithm"`
	PreviousDigestHashValue     string    `json:"previousDigestHashValue"`
	DigestPublicKeyFingerprint  string    `json:"digestPublicKeyFingerprint"`
	DigestEndTime               string    `json:"digestEndTime"`
	DigestS3Bucket              string    `json:"digestS3Bucket"`
	DigestS3Object              string    `json:"digestS3Object"`
	LogFiles                    []LogFile `json:"logFiles"`
}

type ScanPartition struct {
	Account string
	Region  string
}

type ValidateTask struct {
	validate Validate
	results  chan DigestFile
}

func NewDigestCompare(svc *s3.S3, cred *credentials.Credentials) *DigestCompare {
	return &DigestCompare{
		Objects:    make(map[ScanPartition]*treeset.Set),
		minDates:   make(map[string]string),
		maxDates:   make(map[string]string),
		publicKeys: make(map[string]*rsa.PublicKey),
		svc:        svc,
		cred:       cred,
	}
}

func (result *DigestCompare) ListDigestFiles(bucket string, prefix string) error {
	marker := ""

	filenameRegex, err := regexp.Compile(FilenameRegex)

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
			parts := filenameRegex.FindStringSubmatch(*k.Key)

			region := parts[2]
			date := parts[5]

			partition := ScanPartition{
				Account: parts[1],
				Region:  parts[2],
			}

			obj, exists := result.Objects[partition]
			if !exists {
				obj = treeset.NewWithStringComparator()
				result.Objects[partition] = obj
			}

			obj.Add(bucket + "/" + *k.Key)

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

func (result *DigestCompare) GetPublicKeys() error {
	for region, minDateStr := range result.minDates {
		maxDateStr := result.maxDates[region]

		minDate, err := time.Parse(FilenameDateFormat, minDateStr)

		if err != nil {
			return err
		}

		maxDate, err := time.Parse(FilenameDateFormat, maxDateStr)

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
			EndTime:   &maxDate,
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

	return nil
}

func streamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}

func (result *DigestCompare) verifySignature(keyFingerPrint string, hashed [32]byte, signature string) error {
	signed, err := hex.DecodeString(signature)

	if err != nil {
		return fmt.Errorf("hex decode:%v", err)
	}

	pubicKey, exists := result.publicKeys[keyFingerPrint]

	if !exists {
		return fmt.Errorf("no key for fingerprint:%s", keyFingerPrint)
	}

	return rsa.VerifyPKCS1v15(
		pubicKey,
		crypto.SHA256,
		hashed[:],
		signed)
}

func (result *DigestCompare) ValidateObjects() error {

	resultChannel := make(chan LogFile)
	errors := make(chan error)
	taskQueue := make(chan ValidateTask)

	var wgWriter sync.WaitGroup
	wgWriter.Add(1)

	go result.writeFile(resultChannel, errors, wgWriter)
	go result.processTask(taskQueue, errors)

	var wgReader sync.WaitGroup
	wgReader.Add(len(result.Objects))
	for _, set := range result.Objects {
		go result.validateObjects(set, resultChannel, taskQueue, errors, wgReader)
	}

	var err error = nil

	go func() {
		for localErr := range errors {
			log.Printf("error:%v\n", localErr)
			err = localErr
		}
	}()

	wgReader.Wait()
	close(resultChannel)

	wgWriter.Wait()
	close(errors)

	return err
}

func (result *DigestCompare) writeFile(results <-chan LogFile, errors chan error, wg sync.WaitGroup) {
	defer wg.Done()

	fileWriter, err := os.OpenFile(
		"/tmp/files.csv",
		FileOpenMode,
		FilePermission)

	if err != nil {
		errors <- err
		return
	}

	defer fileWriter.Close()

	writer := csv.NewWriter(fileWriter)
	defer writer.Flush()

	writer.Write([]string{
		"S3Bucket",
		"S3Object",
		"HashValue",
		"HashAlgorithm",
		"NewestEventTime",
		"OldestEventTime",
	})

	for file := range results {
		writer.Write([]string{
			file.S3Bucket,
			file.S3Object,
			file.HashValue,
			file.HashAlgorithm,
			file.NewestEventTime,
			file.OldestEventTime,
		})
	}
}

func (result *DigestCompare) processTask(taskQueue chan ValidateTask, errors chan error) {
	for task := range taskQueue {
		validate := task.validate

		for {
			f, err := result.svc.GetObject(&s3.GetObjectInput{
				Bucket: &validate.Bucket,
				Key:    &validate.Key})

			if err != nil {
				data := err.(s3.RequestFailure)
				// Objects can be deleted by AWS while the process is running.
				// in such case, just ignore the record, this doesn't break the chain(since those files
				// are truncated by age, therefor oldest-last links of the chain will be impacted first)
				if data.Code() == "NoSuchKey" {
					close(task.results)
					break
				} else {
					errors <- fmt.Errorf(
						"error getting key bucket:%s key:%s error:%v",
						validate.Bucket,
						validate.Key,
						err)

					close(task.results)
					break
				}
			}

			data := streamToByte(f.Body)
			f.Body.Close()

			decoder := json.NewDecoder(bytes.NewReader(data))

			file := DigestFile{}
			decoder.Decode(&file)

			hashed := sha256.Sum256(data)
			calculatedHash := hex.EncodeToString(hashed[:])

			if validate.ExpectedHash != "" && calculatedHash != validate.ExpectedHash {
				errors <- fmt.Errorf(
					"bad hash encountered on key:%s, expected:%s, got:%s",
					validate.Key,
					calculatedHash,
					validate.ExpectedHash)

				close(task.results)
				break
			}
			if *f.Metadata["Signature-Algorithm"] != "SHA256withRSA" {
				errors <- fmt.Errorf("unkown signature algorithem encountered:%s", *f.Metadata["Signature-Algorithm"])

				close(task.results)
				break
			}

			dataToSign := fmt.Sprintf("%s\n%s/%s\n%s\n%s",
				file.DigestEndTime,
				file.DigestS3Bucket,
				file.DigestS3Object,
				hex.EncodeToString(hashed[:]),
				file.PreviousDigestSignature)

			signatureHash := sha256.Sum256([]byte(dataToSign))

			err = result.verifySignature(file.DigestPublicKeyFingerprint, signatureHash, *f.Metadata["Signature"])

			if err != nil {
				errors <- fmt.Errorf(
					"failed to validate bucket:%s key:%s signature:%v",
					validate.Bucket,
					validate.Key,
					err)

				close(task.results)
				return
			}

			fmt.Printf("Verified object %s/%s\n", validate.Bucket, validate.Key)
			task.results <- file

			validate = Validate{
				Bucket:       file.PreviousDigestS3Bucket,
				Key:          file.PreviousDigestS3Object,
				ExpectedSig:  file.PreviousDigestSignature,
				ExpectedHash: file.PreviousDigestHashValue,
			}
		}
	}
}

func (result *DigestCompare) validateObjects(set *treeset.Set, results chan LogFile, taskQueue chan ValidateTask, errors chan error, wg sync.WaitGroup) {
	defer wg.Done()

	for !set.Empty() {
		it := set.Iterator()
		it.End()
		it.Prev()

		lastKey := it.Value().(string)
		parts := strings.SplitN(lastKey, "/", 2)

		digestResult := make(chan DigestFile)

		taskQueue <- ValidateTask{
			validate: Validate{
				Bucket:       parts[0],
				Key:          parts[1],
				ExpectedSig:  "",
				ExpectedHash: "",
			},
			results: digestResult,
		}

		for digestFile := range digestResult {
			for _, logFile := range digestFile.LogFiles {
				results <- logFile
			}

			set.Remove(digestFile.DigestS3Bucket + "/" + digestFile.DigestS3Object)
		}
	}
}

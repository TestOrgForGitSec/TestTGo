package scanner

import (
	"compliance-hub-plugin-trivy/config"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cloudbees-compliance/chlog-go/log"
	domain "github.com/cloudbees-compliance/chplugin-go/v0.4.0/domainv0_4_0"
	storage "github.com/cloudbees-compliance/storage-go"
	"github.com/google/uuid"
)

func Scan(ctx context.Context, scanType string, a *domain.MasterAsset, ap *domain.AssetProfile, response *[]byte) error {

	scanRunUUID := uuid.NewString()
	requestId := fetchRequestId(ctx)
	log.Info(requestId).Msgf("Starting Scan run %s, asset: %s, profile: %s", scanRunUUID, a.Identifier, ap.Identifier)

	if scanType == EmptyString || response == nil || (scanType == "Registry" && a.Identifier == EmptyString) {
		log.Info(requestId).Msgf("Incorrect Scan params : scanType=%s, scanUrl=%s, or response byte array was nil.", scanType, a.Identifier)
		return errors.New("invalid scan parameters")
	}

	// setup image cache & output directories
	workDir := WorkDirBase + scanRunUUID
	outDir := workDir + OutputDir
	if err := mkDir(ctx, workDir, outDir); err != nil {
		return err
	}
	// remove workdir and subdirs after scan is completed
	//defer os.RemoveAll(workDir)
	defer cleanUpWorkingDir(workDir, requestId)
	switch scanType {
	case "Image":
		log.Info(requestId).Msgf("Scanning Image %s", a.Identifier)
		if err := scanImage(ctx, a, ap, outDir); err != nil {
			log.Error(requestId).Err(err).Msg("Scan Image Failed")
			return err
		}

	case "Registry":
		log.Info(requestId).Msgf("Scanning Image Registry %s", a.Identifier)
		if err := scanRegistry(a.Identifier); err != nil {
			log.Error(requestId).Err(err).Msg("Scan Registry Failed")
			return err
		}
	default:
		return errors.New("invalid scan type requested")

	}

	// create the output response

	if err := createResponse(ctx, scanRunUUID, outDir, response); err != nil {
		return err
	}

	return nil
}

func writeTarballTemp(data []byte) (*os.File, error) {
	f, err := os.CreateTemp("", "docker-image")
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(f.Name(), data, FilePerm)
	return f, err
}

func fetchBinaryData(binAttrib *domain.BinaryAttribute, ctx context.Context) ([]byte, error) {
	// fetch the image tar in external storage
	if binAttrib.SourceType == domain.SourceType_REMOTE {
		storageSpec := storage.StorageSpec(binAttrib.SourceMetadata)
		st, err := storage.NewStorage(ctx, storageSpec)
		if err != nil {
			return nil, err
		}

		binaryData, _, err := st.Fetch(ctx)
		if err != nil {
			return nil, err
		}

		return binaryData, nil
	} else {
		return binAttrib.Data, nil
	}
}

func scanImage(ctx context.Context, a *domain.MasterAsset, ap *domain.AssetProfile, outDir string) error {

	requestId := fetchRequestId(ctx)

	// execute the trivy client against each of
	var tarballData []byte
	for _, binAttrib := range ap.BinAttributes {
		log.Debug(requestId).Msgf("BinAttrib values are : Name : %s, Type : %s, Version: %s, SourceType : %d, SourceMetadata : %s", binAttrib.Name, binAttrib.Type, binAttrib.Version, binAttrib.SourceType, binAttrib.SourceMetadata)
		log.Debug(requestId).Msgf("ApIdentifier is %s", ap.Identifier)

		if binAttrib.Version == "CH_MOST_RECENT" || binAttrib.Version == ap.Identifier {
			// tarballData = binAttrib.Data
			var err error
			tarballData, err = fetchBinaryData(binAttrib, ctx)
			if err != nil {
				return err
			}
			break
		}
	}
	if len(tarballData) == 0 {
		return fmt.Errorf("unable to find binary attributes for asset %s, profile %s", a.Identifier, ap.Identifier)
	}

	tarballFile, err := writeTarballTemp(tarballData)
	if err != nil {
		return err
	}
	defer os.Remove(tarballFile.Name())

	imageName := strings.ReplaceAll(a.Identifier, Slash, UnderScore)
	imageName = strings.ReplaceAll(imageName, Colon, UnderScore)
	outputFile := outDir + Slash + imageName + DoubleUnderScore + OutputFileName
	var cmdWithParams = fmt.Sprintf("Running Command: %s %s %s %s %s %s %s %s %s %s %s %s %s ", App, RunAsImage, RunAsDebug, SpecifyCacheDir, CacheDir, SpecifyOutputFormat, OutputFormat, SpecifyInputFile, tarballFile.Name(), SpecifyOutput, outputFile, SpecifyServer, config.Config.GetString("trivy.remote"))
	log.Info(requestId).Msg(cmdWithParams)
	cmd := exec.Command(App, RunAsImage, RunAsDebug, SpecifyCacheDir, CacheDir, SpecifyOutputFormat, OutputFormat, SpecifyInputFile, tarballFile.Name(), SpecifyOutput, outputFile, SpecifyServer, config.Config.GetString("trivy.remote"))
	scanLog, err := cmd.CombinedOutput()
	if err != nil {
		log.Debug(requestId).Msg(string(scanLog))
		log.Error(requestId).Err(err).Msgf("Could not execute command %s", cmd.String())
		return err
	}

	log.Debug(requestId).Msg(string(scanLog)) // write the scan log if we need to diagnose stuff

	return err
}

func mkDir(ctx context.Context, workDir, outDir string) error {
	requestId := fetchRequestId(ctx)
	if err := os.Mkdir(workDir, FilePerm); err != nil {
		log.Error(requestId).Msgf("Could not create directory %s", workDir)
		return err
	}

	if err := os.Mkdir(outDir, FilePerm); err != nil {
		log.Error(requestId).Msgf("Could not create directory %s", workDir)
		return err
	}
	return nil
}

func scanRegistry(registryUrl string) error {
	return nil
}

func createResponse(ctx context.Context, scanRunUUID, outDir string, response *[]byte) error {

	requestId := fetchRequestId(ctx)

	var (
		scanResp scanResponse
		scanRes  imageResult
		scanLog  imageLog
	)

	scanResp.ScanRunUUID = scanRunUUID

	// get the output files
	files, err := ioutil.ReadDir(outDir)
	if err != nil {
		log.Error(requestId).Err(err).Msgf("Could not read directory %s", outDir)
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		fileName := file.Name()
		filePath := outDir + Slash + fileName

		if strings.Contains(fileName, OutputFileName) {
			scanRes = imageResult{}
			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				log.Error(requestId).Err(err).Msgf("Could not read file %s", fileName)
				return err
			}

			scanRes.ImageUrl = fileName[:strings.Index(fileName, DoubleUnderScore)]
			scanRes.ImageScanOutput = content
			scanResp.ScanOutput = append(scanResp.ScanOutput, scanRes)
			continue
		}

		if strings.Contains(fileName, LogFileName) {
			scanLog = imageLog{}
			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				log.Error(requestId).Err(err).Msgf("Could not read file %s", fileName)
				return err
			}

			scanLog.ImageUrl = fileName[:strings.Index(fileName, DoubleUnderScore)]
			scanLog.ImageScanLog = string(content)
			scanResp.ScanLog = append(scanResp.ScanLog, scanLog)
			continue
		}

	}
	*response, err = json.Marshal(scanResp)

	if err != nil {
		log.Error(requestId).Err(err).Msgf("Could not marshal response - %s", err)
	}

	return nil
}

func fetchRequestId(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	requestId, ok := ctx.Value("requestId").(string)
	if !ok {
		log.Error().Msg("Unable to get request id. Cannot determine sublogger for request id.")
		requestId = ""
	}
	return requestId

}

func cleanUpWorkingDir(dir string, reqId string) {
	//inspect files
	log.Debug(reqId).Msg("Before Removing Working files.....")
	inspectFiles("/tmp", reqId)
	// remove workdir and subdirs after scan is completed
	err := os.RemoveAll(dir)
	if err != nil {
		log.Debug(reqId).Msgf("Error occurred while removing the directory %s", dir)
	}
	log.Debug(reqId).Msg("After Removing Working files.....")
	inspectFiles("/tmp", reqId)

}

func inspectFiles(dir, reqId string) {
	log.Debug(reqId).Msgf("Instrospecting file/dir .... %s", dir)
	walkThroughAllFiles(dir, reqId)
}

func walkThroughAllFiles(path string, reqID string) {
	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			//do nothing
			log.Debug(reqID).Msg("Error occurred while file walk through")
		}
		fmt.Printf("File Name: %s\n", info.Name())
		return nil
	})
}

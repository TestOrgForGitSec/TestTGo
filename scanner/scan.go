package scanner

import (
	"compliance-hub-plugin-trivy/config"
	"encoding/json"
	"errors"
	"fmt"
	domain "github.com/deliveryblueprints/chplugin-go/v0.3.0/domainv0_3_0"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

func Scan(scanType string, a *domain.MasterAsset, ap *domain.AssetProfile, response *[]byte) error {

	scanRunUUID := uuid.NewString()

	log.Info().Msgf("Starting Scan run %s, asset: %s, profile: %s", scanRunUUID, a.Identifier, ap.Identifier)

	if scanType == EmptyString || response == nil || (scanType == "Registry" && a.Identifier == EmptyString) {
		log.Info().Msgf("Incorrect Scan params : scanType=%s, scanUrl=%s, or response byte array was nil.", scanType, a.Identifier)
		return errors.New("invalid scan parameters")
	}

	// setup image cache & output directories
	workDir := WorkDirBase + scanRunUUID
	outDir := workDir + OutputDir
	if err := mkDir(workDir, outDir); err != nil {
		return err
	}

	switch scanType {
	case "Image":
		log.Info().Msgf("Scanning Image %s", a.Identifier)
		if err := scanImage(a, ap, outDir); err != nil {
			log.Error().Err(err).Msg("Scan Image Failed")
			return err
		}

	case "Registry":
		log.Info().Msgf("Scanning Image Registry %s", a.Identifier)
		if err := scanRegistry(a.Identifier); err != nil {
			log.Error().Err(err).Msg("Scan Registry Failed")
			return err
		}
	default:
		return errors.New("invalid scan type requested")

	}

	// create the output response

	if err := createResponse(scanRunUUID, outDir, response); err != nil {
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

func scanImage(a *domain.MasterAsset, ap *domain.AssetProfile, outDir string) error {
	// execute the trivy client against each of
	var tarballData []byte
	for _, binAttrib := range ap.BinAttributes {
		if binAttrib.Version == "MOST_RECENT" {
			tarballData = binAttrib.Data
			break
		}
	}
	if len(tarballData) == 0 {
		return fmt.Errorf("unable to find LATEST binary attributes for asset %s, profile %s", a.Identifier, ap.Identifier)
	}

	tarballFile, err := writeTarballTemp(tarballData)
	if err != nil {
		return err
	}
	defer os.Remove(tarballFile.Name())

	imageName := strings.ReplaceAll(a.Identifier, Slash, UnderScore)
	imageName = strings.ReplaceAll(imageName, Colon, UnderScore)
	outputFile := outDir + Slash + imageName + DoubleUnderScore + OutputFileName
	cmd := exec.Command(App, "-d", RunAsClient, SpecifyFormat, OutputFormat, SpecifyInputFile, tarballFile.Name(), SpecifyOutput, outputFile, SpecifyRemote, config.Config.GetString("trivy.remote"))

	scanLog, err := cmd.CombinedOutput()
	if err != nil {
		log.Debug().Msg(string(scanLog))
		log.Error().Err(err).Msgf("Could not execute command %s", cmd.String())
		return err
	}

	// write the log file from the scan
	log.Debug().Msg(string(scanLog))
	logFileName := outDir + Slash + imageName + DoubleUnderScore + LogFileName
	if err := ioutil.WriteFile(logFileName, scanLog, FilePerm); err != nil {
		log.Error().Err(err).Msgf("Could not write file %s", logFileName)
		return err
	}

	return err
}

func mkDir(workDir, outDir string) error {
	if err := os.Mkdir(workDir, FilePerm); err != nil {
		log.Error().Msgf("Could not create directory %s", workDir)
		return err
	}

	if err := os.Mkdir(outDir, FilePerm); err != nil {
		log.Error().Msgf("Could not create directory %s", workDir)
		return err
	}
	return nil
}

func scanRegistry(registryUrl string) error {
	return nil
}

func createResponse(scanRunUUID, outDir string, response *[]byte) error {
	var (
		scanResp scanResponse
		scanRes  imageResult
		scanLog  imageLog
	)

	scanResp.ScanRunUUID = scanRunUUID

	// get the output files
	files, err := ioutil.ReadDir(outDir)
	if err != nil {
		log.Error().Err(err).Msgf("Could not read directory %s", outDir)
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
				log.Error().Err(err).Msgf("Could not read file %s", fileName)
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
				log.Error().Err(err).Msgf("Could not read file %s", fileName)
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
		log.Error().Err(err).Msgf("Could not marshal response - %s", err)
	}

	return nil
}

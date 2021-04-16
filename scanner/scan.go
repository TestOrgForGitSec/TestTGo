package scanner

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

func Scan(scanType, scanUrl string,response *[]byte) error {

	scanRunUUID := uuid.NewString()

	log.Info().Msgf("Starting Scan run %s", scanRunUUID)

	if scanType == EmptyString || scanUrl == EmptyString || response == nil {
		log.Info().Msgf("Incorrect Scan params : scanType=%s, scanUrl=%s, or response byte array was nil.", scanType,scanUrl)
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
		log.Info().Msgf("Scanning Image %s",scanUrl)
		if err := scanImage(scanUrl, outDir);err != nil {
			log.Error().Err(err).Msg("Scan Image Failed")
			return err
		}

	case "Registry":
		log.Info().Msgf("Scanning Image Registry %s",scanUrl)
		if err := scanRegistry(scanUrl);err != nil {
			log.Error().Err(err).Msg("Scan Registry Failed")
			return err
		}
	default:
		return errors.New("invalid scan type requested")

	}

	// create the output response

	if err := createResponse(scanRunUUID, outDir, response); err!= nil {
		return err
	}

	return nil
}

func scanImage(imageUrl, outDir string) error {
	// execute the trivy client

	imageName := strings.ReplaceAll(imageUrl,Slash,UnderScore)
	imageName = strings.ReplaceAll(imageName,Colon,UnderScore)
	outputFile := outDir + Slash + imageName + DoubleUnderScore + OutputFileName
	cmd := exec.Command(App, RunAsClient,SpecifyFormat, OutputFormat, SpecifyOutput, outputFile, SpecifyRemote, RemoteServer, imageUrl)

	scanLog, err := cmd.CombinedOutput()
	if err != nil {
		log.Debug().Msg(string(scanLog))
		log.Error().Err(err).Msgf("Could not execute command %s", cmd.String())
		return err
	}

	// write the log file from the scan
	log.Debug().Msg(string(scanLog))
	logFileName := outDir + Slash + imageName + DoubleUnderScore + LogFileName
	if err := ioutil.WriteFile(logFileName,scanLog,FilePerm); err != nil {
		log.Error().Err(err).Msgf("Could not write file %s", logFileName)
		return err
	}

	return err
}

func mkDir(workDir, outDir string) error {
	if err := os.Mkdir(workDir,FilePerm); err != nil {
		log.Error().Msgf("Could not create directory %s", workDir)
		return err
	}

	if err := os.Mkdir(outDir,FilePerm); err != nil {
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
		scanRes imageResult
		scanLog imageLog

	)

	scanResp.ScanRunUUID = scanRunUUID

	// get the output files
	files, err := ioutil.ReadDir(outDir)
	if err != nil {
		log.Error().Err(err).Msgf("Could not read directory %s", outDir)
		return err
	}

	for _,file := range files {
		if file.IsDir() {
			continue
		}
		fileName := file.Name()
		filePath := outDir + Slash + fileName


		if strings.Contains(fileName,OutputFileName) {
			scanRes = imageResult{}
			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				log.Error().Err(err).Msgf("Could not read file %s", fileName)
				return err
			}

			scanRes.ImageUrl = fileName[:strings.Index(fileName,DoubleUnderScore)]
			scanRes.ImageScanOutput = string(content)
			scanResp.ScanOutput = append(scanResp.ScanOutput,scanRes)
			continue
		}

		if strings.Contains(fileName,LogFileName) {
			scanLog = imageLog{}
			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				log.Error().Err(err).Msgf("Could not read file %s", fileName)
				return err
			}

			scanLog.ImageUrl = fileName[:strings.Index(fileName,DoubleUnderScore)]
			scanLog.ImageScanLog = string(content)
			scanResp.ScanLog = append(scanResp.ScanLog,scanLog)
			continue
		}
	}

	*response, err = json.Marshal(scanResp)

	return nil
}
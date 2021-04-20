package handlers

import (
	"compliance-hub-plugin-trivy/scanner"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

// HandlePostScan initiates a run of the trivy scanner client.
func HandlePostScan(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var (
		scanRequestData scanRequest
		scanResponse    []byte
	)

	if err := unmarshallScanRequest(r, &scanRequestData); err != nil {
		w.WriteHeader(HTTP_INVALID_REQUEST)
		return
	}

	if err := scanner.Scan(scanRequestData.ScanType, scanRequestData.ScanUrl, &scanResponse); err != nil {
		w.WriteHeader(HTTP_INVALID_REQUEST)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(HTTP_SUCCESS)

	w.Write(scanResponse)
}

func unmarshallScanRequest(r *http.Request, scanRequestData *scanRequest) (err error) {
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(reqBody, scanRequestData)
	if err != nil {
		return err
	}
	return nil
}

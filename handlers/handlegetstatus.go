package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

// HandleGetStatus returns the status of the trivy scanner client. this has no immediate implementation
func HandleGetStatus(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(HTTP_SUCCESS)
	response := scanStatusResponse{ScanStatus: "All Ok"}
	responseBytes, _ := json.Marshal(response)

	w.Write(responseBytes)
}

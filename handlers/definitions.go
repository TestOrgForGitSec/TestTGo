package handlers

const (
	HTTP_SUCCESS         = 200
	HTTP_INVALID_REQUEST = 401
	HTTP_SERVER_FAILURE  = 500
)

type scanStatusResponse struct {
	ScanStatus string `json:"scanStatus"`
}

type scanRequest struct {
	ScanType            string        `json:"scanType"`
	ScanUrl             string        `json:"scanUrl"`
	RegistryCredentials registryCreds `json:"registryCredentials"`
}

type registryCreds struct {
	RegistryProvider string `json:"registryProvider"`
	RegistryUsername string `json:"registryUsername"`
	RegistryPassword string `json:"registryPassword"`
}

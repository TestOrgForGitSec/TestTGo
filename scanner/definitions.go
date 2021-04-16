package scanner


const (
	EmptyString = ""
	UnderScore = "_"
	Slash = "/"
	WorkDirBase = "/tmp/scan-"
	OutputDir = "/output"
	OutputFileName = "scanner_output.json"
	LogFileName = "scanner_log.txt"
	FilePerm = 0755

	// trivy client command constants
	App = "trivy"
	RunAsClient = "client"
	OutputFormat = "-f json"
	SpecifyOutput = "-o "
	RemoteServer = "--remote \"http://trivy-server:8081\" "
)

type scanResponse struct {
	ScanRunUUID string `json:"scanRunUuid"`
	ScanOutput []imageResult `json:"scanOutput"`
	ScanLog []imageLog `json:"scanLog"`
}

type imageResult struct {
	ImageUrl string `json:"imageUrl"`
	ImageScanOutput []byte `json:"imageScanOutput"`
}

type imageLog struct {
	ImageUrl string `json:"imageUrl"`
	ImageScanLog []byte `json:"imageScanLog"`
}

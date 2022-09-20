package scanner

import "encoding/json"

const (
	EmptyString      = ""
	DoubleUnderScore = "__"
	UnderScore       = "_"
	Colon            = ":"
	Slash            = "/"
	WorkDirBase      = "/tmp/scan-"
	OutputDir        = "/output"
	OutputFileName   = "scanner_output.json"
	LogFileName      = "scanner_log.txt"
	FilePerm         = 0755

	// trivy client command constants
	App                 = "trivy"
	RunAsClient         = "client"
	RunAsImage          = "image"
	RunAsDebug          = "--debug"
	SpecifyOutputFormat = "--format"
	OutputFormat        = "json"
	SpecifyOutput       = "--output"
	SpecifyInputFile    = "--input"
	SpecifyRemote       = "--remote"
	SpecifyServer       = "--server"
	//RemoteServer  = "http://trivy-server:8081"
)

type scanResponse struct {
	ScanRunUUID string        `json:"scanRunUuid"`
	ScanOutput  []imageResult `json:"scanOutput"`
	ScanLog     []imageLog    `json:"scanLog"`
}

type imageResult struct {
	ImageUrl        string          `json:"imageUrl"`
	ImageScanOutput json.RawMessage `json:"imageScanOutput"`
}

type imageLog struct {
	ImageUrl     string `json:"imageUrl"`
	ImageScanLog string `json:"imageScanLog"`
}

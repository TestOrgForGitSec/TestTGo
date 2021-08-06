package lservice

import (
	"compliance-hub-plugin-trivy/scanner"
	"context"
	"encoding/json"
	"fmt"
	domain "github.com/deliveryblueprints/chplugin-go/v0.0.1/domainv0_0_1"
	service "github.com/deliveryblueprints/chplugin-go/v0.0.1/servicev0_0_1"
	"github.com/deliveryblueprints/chplugin-service-go/plugin"
	"github.com/rs/zerolog/log"
)

type SubAttributesDTO struct {
	AssetAttributesUUID string          `json:"assetAttributeUuid"`
	Type                string          `json:"type"`
	Attributes          json.RawMessage `json:"attributes,omitEmpty"`
}

type AssetDTO struct {
	UUID          string             `json:"uuid"`
	Identifier    string             `json:"identifier"`
	Type          string             `json:"type"`
	SubType       string             `json:"subType,omitempty"`
	Status        string             `json:"status"`
	Attributes    json.RawMessage    `json:"attributes,omitEmpty"`
	SubAttributes []SubAttributesDTO `json:"subAttributes,omitEmpty"`
}

//TrivyScanner is a implementation of ManifiestService Grpc Service.
type TrivyScanner struct {
	plugin.CHPluginService
}

//NewManifestServiceGrpcImpl returns the pointer to the implementation.
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{}
}

//GetManifest implementiation of gRPC service.
func (serviceImpl *TrivyScanner) GetManifest(ctx context.Context, in *service.GetManifestRequest) (*service.GetManifestResponse, error) {
	return &service.GetManifestResponse{
		Manifest: &domain.Manifest{
			Uuid:    "mg19e330-8827-11eb-8dcd-0242ac130003",
			Name:    "Docker Hub Scanner",
			Version: "0.0.1",
			AssetRoles: []*domain.AssetRole{
				{
					Role:                 "DECORATOR",
					AssetType:            &domain.AssetType{Type: "BINARY"},
					CreatesAttributes:    true,
					CreatesSubAttributes: []string{"trivy"},
					RequiresAssets:       true,
				},
				{
					Role:           "ANALYSER",
					AssetType:      &domain.AssetType{Type: "BINARY"},
					RequiresAssets: true,
				},
			},
		},
		Error: nil,
	}, nil
}

// GetAssetDescriptors implementation of gRPC service.
func (serviceImpl *TrivyScanner) GetAssetDescriptors(context.Context, *service.GetAssetDescriptorsRequest) (*service.GetAssetDescriptorsResponse, error) {
	return &service.GetAssetDescriptorsResponse{
		AssetDescriptors: &domain.AssetDescriptors{
			AttributesDescriptors: []*domain.AssetAttributesDescriptor{
				{
					SubType:     "dockerhub_image",
					Description: "A dockerhub image",
					Descriptors: []*domain.Descriptor{
						{
							Name:        "dockerhub_image.id",
							Description: "The unique reference of this dockerhub image",
							DataType:    "string",
							DataSubtype: "trivy",
							AssetTypes:  []*domain.AssetType{{Type: "BINARY"}},
						},
					},
				},
			},
			SubAttributesDescriptors: nil,
		},
	}, nil
}

func (serviceImpl *TrivyScanner) ExecuteMaster(_ context.Context, _ *service.ExecuteRequest) (*service.ExecuteMasterResponse, error) {
	return &service.ExecuteMasterResponse{}, nil
}

func (serviceImpl *TrivyScanner) ExecuteDecorator(_ context.Context, req *service.ExecuteRequest, assetFetcher plugin.AssetFetcher) (*service.ExecuteDecoratorResponse, error) {
	assets := assetFetcher.FetchAssets(req.Account.Uuid, req.AssetType, map[string]*struct{}{
		"dockerhub_image": {},
	})

	var assetAttributes []*domain.AssetAttributes
	for _, asset := range assets {
		var scanResponse []byte
		if err := scanner.Scan("Image", asset.Identifier, &scanResponse); err != nil {
			log.Info().Msgf("Could not scan %s - ignoring (%s)", asset.Identifier, err)
		} else {
			log.Info().Msgf("payload size %d", len(scanResponse))
			assetAttributes = append(assetAttributes, mapToAssetAttributes(asset, scanResponse))
		}
	}

	return &service.ExecuteDecoratorResponse{
		AssetAttributes: assetAttributes,
		Error:           nil,
	}, nil
}

func mapToAssetAttributes(asset domain.Asset, data []byte) *domain.AssetAttributes {
	return &domain.AssetAttributes{
		Asset: &domain.MasterAsset{
			Type:       asset.Type,
			SubType:    asset.SubType,
			Identifier: asset.Identifier,
		},
		Attributes: json.RawMessage(fmt.Sprintf(`{"id":"%s"}`, asset.Identifier)),
		SubAttributes: []*domain.AssetSubAttributes{
			{
				Type:          "trivy",
				SubAttributes: data,
			},
		},
	}
}


type NVD struct {
	V3Score float32 `json:"V3Score"`
}

type CVSS struct {
	Nvd NVD `json:"nvd"`
}

type TrivyVulnerabilities struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	Title            string `json:"Title"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Severity         string `json:"Severity"`
	CVSS             CVSS   `json:"CVSS"`
}

type TrivyScanOutput struct {
	Target          string                 `json:"Target"`
	Type            string                 `json:"Type"`
	Vulnerabilities []TrivyVulnerabilities `json:"Vulnerabilities"`
}

type TrivyOutput struct {
	ImageUrl        string            `json:"imageUrl"`
	ImageScanOutput []TrivyScanOutput `json:"imageScanOutput"`
}

type TrivyRun struct {
	ScanRunUuid string        `json:"scanRunUuid"`
	ScanOutput  []TrivyOutput `json:"scanOutput"`
}

type CHCounter struct {
	Counters [4]int
}

func mapToControl(results []TrivyVulnerabilities, assetId string, attributesId string) []*domain.ControlEvaluation {
	control := &domain.ControlEvaluation{
		Uuid:       "container_control",
		Name:       "Container Analysis",
		Standard:   "Container Vulnerabilities",
		Importance: "CRITICAL",
		Passes:     []*domain.AssetResult{},
		Failures:   []*domain.AssetResult{},
	}
	chCounters := CHCounter{}

	vulnerabilities := []*domain.RequirementBlock{}

	for _, vulnerability := range results {
		log.Trace().Msgf("DEMO Found vulnerability (%s)", vulnerability.VulnerabilityID)

		var score float32
		if vulnerability.CVSS.Nvd.V3Score != 0 {
			score = vulnerability.CVSS.Nvd.V3Score
		} else {
			score = 5.6
		}
		switch vulnerability.Severity {
		case "CRITICAL":
			chCounters.Counters[0]++
		case "HIGN":
			chCounters.Counters[1]++
		case "MEDIUM":
			chCounters.Counters[2]++
		case "LOW":
			chCounters.Counters[3]++
		default:
			vulnerability.Severity = "LOW"
			chCounters.Counters[3]++

		}

		vulnerabilities = append(vulnerabilities, &domain.RequirementBlock{
			UniqueId: vulnerability.VulnerabilityID,
			Name:     vulnerability.VulnerabilityID + "|-|" + fmt.Sprintf("%.75s", vulnerability.Title) + "|-|" + vulnerability.PkgName + " - " + vulnerability.InstalledVersion + "|-|" + vulnerability.Severity + "|-|" + fmt.Sprintf("%.1f", score),
		})
	}

	vulnerabilities = append(vulnerabilities, &domain.RequirementBlock{
		UniqueId: "CH_COUNTERS",
		Name:     fmt.Sprintf("%d", chCounters.Counters[0]) + "|-|" + fmt.Sprintf("%d", chCounters.Counters[1]) + "|-|" + fmt.Sprintf("%d", chCounters.Counters[2]) + "|-|" + fmt.Sprintf("%d", chCounters.Counters[3]),
	})

	assetResult := &domain.AssetResult{
		Uuid:                    assetId,
		AttributesUuid:          attributesId,
		PassedRequirementBlocks: []*domain.RequirementBlock{},
		FailedRequirementBlocks: vulnerabilities,
	}

	if len(vulnerabilities) > 210 {
		log.Trace().Msgf("DEMO adding fail for %s, %s)", assetId, attributesId)
		control.Failures = append(control.Failures, assetResult)
	} else {
		log.Trace().Msgf("DEMO adding pass for %s, %s)", assetId, attributesId)
		control.Passes = append(control.Passes, assetResult)
	}

	log.Warn().Msgf("DEMO returning control with %d vulnerabilities", len(control.Failures))
	return []*domain.ControlEvaluation{control}
}

func (serviceImpl *TrivyScanner) ExecuteAnalyser(_ context.Context, req *service.ExecuteRequest, assetFetcher plugin.AssetFetcher) (*service.ExecuteAnalyserResponse, error) {
	assets := assetFetcher.FetchAssets(req.Account.Uuid, req.AssetType, map[string]*struct{}{
		"dockerhub_image": {},
	})
	var controls []*domain.ControlEvaluation

	for _, asset := range assets {
		var scanResponse []byte
		if err := scanner.Scan("Image", asset.Identifier, &scanResponse); err != nil {
			log.Info().Msgf("Could not scan %s - ignoring (%s)", asset.Identifier, err)
		} else {
			log.Info().Msgf("payload size %d", len(scanResponse))
			var run TrivyRun
			if err := json.Unmarshal(scanResponse, &run); err != nil {
				log.Error().Msg("oops - trivy hacking failed - oh well, we tried!")
			} else {
				if len(run.ScanOutput) > 0 {
					if len(run.ScanOutput[0].ImageScanOutput) > 0 {
						log.Warn().Msgf("trivy vulneribility count : %d", len(run.ScanOutput[0].ImageScanOutput[0].Vulnerabilities))

						c := mapToControl(run.ScanOutput[0].ImageScanOutput[0].Vulnerabilities, asset.Uuid, asset.AttributesUuid)
						log.Warn().Msgf("found %d trivy controls", len(c))
						controls = append(controls, c...)
					}
				}
			}
		}
	}

	log.Warn().Msgf("found total %d trivy controls", len(controls))
	return &service.ExecuteAnalyserResponse{
		Controls: controls,
	}, nil
}

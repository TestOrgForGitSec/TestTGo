package lservice

import (
	"compliance-hub-plugin-trivy/scanner"
	"context"
	"encoding/json"
	"fmt"
	domain "github.com/deliveryblueprints/chplugin-go/v0.1.0/domainv0_1_0"
	service "github.com/deliveryblueprints/chplugin-go/v0.1.0/servicev0_1_0"
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
					AssetType:                "BINARY",
					Role:                     domain.Role_ANALYSER,
					RequiresAttributes:       true,
					RequiresAssets:           true,
					RequiresBinaryAttributes: true,
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
							AssetTypes:  []string{"BINARY"},
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
	return &service.ExecuteDecoratorResponse{}, nil
}

func mapToAssetAttributes(asset domain.Asset, data []byte) *domain.AssetAttributes {
	return &domain.AssetAttributes{
		Asset: &domain.MasterAsset{
			Type:       asset.MasterAsset.Type,
			SubType:    asset.MasterAsset.SubType,
			Identifier: asset.MasterAsset.Identifier,
		},
		Attributes: json.RawMessage(fmt.Sprintf(`{"id":"%s"}`, asset.MasterAsset.Identifier)),
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

func mapToEvaluation(results []TrivyVulnerabilities, asset domain.Asset) []*domain.Evaluation {

	checksMap := make(map[string]*domain.Evaluation)

	assetResult := domain.AssetResult{
		AssetUuid: asset.Uuid,
		Asset: &domain.MasterAsset{
			Type:       asset.MasterAsset.Type,
			SubType:    asset.MasterAsset.SubType,
			Identifier: asset.MasterAsset.Identifier},
		AttributesUuid: asset.AttributesUuid,
		Details:        []*domain.DetailRow{},
	}

	var check *domain.Evaluation
	var ok bool
	for _, vulnerability := range results {

		log.Trace().Msgf("Found vulnerability (%s)", vulnerability.VulnerabilityID)

		if check, ok = checksMap[vulnerability.VulnerabilityID]; !ok {
			log.Trace().Msgf("Adding new check %s", vulnerability.VulnerabilityID)
			checksMap[vulnerability.VulnerabilityID] = &domain.Evaluation{
				Standard:      "Trivy Scan",
				Code:          vulnerability.VulnerabilityID,
				Name:          fmt.Sprintf("%s - %.75s", vulnerability.VulnerabilityID, vulnerability.Title),
				Importance:    vulnerability.Severity,
				DetailHeaders: []string{"Package", "Score"},
				DetailTypes:   []string{"string", "number"},
				Passes:        []*domain.AssetResult{},
				Failures:      []*domain.AssetResult{},
			}

			check = checksMap[vulnerability.VulnerabilityID]
		}

		log.Trace().Msgf("Adding fail evaluation for %s:%s.%s)", vulnerability.VulnerabilityID, asset.MasterAsset.SubType, asset.MasterAsset.Identifier)

		var score float32
		if vulnerability.CVSS.Nvd.V3Score != 0 {
			score = vulnerability.CVSS.Nvd.V3Score
		} else {
			score = 5.6
		}

		assetResult.Details = append(assetResult.Details, &domain.DetailRow{
			Data: []string{vulnerability.PkgName, fmt.Sprintf("%.1f", score)},
		})

		check.Failures = append(check.Failures, &assetResult)
	}

	// convert map and return
	checks := make([]*domain.Evaluation, len(checksMap))
	i := 0
	for _, check := range checksMap {
		log.Trace().Msgf("Adding check from map, fails %d", len(check.Failures))
		checks[i] = check
		i++
	}

	log.Warn().Msgf("Returning %d failed checks", len(checks))
	return checks
}

func (serviceImpl *TrivyScanner) ExecuteAnalyser(_ context.Context, req *service.ExecuteRequest, assetFetcher plugin.AssetFetcher) (*service.ExecuteAnalyserResponse, error) {
	assets := assetFetcher.FetchAssets(req.Account.Uuid, req.AssetType, map[string]*struct{}{
		"dockerhub_image": {},
	})
	var checks []*domain.Evaluation

	for _, asset := range assets {
		var scanResponse []byte
		if err := scanner.Scan("Image", asset.MasterAsset.Identifier, &scanResponse); err != nil {
			log.Info().Msgf("Could not scan %s.%s.%s - ignoring (%s)", asset.MasterAsset.Type, asset.MasterAsset.SubType, asset.MasterAsset.Identifier, err)
		} else {
			log.Info().Msgf("payload size %d", len(scanResponse))
			var run TrivyRun
			if err := json.Unmarshal(scanResponse, &run); err != nil {
				log.Error().Msgf("Error unmarshalling trivy response for asset %s.%s.%s - ignoring", asset.MasterAsset.Type, asset.MasterAsset.SubType, asset.MasterAsset.Identifier)
			} else {
				if len(run.ScanOutput) > 0 {
					if len(run.ScanOutput[0].ImageScanOutput) > 0 {
						log.Warn().Msgf("trivy vulneribility count : %d", len(run.ScanOutput[0].ImageScanOutput[0].Vulnerabilities))

						c := mapToEvaluation(run.ScanOutput[0].ImageScanOutput[0].Vulnerabilities, asset)
						log.Warn().Msgf("found %d trivy checks", len(c))
						checks = append(checks, c...)
					}
				}
			}
		}
	}

	log.Warn().Msgf("Found total %d failed checks", len(checks))
	return &service.ExecuteAnalyserResponse{
		Checks: checks,
	}, nil
}

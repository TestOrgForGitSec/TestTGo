package main

import (
	"compliance-hub-plugin-trivy/scanner"
	"context"
	"encoding/json"
	"fmt"

	domain "github.com/deliveryblueprints/chplugin-go/v0.4.0/domainv0_4_0"
	service "github.com/deliveryblueprints/chplugin-go/v0.4.0/servicev0_4_0"
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

// TrivyScanner is a implementation of ManifiestService Grpc Service.
type TrivyScanner struct {
	plugin.CHPluginService
}

// NewManifestServiceGrpcImpl returns the pointer to the implementation.
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{}
}

// GetManifest implementiation of gRPC service.
func (serviceImpl *TrivyScanner) GetManifest(ctx context.Context, in *service.GetManifestRequest) (*service.GetManifestResponse, error) {
	return &service.GetManifestResponse{
		Manifest: &domain.Manifest{
			Uuid:    "mg19e330-8827-11eb-8dcd-0242ac130003",
			Name:    "Docker Hub Scanner",
			Version: "0.2.0",
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
	return &service.GetAssetDescriptorsResponse{}, nil
}

/*
func (serviceImpl *TrivyScanner) ExecuteMaster(_ context.Context, _ *service.ExecuteRequest) (*service.ExecuteMasterResponse, error) {
	return &service.ExecuteMasterResponse{}, nil
}



func (serviceImpl *TrivyScanner) ExecuteDecorator(_ context.Context, req *service.ExecuteRequest, assetFetcher plugin.AssetFetcher) (*service.ExecuteDecoratorResponse, error) {
	return &service.ExecuteDecoratorResponse{}, nil
}

*/

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

type TrivyResult struct {
	Target          string                 `json:"Target"`
	Class           string                 `json:"Class"`
	Type            string                 `json:"Type"`
	Vulnerabilities []TrivyVulnerabilities `json:"Vulnerabilities"`
}

type TrivyScanOutput struct {
	Results []TrivyResult `json:"Results"`
}

type TrivyOutput struct {
	ImageUrl        string          `json:"imageUrl"`
	ImageScanOutput TrivyScanOutput `json:"imageScanOutput"`
}

type TrivyRun struct {
	ScanRunUuid string        `json:"scanRunUuid"`
	ScanOutput  []TrivyOutput `json:"scanOutput"`
}

type vulnerabilityAssetCheck struct {
	id          string
	title       string
	severity    string
	assetResult *domain.AssetResult
}

func mapToEvaluation(results []TrivyVulnerabilities, asset domain.Asset, profile *domain.AssetProfile, checks map[string]*domain.Evaluation) map[string]*domain.Evaluation {

	assetChecks := map[string]vulnerabilityAssetCheck{}
	var assetCheck vulnerabilityAssetCheck
	var ok bool
	for _, vulnerability := range results {
		if assetCheck, ok = assetChecks[vulnerability.VulnerabilityID]; !ok {
			assetChecks[vulnerability.VulnerabilityID] = vulnerabilityAssetCheck{
				id:       vulnerability.VulnerabilityID,
				title:    vulnerability.Title,
				severity: vulnerability.Severity,
				assetResult: &domain.AssetResult{
					AssetUuid: asset.Uuid,
					Asset: &domain.MasterAsset{
						Type:       asset.MasterAsset.Type,
						SubType:    asset.MasterAsset.SubType,
						Identifier: asset.MasterAsset.Identifier},
					AttributesUuid: profile.AttributesUuid,
					ProfileUuid:    profile.Uuid,
					Details:        []*domain.DetailRow{},
				},
			}

			assetCheck = assetChecks[vulnerability.VulnerabilityID]
		}

		log.Trace().Msgf("Adding fail detail for %s:%s.%s)", vulnerability.VulnerabilityID, asset.MasterAsset.SubType, asset.MasterAsset.Identifier)

		var score float32
		if vulnerability.CVSS.Nvd.V3Score != 0 {
			score = vulnerability.CVSS.Nvd.V3Score
		} else {
			score = 5.6
		}

		assetCheck.assetResult.Details = append(assetCheck.assetResult.Details, &domain.DetailRow{
			Data: []string{vulnerability.PkgName, fmt.Sprintf("%.1f", score)},
		})
	}

	var check *domain.Evaluation
	for vulnerabilityId, aCheck := range assetChecks {

		if check, ok = checks[vulnerabilityId]; !ok {
			log.Trace().Msgf("Adding new check %s", vulnerabilityId)
			checks[vulnerabilityId] = &domain.Evaluation{
				Standard:      "Trivy Scan",
				Code:          vulnerabilityId,
				Name:          fmt.Sprintf("%s - %.75s", vulnerabilityId, aCheck.title),
				Importance:    aCheck.severity,
				DetailHeaders: []string{"Package", "Score"},
				DetailTypes:   []string{"string", "number"},
				Passes:        []*domain.AssetResult{},
				Failures:      []*domain.AssetResult{},
			}

			check = checks[vulnerabilityId]
		}
		check.Failures = append(check.Failures, aCheck.assetResult)
	}

	log.Warn().Msgf("Appended %d failed checks for asset %s", len(assetChecks), asset.Uuid)

	return checks
}

func (serviceImpl *TrivyScanner) ExecuteAnalyser(_ context.Context, req *service.ExecuteRequest, assetFetcher plugin.AssetFetcher) (*service.ExecuteAnalyserResponse, error) {
	log.Debug().Msgf("Request received: %s", req)
	assets, err := assetFetcher.FetchAssets(plugin.AssetFetchRequest{
		AccountID:          req.Account.Uuid,
		AssetType:          req.AssetType,
		AssetSubTypes:      []string{"dockerhub_repo"},
		Identifiers:        req.AssetIdentifiers,
		ProfileIdentifiers: req.ProfileIdentifiers,
	})
	if err != nil {
		return nil, err
	}

	checks := map[string]*domain.Evaluation{}

	for _, asset := range assets {
		for _, profile := range asset.Profiles {
			// TODO profiles would be tags; for now, don't handle them- but they are there.
			var scanResponse []byte
			if err := scanner.Scan("Image", asset.MasterAsset, profile, &scanResponse); err != nil {
				log.Info().Msgf("Could not scan %s.%s.%s - ignoring (%s)", asset.MasterAsset.Type, asset.MasterAsset.SubType, asset.MasterAsset.Identifier, err)
			} else {
				log.Info().Msgf("payload size %d", len(scanResponse))
				var run TrivyRun
				if err := json.Unmarshal(scanResponse, &run); err != nil {
					log.Error().Msgf("Error unmarshalling trivy response for asset %s.%s.%s - ignoring", asset.MasterAsset.Type, asset.MasterAsset.SubType, asset.MasterAsset.Identifier)
					log.Error().Msgf(err.Error())
				} else {
					if len(run.ScanOutput) > 0 {
						if len(run.ScanOutput[0].ImageScanOutput.Results[0].Vulnerabilities) > 0 {
							log.Warn().Msgf("trivy vulnerability count : %d", len(run.ScanOutput[0].ImageScanOutput.Results[0].Vulnerabilities))

							checks = mapToEvaluation(run.ScanOutput[0].ImageScanOutput.Results[0].Vulnerabilities, *asset, profile, checks)
							log.Warn().Msgf("total so far : %d trivy checks", len(checks))
						}
					}
				}
			}
		}
	}

	log.Warn().Msgf("Found total %d failed checks", len(checks))

	// convert map and return
	checkList := make([]*domain.Evaluation, len(checks))
	i := 0
	for _, check := range checks {
		log.Trace().Msgf("Adding check from map, fails %d", len(check.Failures))
		checkList[i] = check
		i++
	}

	return &service.ExecuteAnalyserResponse{
		Checks: checkList,
	}, nil
}

package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	domain "github.com/deliveryblueprints/chplugin-go/v0.3.0/domainv0_3_0"
	service "github.com/deliveryblueprints/chplugin-go/v0.3.0/servicev0_3_0"
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

//TrivyScanner is an implementation of ManifiestService Grpc Service.
type trivyScanner struct {
	service.CHPluginServiceServer
}

// NewTrivyScanner returns the implementation.
func NewTrivyScanner() service.CHPluginServiceServer {
	return &trivyScanner{}
}

//GetManifest implementation of gRPC service.
func (ts *trivyScanner) GetManifest(ctx context.Context, in *service.GetManifestRequest) (*service.GetManifestResponse, error) {
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
func (ts *trivyScanner) GetAssetDescriptors(context.Context, *service.GetAssetDescriptorsRequest) (*service.GetAssetDescriptorsResponse, error) {
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

func (ts *trivyScanner) Master(stream service.CHPluginService_MasterServer) error {
	return fmt.Errorf("unimplemented")
}

func (ts *trivyScanner) Decorator(stream service.CHPluginService_DecoratorServer) error {
	return fmt.Errorf("unimplemented")
}

func (ts *trivyScanner) Analyser(stream service.CHPluginService_AnalyserServer) error {
	log.Info().Msgf("Analyser execution stream initiated")
	defer log.Info().Msgf("Analyser execution stream completed")

	return NewAnalyserProcessor(stream.Context(), &stream, ts).Process()
}

func (ts *trivyScanner) Aggregator(stream service.CHPluginService_AggregatorServer) error {
	return fmt.Errorf("unimplemented")
}

func (ts *trivyScanner) Assessor(stream service.CHPluginService_AssessorServer) error {
	return fmt.Errorf("unimplemented")
}

func (ts *trivyScanner) ExecuteAggregator(context.Context, *service.ExecuteRequest) (*service.ExecuteAggregatorResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (ts *trivyScanner) ExecuteAssessor(context.Context, *service.ExecuteRequest) (*service.ExecuteAssessorResponse, error) {
	return nil, fmt.Errorf("unimplemented")
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

type vulnerabilityAssetCheck struct {
	id          string
	title       string
	severity    string
	assetResult *domain.AssetResult
}

func mapToEvaluation(results []TrivyVulnerabilities, asset *domain.Asset, profile *domain.AssetProfile, checks map[string]*domain.Evaluation) map[string]*domain.Evaluation {

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

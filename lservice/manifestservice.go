package lservice

import (
	"compliance-hub-plugin-trivy/scanner"
	"context"
	"encoding/json"
	domain "github.com/deliveryblueprints/chplugin-go/v1.0/domain"
	service "github.com/deliveryblueprints/chplugin-go/v1.0/service"
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
	assets []*AssetDTO
	plugin.CHPluginService
}

//NewManifestServiceGrpcImpl returns the pointer to the implementation.
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{
		assets: []*AssetDTO{
			{
				UUID:          "mg1b7594-8827-11eb-8dcd-0242ac130003",
				Type:          "BINARY",
				SubType:       "container_image",
				Identifier:    "jenkins/jenkins:2.235.1-lts-alpine",
				Status:        "ACTIVE",
				Attributes:    json.RawMessage(`{"id":"jenkins/jenkins:2.235.1-lts-alpine", "type": "image", "pull_command": "docker pull jenkins/jenkins:2.235.1-lts-alpine"}`),
				SubAttributes: []SubAttributesDTO{},
			},
			{
				UUID:          "mg2bc48e-8827-11eb-8dcd-0242ac130003",
				Type:          "BINARY",
				SubType:       "container_image",
				Identifier:    "jenkins/jenkins:2.277.2-lts-alpine",
				Status:        "ACTIVE",
				Attributes:    json.RawMessage(`{"id":"jenkins/jenkins:2.277.2-lts-alpine", "type": "image", "pull_command": "docker pull jenkins/jenkins:2.277.2-lts-alpine"}`),
				SubAttributes: []SubAttributesDTO{},
			},
			{
				UUID:          "mg3bc48e-8827-11eb-8dcd-0242ac130003",
				Type:          "BINARY",
				SubType:       "container_image",
				Identifier:    "cloudbees/cloudbees-core-mm:2.289.2.2",
				Status:        "ACTIVE",
				Attributes:    json.RawMessage(`{"id":"cloudbees/cloudbees-core-mm:2.289.2.2", "type": "image", "pull_command": "docker pull cloudbees/cloudbees-core-mm:2.289.2.2"}`),
				SubAttributes: []SubAttributesDTO{},
			},
			{
				UUID:          "mg4bc48e-8827-11eb-8dcd-0242ac130003",
				Type:          "BINARY",
				SubType:       "container_image",
				Identifier:    "cloudbees/cloudbees-core-mm:latest",
				Status:        "ACTIVE",
				Attributes:    json.RawMessage(`{"id":"cloudbees/cloudbees-core-mm:latest", "type": "image", "pull_command": "docker pull cloudbees/cloudbees-core-mm:latest"}`),
				SubAttributes: []SubAttributesDTO{},
			},
		},
	}
}

//GetManifest implementiation of gRPC service.
func (serviceImpl *TrivyScanner) GetManifest(ctx context.Context, in *service.GetManifestRequest) (*service.GetManifestResponse, error) {
	return &service.GetManifestResponse{
		Manifest: &domain.Manifest{
			Uuid: "mg19e330-8827-11eb-8dcd-0242ac130003",
			Name: "TrivyScanner",
			AssetRoles: []*domain.AssetRole{
				{
					Role:      "MASTER",
					AssetType: &domain.AssetType{Type: "BINARY"},
				},
				{
					Role:                 "DECORATOR",
					AssetType:            &domain.AssetType{Type: "BINARY"},
					CreatesSubAttributes: []string{"trivy"},
				},
			},
		},
		Error: nil,
	}, nil
}

func (serviceImpl *TrivyScanner) ExecuteMaster(_ context.Context, _ *service.ExecuteRequest) (*service.ExecuteMasterResponse, error) {
	assets := mapToMasterAssets(serviceImpl.assets)
	return &service.ExecuteMasterResponse{
		Assets: assets,
		Error:  nil,
	}, nil
}

func mapToMasterAssets(assets []*AssetDTO) []*domain.MasterAsset {
	var result []*domain.MasterAsset
	for _, a := range assets {
		result = append(result, &domain.MasterAsset{
			Type:       a.Type,
			SubType:    a.SubType,
			Identifier: a.Identifier,
		})
	}
	return result
}

func (serviceImpl *TrivyScanner) ExecuteDecorator(_ context.Context, _ *service.ExecuteRequest, _ plugin.AssetFetcher) (*service.ExecuteDecoratorResponse, error) {
	for _, asset := range serviceImpl.assets {
		// Clear any previous SubAttributes
		asset.SubAttributes = []SubAttributesDTO{}
		var scanResponse []byte
		if err := scanner.Scan("Image", asset.Identifier, &scanResponse); err != nil {
			log.Info().Msgf("Could not scan %s - ignoring (%s)", asset.Identifier, err)
		} else {
			log.Info().Msgf("payload size %d", len(scanResponse))
			asset.SubAttributes = append(asset.SubAttributes, SubAttributesDTO{
				Type:       "trivy",
				Attributes: scanResponse,
			})
		}
	}
	attributes := mapToAssetAttributes(serviceImpl.assets)

	return &service.ExecuteDecoratorResponse{
		AssetAttributes: attributes,
		Error:           nil,
	}, nil
}

func mapToAssetAttributes(assets []*AssetDTO) []*domain.AssetAttributes {
	var result []*domain.AssetAttributes
	for _, a := range assets {
		result = append(result, &domain.AssetAttributes{
			Asset: &domain.MasterAsset{
				Type:       a.Type,
				SubType:    a.SubType,
				Identifier: a.Identifier,
			},
			Attributes:    a.Attributes,
			SubAttributes: subAttributesDTOListToSubAttributes(a.SubAttributes), //[]*domain.AssetSubAttributes{},
		})
	}
	return result
}

func subAttributesDTOListToSubAttributes(subAttributesDTO []SubAttributesDTO) []*domain.AssetSubAttributes {
	subAttributes := make([]*domain.AssetSubAttributes, len(subAttributesDTO))
	for i, subAttribute := range subAttributesDTO {

		var rawSubAttributes json.RawMessage
		var err error
		if rawSubAttributes, err = json.Marshal(subAttribute.Attributes); err != nil {
			log.Error().Err(err).Msgf("error marshalling sub attributes")
			rawSubAttributes = json.RawMessage(`{}`)
		}

		subAttributes[i] = &domain.AssetSubAttributes{
			AttributesUuid: subAttribute.AssetAttributesUUID,
			Type:           subAttribute.Type,
			SubAttributes:  rawSubAttributes,
		}
	}

	return subAttributes
}

func attributesToRawJson(attributes json.RawMessage) []byte {
	if raw, err := json.Marshal(attributes); err != nil {
		log.Error().Err(err).Msgf("error marshalling attributes")
		return json.RawMessage(`{}`)
	} else {
		return raw
	}
}

func (serviceImpl *TrivyScanner) ExecuteAnalyser(_ context.Context, _ *service.ExecuteRequest, _ plugin.AssetFetcher) (*service.ExecuteAnalyserResponse, error) {
	// arguably should return an error here?? ie not advertised in manifest etc
	return &service.ExecuteAnalyserResponse{}, nil
}

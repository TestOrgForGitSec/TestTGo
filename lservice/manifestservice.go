package lservice

import (
	"compliance-hub-plugin-trivy/internal/gRPC/basic/domain"
	"compliance-hub-plugin-trivy/internal/gRPC/basic/service"
	"compliance-hub-plugin-trivy/scanner"
	"context"
	"encoding/json"

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

//ManifestServiceGrpcImpl is a implementation of ManifiestService Grpc Service.
type ManifestServiceGrpcImpl struct {
	assets []*AssetDTO
}

//NewManifestServiceGrpcImpl returns the pointer to the implementation.
func NewManifestServiceGrpcImpl() *ManifestServiceGrpcImpl {
	return &ManifestServiceGrpcImpl{
		[]*AssetDTO{
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
		},
	}
}

//GetManifest implementiation of gRPC service.
func (serviceImpl *ManifestServiceGrpcImpl) GetManifest(ctx context.Context, in *service.GetManifestRequest) (*service.GetManifestResponse, error) {
	log.Info().Msgf("Received request for manifest")

	return &service.GetManifestResponse{
		Manifest: &domain.Manifest{
			Uuid: "mg19e330-8827-11eb-8dcd-0242ac130003",
			Name: "TrivyScanner",
			AssetRoles: []*domain.AssetRole{
				&domain.AssetRole{Role: "MASTER", AssetType: &domain.AssetType{Type: "BINARY"}, RequestsAssets: false,
					Command: &domain.Command{Command: "GET_ASSETS"}},
				&domain.AssetRole{Role: "DECORATOR", AssetType: &domain.AssetType{Type: "BINARY"}, RequestsAssets: false,
					Command: &domain.Command{Command: "SCAN_ASSETS"}},
			},
			Commands: []*domain.Command{
				&domain.Command{Command: "GET_ASSETS"},
				&domain.Command{Command: "SCAN_ASSETS"},
			},
		},
		Error: nil,
	}, nil
}

func assetToRawJsonMessage(asset AssetDTO, stripAttributes bool) (json.RawMessage, error) {
	if stripAttributes {
		asset.Attributes = nil
		asset.SubAttributes = nil
	}

	if assetJson, err := json.Marshal(asset); err != nil {
		return json.RawMessage{}, err
	} else {
		return assetJson, nil
	}

	return json.RawMessage{}, nil
}

// Helper function just for POC
func assetsToRawJsonMessage(assets []*AssetDTO, stripAttributes bool) (json.RawMessage, error) {
	rawJsonArray := json.RawMessage("[")
	for i, asset := range assets {
		if rawAsset, err := assetToRawJsonMessage(*asset, stripAttributes); err != nil {
			log.Error().Msgf("Error creating rawAsset - %s", err)
			return json.RawMessage{}, err
		} else {
			rawJsonArray = append(rawJsonArray, rawAsset...)
			if i+1 < len(assets) {
				rawJsonArray = append(rawJsonArray, byte(','))
			}
		}
	}
	rawJsonArray = append(rawJsonArray, byte(']'))

	return rawJsonArray, nil
}

//ExecuteCommand implementation of gRPC service
func (serviceImpl *ManifestServiceGrpcImpl) ExecuteCommand(ctx context.Context, in *service.ExecuteCommandRequest) (*service.ExecuteCommandResponse, error) {
	log.Info().Msgf("Received request to execute %s", in.Command)

	var payload json.RawMessage

	switch in.Command {
	case "GET_ASSETS":
		payload, _ = assetsToRawJsonMessage(serviceImpl.assets, true)
	case "SCAN_ASSETS":
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
		payload, _ = assetsToRawJsonMessage(serviceImpl.assets, false)
	}

	return &service.ExecuteCommandResponse{
		Payload: payload,
		Error:   nil,
	}, nil
}

func (serviceImpl *ManifestServiceGrpcImpl) Assets(stream service.ManifestService_AssetsServer) error {
	return nil
}

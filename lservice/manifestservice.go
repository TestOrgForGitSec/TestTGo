package lservice

import (
	"compliance-hub-plugin-trivy/scanner"
	"context"
	"encoding/json"
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
		SubAttributes: []*domain.AssetSubAttributes{
			{
				Type:          "trivy",
				SubAttributes: data,
			},
		},
	}
}

func (serviceImpl *TrivyScanner) ExecuteAnalyser(_ context.Context, _ *service.ExecuteRequest, _ plugin.AssetFetcher) (*service.ExecuteAnalyserResponse, error) {
	// arguably should return an error here?? ie not advertised in manifest etc
	return &service.ExecuteAnalyserResponse{}, nil
}

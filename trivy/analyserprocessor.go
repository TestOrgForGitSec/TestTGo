package trivy

import (
	"compliance-hub-plugin-trivy/logging"
	"compliance-hub-plugin-trivy/scanner"
	"context"
	"encoding/json"
	"errors"
	domain "github.com/deliveryblueprints/chplugin-go/v0.3.0/domainv0_3_0"
	service "github.com/deliveryblueprints/chplugin-go/v0.3.0/servicev0_3_0"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/types/known/anypb"
	"io"
	"time"
)

type analyserProcessor struct {
	ctx    context.Context
	stream service.CHPluginService_DecoratorServer
	ts     *trivyScanner
	log    zerolog.Logger
}

func (p *analyserProcessor) sendAndProcessAssetRequests(req *service.ExecuteRequest) ([]*domain.Asset, error) {

	assetRequest := &service.AssetRequest{
		RequestUuid: uuid.NewV4().String(),
		Account: &domain.Account{
			Uuid: req.Account.Uuid,
			Type: req.Account.Type,
		},
		Type: "BINARY",
		SubTypes: []string{
			"dockerhub_image",
		},
		Identifiers: req.AssetIdentifiers,
		ProfileIdentifiers: req.ProfileIdentifiers,
	}

	resp, _ := anypb.New(assetRequest)

	p.log.Debug().Msg("Sending asset request")
	sErr := p.sendWithTimeout(p.ctx, &service.StreamMessage{
		Type:  service.MessageType_ASSET_REQUEST,
		Value: resp,
	}, 5*time.Second)
	if sErr != nil {
		return nil, errors.New("Failed to send message to stream: " + sErr.Error())
	}

	var assets []*domain.Asset
	timeout := 5 * time.Second
	for {
		in, rErr := p.readWithTimeout(p.ctx, timeout)

		if rErr == context.DeadlineExceeded || rErr == context.Canceled {
			p.log.Error().Err(rErr).Msg("Aborting stream")
			return nil, rErr
		}

		if rErr != nil {
			p.log.Error().Err(rErr).Msg("Error reading from stream")
			return nil, rErr
		}

		// TODO(mrg) add some processing to ensure messages are received in the correct order?
		switch in.Type {
		case service.MessageType_ASSET_STREAM_START:
			assets = []*domain.Asset{}
			p.log.Debug().Msg("Asset response stream started")
		case service.MessageType_ASSET_RESPONSE:
			p.log.Debug().Msg("Asset response received")
			var asset domain.Asset
			if err := in.Value.UnmarshalTo(&asset); err != nil {
				p.log.Error().Err(err).Msg("Unable to unmarshal Asset")
				return nil, err
			}
			assets = append(assets, &asset)
		case service.MessageType_ASSET_STREAM_END:
			p.log.Debug().Msg("Asset response stream ended")
			return assets, nil
		}
	}
}

func (p *analyserProcessor) processExecuteRequest(req *service.ExecuteRequest) error {
	assets, err := p.sendAndProcessAssetRequests(req)
	if err != nil {
		return err
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
					log.Error().Err(err).Msgf("Error unmarshalling trivy response for asset %s.%s.%s - ignoring", asset.MasterAsset.Type, asset.MasterAsset.SubType, asset.MasterAsset.Identifier)
				} else {
					if len(run.ScanOutput) > 0 {
						if len(run.ScanOutput[0].ImageScanOutput) > 0 {
							log.Warn().Msgf("trivy vulneribility count : %d", len(run.ScanOutput[0].ImageScanOutput[0].Vulnerabilities))

							checks = mapToEvaluation(run.ScanOutput[0].ImageScanOutput[0].Vulnerabilities, asset, profile, checks)
							log.Warn().Msgf("total so far : %d trivy checks", len(checks))
						}
					}
				}
			}
		}
	}
	log.Warn().Msgf("Found total %d failed checks", len(checks))

	p.log.Info().Msg("Sending analyser response stream start")
	sErr := p.sendWithTimeout(p.ctx, &service.StreamMessage{
		Type: service.MessageType_RESPONSE_STREAM_START,
	}, 5*time.Second)
	if sErr != nil {
		return errors.New("Failed to send message to stream: " + sErr.Error())
	}

	for _, check := range checks {
		log.Trace().Msgf("Adding check from map, fails %d", len(check.Failures))
		resp, _ := anypb.New(check)
		p.log.Debug().Msg("Sending analyser response")
		sErr := p.sendWithTimeout(p.ctx, &service.StreamMessage{
			Type:  service.MessageType_ANALYSER_RESPONSE,
			Value: resp,
		}, 5*time.Second)
		if sErr != nil {
			return errors.New("Failed to send message to stream: " + sErr.Error())
		}
	}

	p.log.Info().Msg("Sending analyser response stream end")
	sErr = p.sendWithTimeout(p.ctx, &service.StreamMessage{
		Type: service.MessageType_RESPONSE_STREAM_END,
	}, 5*time.Second)
	if sErr != nil {
		return errors.New("Failed to send message to stream: " + sErr.Error())
	}

	return nil
}

// sendWithTimeout sends a StreamMessage to the processors stream, erroring when the given timeout is reached
func (p *analyserProcessor) sendWithTimeout(ctx context.Context, payload *service.StreamMessage, timeout time.Duration) error {
	sendCtx, sendCtxCancel := context.WithTimeout(ctx, timeout)
	defer sendCtxCancel()

	errChan := make(chan error, 1)
	doneChan := make(chan interface{}, 1)
	go func() {
		stream := p.stream
		err := stream.Send(payload)
		if err != nil {
			errChan <- err
			close(errChan)
		} else {
			close(doneChan)
		}
	}()
	select {
	case <-sendCtx.Done():
		return sendCtx.Err()
	case err := <-errChan:
		return err
	case <-doneChan:
		return nil
	}
}

// readWithTimeout reads from the processors stream until either a response is received or the given timeout is reached
func (p *analyserProcessor) readWithTimeout(ctx context.Context, timeout time.Duration) (*service.StreamMessage, error) {
	recvCtx, recvCtxCancel := context.WithTimeout(ctx, timeout)
	defer recvCtxCancel()

	errChan := make(chan error, 1)
	resultChan := make(chan *service.StreamMessage, 1)
	go func() {
		stream := p.stream
		in, err := stream.Recv()
		if err != nil {
			errChan <- err
			close(errChan)
		} else {
			resultChan <- in
			close(resultChan)
		}
	}()
	select {
	case <-recvCtx.Done():
		return nil, recvCtx.Err()
	case err := <-errChan:
		return nil, err
	case result := <-resultChan:
		return result, nil
	}
}

func (p *analyserProcessor) Process() error {

	p.log.Info().Msg("Processing DECORATOR stream")
	defer p.log.Debug().Msg("Stream processing complete")

	// EXECUTE_REQUEST should come immediately so give a low timeout
	p.log.Info().Msg("Waiting for execute details")
	in, err := p.readWithTimeout(p.ctx, 5*time.Second)

	if err == context.DeadlineExceeded || err == context.Canceled {
		p.log.Error().Err(err).Msgf("timed out waiting for EXECUTE_REQUEST msg")
		return errors.New("timeout or cancel whilst waiting for EXECUTE_REQUEST msg from CE : " + err.Error())
	}

	if err == io.EOF {
		p.log.Error().Msg("Stream closed before EXECUTE_REQUEST msg received")
		return errors.New("stream closed before EXECUTE_REQUEST msg received from CE")
	}

	if err != nil {
		p.log.Error().Err(err).Msg("Error reading stream")
		return errors.New("error reading from stream : " + err.Error())
	}

	if in.Type != service.MessageType_EXECUTE_REQUEST {
		p.log.Error().Msg("Expected EXECUTE_REQUEST but received a different message type : " + in.Type.String())
		return errors.New("expected EXECUTE_REQUEST but received a different message type : " + in.Type.String())
	}

	var execReq service.ExecuteRequest
	if err := in.Value.UnmarshalTo(&execReq); err != nil {
		p.log.Error().Err(err).Msg("Unable to unmarshal ExecuteRequest")
		return errors.New("failed to unmarshall ExecuteRequest")
	}

	p.log.Trace().Msgf("EXECUTE_REQUEST received : %s", in)

	if err := p.processExecuteRequest(&execReq); err != nil {
		p.log.Error().Err(err).Msg("Failed to process ExecuteRequest")
		return errors.New("error in plugin execution : " + err.Error())
	}

	return nil
}

func NewAnalyserProcessor(ctx context.Context, stream *service.CHPluginService_AnalyserServer, ts *trivyScanner) StreamProcessor {
	return &analyserProcessor{
		ctx:    ctx,
		stream: *stream,
		ts:     ts,
		log:    logging.GetSubLogger("analyser_processor", uuid.NewV4().String()),
	}
}

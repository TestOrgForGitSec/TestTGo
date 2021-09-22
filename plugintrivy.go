package main

import (
	"compliance-hub-plugin-trivy/config"
	"compliance-hub-plugin-trivy/lservice"
	"fmt"
	service "github.com/deliveryblueprints/chplugin-go/v0.1.0/servicev0_1_0"
	"github.com/deliveryblueprints/chplugin-service-go/plugin"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"net"
)

func getNetListener(address string, port uint) net.Listener {
	log.Info().Msgf("Binding gRPC server on %s:%d", address, port)
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		log.Fatal().Msgf("failed to listen: %v", err)
		panic(fmt.Sprintf("failed to listen: %v", err))
	}

	return lis
}

func main() {

	config.InitConfig()

	netListener := getNetListener(config.Config.GetString("server.address"), config.Config.GetUint("server.port"))
	gRPCServer := grpc.NewServer()

	chPluginServiceImpl := plugin.CHPluginServiceBuilder(lservice.NewTrivyScanner())
	service.RegisterCHPluginServiceServer(gRPCServer, chPluginServiceImpl)

	// start the server
	log.Info()
	if err := gRPCServer.Serve(netListener); err != nil {
		log.Fatal().Msgf("failed to serve: %s", err)
	}

}

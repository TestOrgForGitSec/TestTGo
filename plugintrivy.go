package main

import (
	"compliance-hub-plugin-trivy/config"
	"compliance-hub-plugin-trivy/logging"
	"fmt"
	service "github.com/deliveryblueprints/chplugin-go/v0.3.0/servicev0_3_0"
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
	logging.InitLogging()

	netListener := getNetListener(config.Config.GetString("server.address"), config.Config.GetUint("server.port"))
	gRPCServer := grpc.NewServer(grpc.MaxRecvMsgSize(config.Config.GetInt("server.max_recv_size")))
	chPluginServiceImpl := plugin.CHPluginServiceBuilder(NewTrivyScanner())
	service.RegisterCHPluginServiceServer(gRPCServer, chPluginServiceImpl)

	// start the server
	if err := gRPCServer.Serve(netListener); err != nil {
		log.Fatal().Msgf("failed to serve: %s", err)
	}

}

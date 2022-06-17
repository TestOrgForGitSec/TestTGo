package main

import (
	"compliance-hub-plugin-trivy/config"
	"fmt"
	"net"
	"time"

	"github.com/deliveryblueprints/chlog-go/log"
	service "github.com/deliveryblueprints/chplugin-go/v0.4.0/servicev0_4_0"
	"github.com/deliveryblueprints/chplugin-service-go/plugin"
	"google.golang.org/grpc"
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

	trackingInfo := map[string]string{"Service": "Trivy-Plugin"}
	log.Init(config.Config, trackingInfo)

	netListener := getNetListener(config.Config.GetString("server.address"), config.Config.GetUint("server.port"))
	gRPCServer := grpc.NewServer(grpc.MaxRecvMsgSize(config.Config.GetInt("grpc.maxrecvsize")))
	chPluginServiceImpl := plugin.CHPluginServiceBuilder(NewTrivyScanner())
	service.RegisterCHPluginServiceServer(gRPCServer, chPluginServiceImpl)
	log.Info().Msgf("Starting: %s", time.Now().Format(time.RFC3339))
	// start the server
	if err := gRPCServer.Serve(netListener); err != nil {
		log.Fatal().Msgf("failed to serve: %s", err)

	}

}

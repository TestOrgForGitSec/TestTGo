package main

import (
	"compliance-hub-plugin-trivy/config"
	"compliance-hub-plugin-trivy/internal/gRPC/basic/service"
	"compliance-hub-plugin-trivy/lservice"
	"fmt"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"net"
)

//var TrivyRouter *httprouter.Router

func getNetListener(address string, port uint) net.Listener {
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

	manifestServiceImpl := lservice.NewManifestServiceGrpcImpl()
	service.RegisterManifestServiceServer(gRPCServer, manifestServiceImpl)

	// start the server
	if err := gRPCServer.Serve(netListener); err != nil {
		log.Fatal().Msgf("failed to serve: %s", err)
	}

	/*
		TrivyRouter = httprouter.New()

		TrivyRouter.GET("/status", handlers.HandleGetStatus)

		TrivyRouter.POST("/scan", handlers.HandlePostScan)

		log.Fatal(http.ListenAndServe(":8080", TrivyRouter), nil)
	*/

}

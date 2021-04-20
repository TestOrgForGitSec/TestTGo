package main

import (
	"compliance-hub-plugin-trivy/internal/gRPC/basic/service"
	"compliance-hub-plugin-trivy/lservice"
	"fmt"
	"google.golang.org/grpc"
	"log"
	"net"
)

//var TrivyRouter *httprouter.Router

func getNetListener(port uint) net.Listener {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
		panic(fmt.Sprintf("failed to listen: %v", err))
	}

	return lis
}

func main() {

	netListener := getNetListener(6010)
	gRPCServer := grpc.NewServer()

	manifestServiceImpl := lservice.NewManifestServiceGrpcImpl()
	service.RegisterManifestServiceServer(gRPCServer, manifestServiceImpl)

	// start the server
	if err := gRPCServer.Serve(netListener); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}

	/*
		TrivyRouter = httprouter.New()

		TrivyRouter.GET("/status", handlers.HandleGetStatus)

		TrivyRouter.POST("/scan", handlers.HandlePostScan)

		log.Fatal(http.ListenAndServe(":8080", TrivyRouter), nil)
	*/

}

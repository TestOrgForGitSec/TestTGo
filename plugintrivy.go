package main

import (
	"compliance-hub-plugin-trivy/handlers"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

var TrivyRouter *httprouter.Router

func main() {
	TrivyRouter = httprouter.New()

	TrivyRouter.GET("/status", handlers.HandleGetStatus)

	TrivyRouter.POST("/scan", handlers.HandlePostScan)

	log.Fatal(http.ListenAndServe(":8080", TrivyRouter), nil)
}



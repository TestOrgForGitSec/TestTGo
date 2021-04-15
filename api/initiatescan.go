package main

import (
	"log"
	"net/http"
	"github.com/julienschmidt/httprouter"
)

var TrivyRouter *httprouter.Router

func main() {
	TrivyRouter = httprouter.New()

	TrivyRouter.GET("/status", handleGetStatus)

	TrivyRouter.POST("/scan", handlePostScan)

	log.Fatal(http.ListenAndServe(":8080", TrivyRouter), nil)
}
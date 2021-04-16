package main

import (
	"log"
	"net/http"
	"github.com/julienschmidt/httprouter"
)

var TrivyRouter *httprouter.Router

func main() {
	TrivyRouter = httprouter.New()

	TrivyRouter.GET("/status", HandleGetStatus)

	TrivyRouter.POST("/scan", HandlePostScan)

	log.Fatal(http.ListenAndServe(":8080", TrivyRouter), nil)
}